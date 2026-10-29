#!/usr/bin/env python3
"""MA300-to-browser bridge.

Reads live pyzk Attendance objects from one MA300 device and publishes a
normalized, one-way SSE stream for the reception frontend. This process never
creates attendance records in the main application.
"""

from __future__ import annotations

import errno
import json
import locale
import logging
import logging.handlers
import os
import queue
import signal
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from struct import unpack
from typing import Any, Callable, Iterator, List, MutableMapping, Optional


LOG = logging.getLogger("ma300_agent")
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG_FILE = os.path.join("logs", "ma300-agent.log")
LOG_FILE_MAX_BYTES = 1024 * 1024
LOG_FILE_BACKUPS = 5

# Windows has no SO_EXCLUSIVEADDRUSE outside of win32 builds; the value is ~SO_REUSEADDR.
SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", -5)
WSAEACCES = 10013
WSAEADDRINUSE = 10048

# pyzk 0.9 protocol constants (zk/const.py), repeated so that tests and the
# session check do not depend on importing pyzk.
CMD_GET_TIME = 201
CMD_REG_EVENT = 500
CMD_ACK_UNAUTH = 2005
USHRT_MAX = 65535


def required_setting(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be set")
    return value


def integer_setting(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError as error:
        raise RuntimeError(f"{name} must be an integer") from error


def boolean_setting(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be true or false")


def load_env_file(path: Optional[str] = None, environ: Optional[MutableMapping[str, str]] = None) -> List[str]:
    """Load KEY=VALUE lines from .env without overriding the real environment.

    Returns human-readable problems to log once logging is configured.
    """
    environ = os.environ if environ is None else environ
    explicit = path is not None or bool(environ.get("AGENT_ENV_FILE", "").strip())
    if path is None:
        path = environ.get("AGENT_ENV_FILE", "").strip() or os.path.join(APP_DIR, ".env")
    if not os.path.isfile(path):
        return [f"settings file {path} not found"] if explicit else []

    problems = []
    # utf-8-sig: Notepad on Windows 7 saves UTF-8 with a byte order mark.
    with open(path, encoding="utf-8-sig") as env_file:
        try:
            lines = env_file.read().splitlines()
        except UnicodeDecodeError:
            lines = None
    if lines is None:
        # Notepad's default "ANSI" on a Russian Windows 7 is cp1251.
        encoding = ansi_encoding()
        with open(path, encoding=encoding, errors="replace") as env_file:
            lines = env_file.read().splitlines()
        problems.append(f"{path} is not UTF-8, read it as {encoding}; save it in Notepad as UTF-8")
    for number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not key or not key.replace("_", "a").isalnum():
            problems.append(f"{path}:{number}: ignored line without KEY=VALUE")
            continue
        value = _env_value(value)
        if key not in environ:
            environ[key] = value
    return problems


def ansi_encoding() -> str:
    """The Windows "ANSI" code page; cp1251 where the locale reports UTF-8 (macOS, Linux)."""
    encoding = locale.getpreferredencoding(False)
    return "cp1251" if encoding.lower().replace("-", "") in ("utf8", "ascii", "ansi_x3.41968") else encoding


def _env_value(raw: str) -> str:
    """Like bash: quotes keep '#', an unquoted ' #' starts a comment (also right after '=')."""
    value = raw.strip()
    if value.startswith("#") and raw[:1].isspace():
        return ""
    if value[:1] in ("\"", "'"):
        closing = value.find(value[0], 1)
        if closing > 0:
            return value[1:closing]
    for index in range(1, len(value)):
        if value[index] == "#" and value[index - 1].isspace():
            return value[:index].rstrip()
    return value


@dataclass(frozen=True)
class Settings:
    device_host: str
    device_port: int
    device_timeout_seconds: int
    device_password: int
    force_udp: bool
    omit_ping: bool
    verbose_pyzk: bool
    listen_host: str
    listen_port: int
    reconnect_delay_seconds: int
    idle_check_seconds: int = 30

    @classmethod
    def from_environment(cls) -> "Settings":
        settings = cls(
            device_host=required_setting("MA300_HOST"),
            device_port=integer_setting("MA300_PORT", 4370),
            device_timeout_seconds=integer_setting("MA300_TIMEOUT_SECONDS", 10),
            device_password=integer_setting("MA300_PASSWORD", 0),
            force_udp=boolean_setting("MA300_FORCE_UDP", True),
            omit_ping=boolean_setting("MA300_OMIT_PING", True),
            verbose_pyzk=boolean_setting("MA300_VERBOSE", False),
            listen_host=os.environ.get("AGENT_HOST", "127.0.0.1"),
            listen_port=integer_setting("AGENT_PORT", 8765),
            reconnect_delay_seconds=integer_setting("MA300_RECONNECT_DELAY_SECONDS", 3),
            idle_check_seconds=integer_setting("MA300_IDLE_CHECK_SECONDS", 30),
        )
        if settings.device_timeout_seconds < 1:
            raise RuntimeError("MA300_TIMEOUT_SECONDS must be at least 1")
        if settings.idle_check_seconds < 0:
            raise RuntimeError("MA300_IDLE_CHECK_SECONDS must be 0 (off) or positive")
        return settings


@dataclass(frozen=True)
class DeviceAttendanceEvent:
    event_id: str
    user_id: str
    timestamp: str
    status: int
    punch: int

    @classmethod
    def from_pyzk(cls, attendance: Any) -> "DeviceAttendanceEvent":
        user_id = str(getattr(attendance, "user_id", "")).strip()
        if not user_id:
            raise ValueError("Attendance without user_id")

        timestamp = getattr(attendance, "timestamp", None)
        if isinstance(timestamp, datetime):
            timestamp_value = timestamp.astimezone().isoformat() if timestamp.tzinfo else timestamp.isoformat()
        elif timestamp is not None:
            timestamp_value = str(timestamp)
        else:
            timestamp_value = datetime.now().astimezone().isoformat()

        return cls(
            event_id=str(uuid.uuid4()),
            user_id=user_id,
            timestamp=timestamp_value,
            status=int(getattr(attendance, "status", 0) or 0),
            punch=int(getattr(attendance, "punch", 0) or 0),
        )

    def sse_payload(self) -> dict[str, Any]:
        return {
            "type": "attendance",
            "eventId": self.event_id,
            "userId": self.user_id,
            "timestamp": self.timestamp,
            "status": self.status,
            "punch": self.punch,
        }


class EventHub:
    """Fan-out hub for browser SSE connections."""

    def __init__(self) -> None:
        self._clients: set[queue.Queue[DeviceAttendanceEvent]] = set()
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue[DeviceAttendanceEvent]:
        client: queue.Queue[DeviceAttendanceEvent] = queue.Queue()
        with self._lock:
            self._clients.add(client)
        return client

    def unsubscribe(self, client: queue.Queue[DeviceAttendanceEvent]) -> None:
        with self._lock:
            self._clients.discard(client)

    def publish(self, event: DeviceAttendanceEvent) -> None:
        with self._lock:
            clients = tuple(self._clients)
        for client in clients:
            client.put(event)


class DeviceStatus:
    """Thread-safe MA300 session state for /healthz."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = "starting"
        self._last_packet_at: Optional[str] = None
        self._reconnects = 0
        self._last_error: Optional[str] = None

    def connecting(self) -> None:
        with self._lock:
            self._state = "connecting"

    def connected(self) -> None:
        with self._lock:
            self._state = "connected"
            self._last_packet_at = _now_iso()

    def packet(self) -> None:
        with self._lock:
            self._last_packet_at = _now_iso()

    def reconnecting(self, reason: str) -> None:
        with self._lock:
            self._state = "reconnecting"
            self._reconnects += 1
            self._last_error = reason

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "state": self._state,
                "lastPacketAt": self._last_packet_at,
                "reconnects": self._reconnects,
                "lastError": self._last_error,
            }


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class SessionLost(Exception):
    """The MA300 no longer serves the UDP session the agent captures on."""


class _RegEventAttendance:
    def __init__(self, user_id: str, timestamp: Any, status: int, punch: int) -> None:
        self.user_id = user_id
        self.timestamp = timestamp
        self.status = status
        self.punch = punch


def parse_reg_event(data: bytes, decode_timehex: Callable[[bytes], Any]) -> List[_RegEventAttendance]:
    """Decode a CMD_REG_EVENT payload exactly like pyzk 0.9 live_capture()."""
    attendances = []
    while len(data) >= 12:
        if len(data) == 12:
            user_id, status, punch, timehex = unpack("<IBB6s", data)
            data = data[12:]
        elif len(data) == 32:
            user_id, status, punch, timehex = unpack("<24sBB6s", data[:32])
            data = data[32:]
        elif len(data) == 36:
            user_id, status, punch, timehex, _other = unpack("<24sBB6s4s", data[:36])
            data = data[36:]
        elif len(data) >= 52:
            user_id, status, punch, timehex, _other = unpack("<24sBB6s20s", data[:52])
            data = data[52:]
        else:
            break
        if isinstance(user_id, int):
            user_id = str(user_id)
        else:
            user_id = user_id.split(b"\x00")[0].decode(errors="ignore")
        attendances.append(_RegEventAttendance(user_id, decode_timehex(timehex), status, punch))
    return attendances


class ZkLiveCaptureSource:
    def __init__(
        self,
        settings: Settings,
        status: Optional[DeviceStatus] = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self.status = status or DeviceStatus()
        self._monotonic = monotonic

    def events(self, stopped: threading.Event) -> Iterator[DeviceAttendanceEvent]:
        timeout = self._settings.device_timeout_seconds
        idle_check = self._settings.idle_check_seconds
        delay = self._settings.reconnect_delay_seconds
        while not stopped.is_set():
            connection = None
            session_alive = True
            try:
                self.status.connecting()
                connection = self._connect()
                connection.enable_device()
                self.status.connected()
                LOG.info(
                    "Connected to MA300 at %s:%s; waiting for live events",
                    self._settings.device_host,
                    self._settings.device_port,
                )
                capture = connection.live_capture(new_timeout=timeout)
                last_packet = self._monotonic()
                try:
                    for attendance in capture:
                        if stopped.is_set():
                            return
                        if attendance is not None:
                            last_packet = self._monotonic()
                            self.status.packet()
                            event = self._convert(attendance)
                            if event is not None:
                                yield event
                            continue

                        LOG.debug("time out")
                        silence = self._monotonic() - last_packet
                        if not idle_check or silence < idle_check:
                            continue
                        # Bound detection by idle_check + timeout even when the
                        # silence already overshot idle_check by part of a timeout.
                        check_timeout = max(0.5, min(timeout, idle_check + timeout - silence))
                        pushed = self._check_session(connection, check_timeout, timeout)
                        last_packet = self._monotonic()
                        self.status.packet()
                        for pushed_attendance in pushed:
                            event = self._convert(pushed_attendance)
                            if event is not None:
                                yield event
                finally:
                    capture.close()
            except SessionLost as error:
                session_alive = False
                if stopped.is_set():
                    return
                self.status.reconnecting(str(error))
                LOG.warning("MA300 session did not answer (%s); reconnecting in %s s", error, delay)
                stopped.wait(delay)
            except Exception as error:  # pyzk exposes transport errors through several exception types.
                if stopped.is_set():
                    return
                reason = f"{type(error).__name__}: {error}"
                self.status.reconnecting(reason)
                LOG.warning("MA300 connection/capture failed (%s); reconnecting in %s s", reason, delay)
                LOG.debug("MA300 failure details", exc_info=True)
                stopped.wait(delay)
            finally:
                if connection is not None:
                    self._release(connection, session_alive, quiet=not stopped.is_set())

    def _check_session(self, connection: Any, check_timeout: float, capture_timeout: float) -> List[Any]:
        """Ask the MA300 for its clock inside the live capture session.

        Returns attendances that the terminal pushed while the check was in
        flight (pyzk reads that CMD_REG_EVENT packet as the command reply), or
        raises SessionLost when the terminal does not serve the session.
        """
        reply_id = getattr(connection, "_ZK__reply_id")
        sock = getattr(connection, "_ZK__sock")
        try:
            sock.settimeout(check_timeout)
            response = getattr(connection, "_ZK__send_command")(CMD_GET_TIME, b"", 1032)
        except Exception as error:
            raise SessionLost(f"no reply to the session check within {check_timeout:g} s: {error}") from error
        finally:
            try:
                sock.settimeout(capture_timeout)
            except OSError:
                pass

        code = response.get("code")
        if response.get("status"):
            LOG.debug("MA300 session check passed")
            return []
        if code == CMD_REG_EVENT:
            # The terminal pushed an event before answering. Acknowledge and
            # decode it here; live_capture() later skips the late clock reply.
            next_reply_id = reply_id + 1
            if next_reply_id >= USHRT_MAX:
                next_reply_id -= USHRT_MAX
            setattr(connection, "_ZK__reply_id", next_reply_id)
            packet = getattr(connection, "_ZK__data_recv")
            getattr(connection, "_ZK__ack_ok")()
            LOG.debug("MA300 pushed an event during the session check")
            return parse_reg_event(packet[8:], getattr(connection, "_ZK__decode_timehex"))
        if code == CMD_ACK_UNAUTH:
            raise SessionLost("terminal answered 'unauthorized': it forgot the session")
        # Any other answer still comes from a terminal that serves the session;
        # it merely refused the clock command.
        LOG.debug("MA300 answered the session check with code %s; the session is alive", code)
        return []

    @staticmethod
    def _convert(attendance: Any) -> Optional[DeviceAttendanceEvent]:
        try:
            event = DeviceAttendanceEvent.from_pyzk(attendance)
        except (TypeError, ValueError) as error:
            LOG.warning("Ignoring malformed MA300 Attendance: %s", error)
            return None
        LOG.info(
            "EVENT: <Attendance>: %s : %s (%s, %s)",
            event.user_id,
            event.timestamp,
            event.status,
            event.punch,
        )
        return event

    @staticmethod
    def _release(connection: Any, session_alive: bool, quiet: bool) -> None:
        if not session_alive:
            # CMD_EXIT to a terminal that lost the session only waits for a timeout.
            try:
                getattr(connection, "_ZK__sock").close()
            except Exception:  # best-effort cleanup of a dead session.
                pass
            return
        try:
            connection.disconnect()
            (LOG.debug if quiet else LOG.info)("Disconnected from MA300")
        except Exception as error:  # disconnect is best-effort after a failed socket.
            LOG.debug("MA300 disconnect failed: %s", error)

    def _connect(self) -> Any:
        try:
            from zk import ZK
        except ImportError as error:
            raise RuntimeError("pyzk is not installed; run pip install -r requirements.txt") from error

        client = ZK(
            self._settings.device_host,
            port=self._settings.device_port,
            timeout=self._settings.device_timeout_seconds,
            password=self._settings.device_password,
            force_udp=self._settings.force_udp,
            ommit_ping=self._settings.omit_ping,
            verbose=self._settings.verbose_pyzk,
        )
        try:
            return client.connect()
        except Exception:
            try:
                getattr(client, "_ZK__sock").close()
            except Exception:  # best-effort cleanup of a failed connect.
                pass
            raise


def running_on_windows() -> bool:
    return sys.platform == "win32"


def configure_listen_socket(sock: Any, windows: Optional[bool] = None) -> None:
    """Make a second agent on the same address fail to bind.

    On Windows SO_REUSEADDR lets two processes listen on one port, so the
    socket is exclusive instead. POSIX SO_REUSEADDR only allows a restart while
    old connections linger in TIME_WAIT and is kept.
    """
    if windows is None:
        windows = running_on_windows()
    if windows:
        sock.setsockopt(socket.SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def address_in_use(error: OSError) -> bool:
    if getattr(error, "winerror", None) in (WSAEADDRINUSE, WSAEACCES):
        return True
    return error.errno == errno.EADDRINUSE


class AgentHttpServer(ThreadingHTTPServer):
    allow_reuse_address = False  # configure_listen_socket() decides per platform.

    def __init__(self, address: tuple[str, int], hub: EventHub, device_status: Optional[DeviceStatus] = None) -> None:
        self.hub = hub
        self.device_status = device_status or DeviceStatus()
        super().__init__(address, AgentRequestHandler)

    def server_bind(self) -> None:
        configure_listen_socket(self.socket)
        super().server_bind()


class AgentRequestHandler(BaseHTTPRequestHandler):
    server: AgentHttpServer
    server_version = "MA300Agent/1.0"

    def end_headers(self) -> None:
        # The production default binds only to 127.0.0.1. CORS is therefore
        # needed for a locally hosted reception frontend, not for LAN access.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        super().end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._json_response(HTTPStatus.OK, {"status": "ok", "device": self.server.device_status.snapshot()})
            return
        if self.path != "/events":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        client = self.server.hub.subscribe()
        try:
            self.wfile.write(b"event: connected\ndata: {}\n\n")
            self.wfile.flush()
            while True:
                try:
                    event = client.get(timeout=15)
                    payload = json.dumps(event.sse_payload(), ensure_ascii=False)
                    self.wfile.write(f"event: attendance\ndata: {payload}\n\n".encode())
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        finally:
            self.server.hub.unsubscribe(client)

    def _json_response(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        return


def run_capture(source: ZkLiveCaptureSource, hub: EventHub, stopped: threading.Event) -> None:
    for event in source.events(stopped):
        hub.publish(event)


def configure_logging(app_dir: Optional[str] = None, level: Optional[str] = None) -> Optional[str]:
    """Log to the console and/or a rotating file; returns the log file path.

    Under pythonw.exe sys.stdout/sys.stderr are None: logging then goes to
    logs/ma300-agent.log and both streams are pointed at os.devnull so that
    print() in pyzk and tracebacks of threads cannot fail.
    """
    app_dir = APP_DIR if app_dir is None else app_dir
    level = (os.environ.get("LOG_LEVEL", "") if level is None else level).strip().upper() or "INFO"
    if not isinstance(logging.getLevelName(level), int):
        raise ValueError(f"LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR or CRITICAL, not {level!r}")
    console = sys.stderr is not None
    log_file = os.environ.get("LOG_FILE", "").strip()
    if not log_file and not console:
        log_file = DEFAULT_LOG_FILE
    handlers: List[logging.Handler] = []
    if console:
        handlers.append(logging.StreamHandler(sys.stderr))
    if log_file:
        log_file = os.path.join(app_dir, log_file)  # absolute LOG_FILE wins in os.path.join.
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(
            logging.handlers.RotatingFileHandler(
                log_file, maxBytes=LOG_FILE_MAX_BYTES, backupCount=LOG_FILE_BACKUPS, encoding="utf-8"
            )
        )
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w")
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    return log_file or None


def main() -> int:
    """Run the agent; startup errors go to the log (also under pythonw.exe) and exit non-zero."""
    startup_errors = []
    try:
        env_problems = load_env_file()
    except (OSError, UnicodeDecodeError) as error:
        env_problems = []
        startup_errors.append(f"Cannot read the settings file: {error}")
    try:
        log_file = configure_logging()
    except ValueError as error:
        startup_errors.append(f"Invalid settings: {error}")
        log_file = configure_logging(level="INFO")
    for problem in env_problems:
        LOG.warning("%s", problem)
    if log_file:
        LOG.info("Logging to %s", log_file)
    if not startup_errors:
        try:
            settings = Settings.from_environment()
        except RuntimeError as error:
            startup_errors.append(f"Invalid settings: {error}")
    if startup_errors:
        for message in startup_errors:
            LOG.error("%s. The agent stops; fix .env and start it again.", message)
        return 1
    try:
        return _serve(settings)
    except Exception:
        LOG.exception("MA300 agent stopped on an unexpected error")
        return 1


def _serve(settings: Settings) -> int:
    stopped = threading.Event()
    hub = EventHub()
    status = DeviceStatus()
    # Bind before talking to the MA300: a second copy must not touch the
    # session of the running agent.
    try:
        server = AgentHttpServer((settings.listen_host, settings.listen_port), hub, status)
    except OSError as error:
        if not address_in_use(error):
            LOG.error(
                "Cannot listen on %s:%s (%s). Check AGENT_HOST/AGENT_PORT in .env.",
                settings.listen_host,
                settings.listen_port,
                error,
            )
            return 1
        LOG.error(
            "MA300 agent is already running on %s:%s (%s). This copy exits; "
            "агент уже запущен, вторую копию не запускайте.",
            settings.listen_host,
            settings.listen_port,
            error,
        )
        return 2
    source = ZkLiveCaptureSource(settings, status)
    capture_thread = threading.Thread(target=run_capture, args=(source, hub, stopped), name="ma300-capture", daemon=True)

    def stop(_: int, __: Any) -> None:
        stopped.set()
        # shutdown() blocks until serve_forever() exits and therefore must run
        # outside the main thread that receives SIGINT/SIGTERM.
        threading.Thread(target=server.shutdown, name="http-shutdown", daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    capture_thread.start()
    LOG.info("MA300 agent listens on http://%s:%s", settings.listen_host, settings.listen_port)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        stopped.set()
        server.server_close()
        capture_thread.join(timeout=settings.reconnect_delay_seconds + 1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
