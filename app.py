#!/usr/bin/env python3
"""MA300-to-browser bridge.

Reads live pyzk Attendance objects from one MA300 device and publishes a
normalized, one-way SSE stream for the reception frontend. This process never
creates attendance records in the main application.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import signal
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Iterator


LOG = logging.getLogger("ma300_agent")


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

    @classmethod
    def from_environment(cls) -> "Settings":
        return cls(
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
        )


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


class ZkLiveCaptureSource:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def events(self, stopped: threading.Event) -> Iterator[DeviceAttendanceEvent]:
        while not stopped.is_set():
            connection = None
            try:
                connection = self._connect()
                LOG.info("Connected to MA300 at %s:%s", self._settings.device_host, self._settings.device_port)
                connection.enable_device()
                LOG.info("Waiting for MA300 live events")

                for attendance in connection.live_capture():
                    if stopped.is_set():
                        return
                    if attendance is None:
                        LOG.info("time out")
                        continue
                    try:
                        event = DeviceAttendanceEvent.from_pyzk(attendance)
                    except (TypeError, ValueError) as error:
                        LOG.warning("Ignoring malformed MA300 Attendance: %s", error)
                        continue
                    LOG.info(
                        "EVENT: <Attendance>: %s : %s (%s, %s)",
                        event.user_id,
                        event.timestamp,
                        event.status,
                        event.punch,
                    )
                    yield event
            except Exception as error:  # pyzk exposes transport errors through several exception types.
                if stopped.is_set():
                    return
                LOG.exception("MA300 connection/capture failed: %s", error)
                stopped.wait(self._settings.reconnect_delay_seconds)
            finally:
                if connection is not None:
                    try:
                        connection.disconnect()
                        LOG.info("Disconnected from MA300")
                    except Exception as error:  # disconnect is best-effort after a failed socket.
                        LOG.warning("MA300 disconnect failed: %s", error)

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
        return client.connect()


class AgentHttpServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], hub: EventHub) -> None:
        super().__init__(address, AgentRequestHandler)
        self.hub = hub


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
            self._json_response(HTTPStatus.OK, {"status": "ok"})
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
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.server.hub.unsubscribe(client)

    def _json_response(self, status: HTTPStatus, payload: dict[str, str]) -> None:
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


def configure_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> None:
    configure_logging()
    settings = Settings.from_environment()
    stopped = threading.Event()
    hub = EventHub()
    source = ZkLiveCaptureSource(settings)
    capture_thread = threading.Thread(target=run_capture, args=(source, hub, stopped), name="ma300-capture", daemon=True)
    server = AgentHttpServer((settings.listen_host, settings.listen_port), hub)

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


if __name__ == "__main__":
    main()
