"""A minimal UDP MA300 for tests: enough of the ZK protocol for pyzk 0.9 live_capture().

Binds 127.0.0.1 on an ephemeral port and never talks to a real terminal.
"""

import socket
import threading
import time
from struct import pack, unpack

CMD_GET_FREE_SIZES = 50
CMD_STARTVERIFY = 60
CMD_CANCELCAPTURE = 62
CMD_ATTLOG_RRQ = 13
CMD_PREPARE_BUFFER = 1503  # pyzk read_with_buffer(): the real command is inside command_string
CMD_GET_TIME = 201
CMD_REG_EVENT = 500
CMD_CONNECT = 1000
CMD_EXIT = 1001
CMD_ENABLEDEVICE = 1002
CMD_ACK_OK = 2000
CMD_ACK_ERROR = 2001
CMD_ACK_UNAUTH = 2005


class FakeMA300:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.lock = threading.Lock()
        self.commands = []  # (command, session_id, reply_id, monotonic time) in arrival order
        self.journal_requests = 0  # CMD_ATTLOG_RRQ, direct or inside CMD_PREPARE_BUFFER
        self.event_acks = 0
        self.connects = 0
        self.session_id = 0
        self.next_session_id = 100
        self.client = None
        # Behaviour switches.
        self.silent = False  # drop every packet: terminal unreachable
        self.forget_session = False  # answer UNAUTH to the current session
        self.event_before_time_reply = None  # user_id pushed right before a CMD_GET_TIME reply
        self.event_after_time_reply = None  # user_id pushed right after a CMD_GET_TIME reply
        self.time_reply_code = CMD_ACK_OK  # answer code for CMD_GET_TIME in a live session
        # The journal holds old records, so pyzk get_attendance() really asks for them.
        self.records = 5
        self._stopped = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stopped.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def count(self, command: int) -> int:
        with self.lock:
            return sum(1 for item in self.commands if item[0] == command)

    def times(self, command: int):
        with self.lock:
            return [item[3] for item in self.commands if item[0] == command]

    def session_reply_ids(self):
        """reply_id of every command in the current session, except event acknowledgements."""
        with self.lock:
            return [item[2] for item in self.commands if item[1] == self.session_id and item[0] != CMD_ACK_OK]

    def push_event(self, user_id: str) -> None:
        payload = pack("<24sBB6s", user_id.encode(), 1, 0, bytes([26, 10, 29, 9, 15, 30]))
        header = pack("<4H", CMD_REG_EVENT, 0, self.session_id, 0)
        self.sock.sendto(header + payload, self.client)

    def _reply(self, code: int, session_id: int, reply_id: int, data: bytes = b"") -> None:
        self.sock.sendto(pack("<4H", code, 0, session_id, reply_id) + data, self.client)

    def _serve(self) -> None:
        while not self._stopped.is_set():
            try:
                packet, address = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            command, _checksum, session_id, reply_id = unpack("<4H", packet[:8])
            with self.lock:
                self.commands.append((command, session_id, reply_id, time.monotonic()))
                if command == CMD_ATTLOG_RRQ or (
                    command == CMD_PREPARE_BUFFER and len(packet) >= 11 and unpack("<h", packet[9:11])[0] == CMD_ATTLOG_RRQ
                ):
                    self.journal_requests += 1
                if self.silent:
                    continue
                self.client = address
                if command == CMD_CONNECT:
                    self.connects += 1
                    self.session_id = self.next_session_id
                    self.next_session_id += 1
                    self.forget_session = False
                    self._reply(CMD_ACK_OK, self.session_id, reply_id)
                    continue
                if command == CMD_ACK_OK:
                    self.event_acks += 1
                    continue
                if self.forget_session or session_id != self.session_id:
                    self._reply(CMD_ACK_UNAUTH, session_id, reply_id)
                    continue
                if command == CMD_GET_FREE_SIZES:
                    sizes = [0] * 20
                    sizes[8] = self.records
                    self._reply(CMD_ACK_OK, session_id, reply_id, pack("<20i", *sizes) + bytes(12))
                elif command == CMD_GET_TIME:
                    if self.event_before_time_reply:
                        self.push_event(self.event_before_time_reply)
                        self.event_before_time_reply = None
                    self._reply(self.time_reply_code, session_id, reply_id, pack("<I", 0))
                    if self.event_after_time_reply:
                        self.push_event(self.event_after_time_reply)
                        self.event_after_time_reply = None
                elif command in (CMD_CANCELCAPTURE, CMD_STARTVERIFY, CMD_ENABLEDEVICE, CMD_REG_EVENT, CMD_EXIT):
                    self._reply(CMD_ACK_OK, session_id, reply_id)
                else:
                    self._reply(CMD_ACK_ERROR, session_id, reply_id)
