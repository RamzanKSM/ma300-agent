import logging
import threading
import time
import unittest

from app import LOG, DeviceStatus, Settings, ZkLiveCaptureSource
from fake_ma300 import CMD_ACK_ERROR, CMD_CONNECT, CMD_GET_TIME, CMD_REG_EVENT, FakeMA300

TIMEOUT = 1
IDLE_CHECK = 2


class RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append((time.monotonic(), record.levelno, record.getMessage()))

    def messages(self, level: int):
        return [message for _, levelno, message in self.records if levelno == level]


def wait_until(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class WatchdogTest(unittest.TestCase):
    """The capture loop against real pyzk 0.9 talking UDP to FakeMA300 on 127.0.0.1."""

    timeout = TIMEOUT
    idle_check = IDLE_CHECK

    def setUp(self) -> None:
        self.device = FakeMA300()
        self.settings = Settings(
            device_host="127.0.0.1",
            device_port=self.device.port,
            device_timeout_seconds=self.timeout,
            device_password=0,
            force_udp=True,
            omit_ping=True,
            verbose_pyzk=False,
            listen_host="127.0.0.1",
            listen_port=0,
            reconnect_delay_seconds=0,
            idle_check_seconds=self.idle_check,
        )
        self.log = RecordingHandler()
        self.previous_level = LOG.level
        LOG.setLevel(logging.DEBUG)
        LOG.addHandler(self.log)
        self.status = DeviceStatus()
        self.source = ZkLiveCaptureSource(self.settings, self.status)
        self.stopped = threading.Event()
        self.events = []
        self.thread = threading.Thread(target=self._capture, daemon=True)
        self.thread.start()
        self.assertTrue(wait_until(lambda: self.device.count(CMD_REG_EVENT) >= 1), "live capture did not start")
        self.capture_started = time.monotonic()

    def tearDown(self) -> None:
        self.stopped.set()
        self.device.push_event("0")  # wakes live_capture so the loop sees the stop flag
        self.thread.join(timeout=self.timeout * 3)
        LOG.removeHandler(self.log)
        LOG.setLevel(self.previous_level)
        # pyzk get_attendance() sends CMD_ATTLOG_RRQ inside CMD_PREPARE_BUFFER (1503); the fake counts both.
        self.assertEqual(self.device.journal_requests, 0, "the journal must never be replayed")
        self.device.close()

    def _capture(self) -> None:
        for event in self.source.events(self.stopped):
            self.events.append(event)

    def user_ids(self):
        return [event.user_id for event in self.events]

    def test_reconnects_when_the_terminal_stops_answering(self) -> None:
        self.device.silent = True
        dead_since = time.monotonic()

        self.assertTrue(wait_until(lambda: self.log.messages(logging.WARNING)))
        detected_at, _, message = next(r for r in self.log.records if r[1] == logging.WARNING)
        self.assertIn("MA300 session did not answer (no reply to the session check", message)
        self.assertLessEqual(detected_at - dead_since, IDLE_CHECK + TIMEOUT + 0.3)
        self.assertGreaterEqual(detected_at - dead_since, IDLE_CHECK - 0.1)

        self.device.silent = False
        self.assertTrue(wait_until(lambda: self.device.connects >= 2 and self.status.snapshot()["state"] == "connected"))
        self.assertTrue(wait_until(lambda: self.device.count(CMD_REG_EVENT) >= 2))
        self.device.push_event("2265")
        self.assertTrue(wait_until(lambda: self.user_ids() == ["2265"]))
        snapshot = self.status.snapshot()
        self.assertGreaterEqual(snapshot["reconnects"], 1)
        self.assertIsNotNone(snapshot["lastError"])

    def test_reconnects_when_the_terminal_forgot_the_session(self) -> None:
        self.device.forget_session = True

        self.assertTrue(wait_until(lambda: self.device.connects >= 2))
        warnings = self.log.messages(logging.WARNING)
        self.assertEqual(len(warnings), 1)
        self.assertIn("unauthorized", warnings[0])
        self.assertTrue(wait_until(lambda: self.device.count(CMD_REG_EVENT) >= 2))
        self.device.push_event("2265")
        self.assertTrue(wait_until(lambda: self.user_ids() == ["2265"]))
        self.assertEqual(self.status.snapshot()["reconnects"], 1)

    def test_keeps_a_live_session_and_logs_nothing_at_info_while_idle(self) -> None:
        self.assertTrue(wait_until(lambda: self.device.count(CMD_GET_TIME) >= 2, timeout=IDLE_CHECK * 4))
        self.device.push_event("2265")
        self.assertTrue(wait_until(lambda: self.user_ids() == ["2265"]))
        time.sleep(TIMEOUT)

        self.assertEqual(self.device.connects, 1)
        self.assertEqual(self.device.count(CMD_CONNECT), 1)
        self.assertEqual(self.user_ids(), ["2265"])
        self.assertEqual(self.log.messages(logging.WARNING), [])
        self.assertIn("time out", self.log.messages(logging.DEBUG))
        infos = self.log.messages(logging.INFO)
        self.assertNotIn("time out", infos)
        self.assertEqual(len(infos), 2, infos)  # connected + the event
        self.assertTrue(infos[0].startswith("Connected to MA300"))
        self.assertTrue(infos[1].startswith("EVENT: <Attendance>: 2265"))
        self.assertEqual(self.status.snapshot()["state"], "connected")

    def test_an_event_pushed_during_the_session_check_arrives_once(self) -> None:
        self.device.event_before_time_reply = "777"

        self.assertTrue(wait_until(lambda: self.user_ids() == ["777"], timeout=IDLE_CHECK * 3))
        # Our ack for the event plus live_capture's ack of the late clock reply.
        self.assertTrue(wait_until(lambda: self.device.event_acks >= 2))
        # One more full check cycle: no duplicate, no reconnect.
        checks = self.device.count(CMD_GET_TIME)
        self.assertTrue(wait_until(lambda: self.device.count(CMD_GET_TIME) > checks, timeout=IDLE_CHECK * 3))
        self.device.push_event("2265")
        self.assertTrue(wait_until(lambda: len(self.events) == 2))
        time.sleep(TIMEOUT)

        self.assertEqual(self.user_ids(), ["777", "2265"])
        self.assertEqual(self.device.event_acks, 3)
        self.assertEqual(self.device.connects, 1)
        self.assertEqual(self.log.messages(logging.WARNING), [])
        # The clock reply that the event displaced must not break reply_id numbering.
        reply_ids = self.device.session_reply_ids()
        self.assertEqual([b - a for a, b in zip(reply_ids, reply_ids[1:])], [1] * (len(reply_ids) - 1), reply_ids)

    def test_an_error_answer_to_the_session_check_keeps_the_session(self) -> None:
        self.device.time_reply_code = CMD_ACK_ERROR

        self.assertTrue(wait_until(lambda: self.device.count(CMD_GET_TIME) >= 2, timeout=IDLE_CHECK * 4))
        self.device.push_event("2265")
        self.assertTrue(wait_until(lambda: self.user_ids() == ["2265"]))

        self.assertEqual(self.device.connects, 1)
        self.assertEqual(self.log.messages(logging.WARNING), [])
        self.assertTrue(any("code 2001" in message for message in self.log.messages(logging.DEBUG)))
        self.assertEqual(self.status.snapshot()["reconnects"], 0)

    def test_a_passed_check_restarts_the_silence_timer(self) -> None:
        self.assertTrue(wait_until(lambda: self.device.count(CMD_GET_TIME) >= 3, timeout=IDLE_CHECK * 5))

        checks = self.device.times(CMD_GET_TIME)
        gaps = [later - earlier for earlier, later in zip(checks, checks[1:])]
        for gap in gaps:
            self.assertGreaterEqual(gap, IDLE_CHECK - 0.2, gaps)
        self.assertGreaterEqual(checks[0] - self.capture_started, IDLE_CHECK - 0.2)

    def test_an_event_right_after_the_session_check_arrives_once(self) -> None:
        self.device.event_after_time_reply = "778"

        self.assertTrue(wait_until(lambda: self.user_ids() == ["778"], timeout=IDLE_CHECK * 3))
        time.sleep(TIMEOUT * 2)

        self.assertEqual(self.user_ids(), ["778"])
        self.assertEqual(self.device.connects, 1)
        self.assertEqual(self.log.messages(logging.WARNING), [])

    def test_events_restart_the_silence_timer(self) -> None:
        # An event every TIMEOUT/2 keeps the line busy: no session check is needed.
        for index in range(int(IDLE_CHECK * 2 / (TIMEOUT / 2))):
            self.device.push_event(str(1000 + index))
            time.sleep(TIMEOUT / 2)

        self.assertEqual(self.device.count(CMD_GET_TIME), 0)
        self.assertEqual(len(self.events), int(IDLE_CHECK * 2 / (TIMEOUT / 2)))


class UnevenTimeoutsTest(WatchdogTest):
    """IDLE_CHECK not a multiple of the timeout: detection still within IDLE_CHECK + timeout."""

    timeout = 2
    idle_check = 3

    def test_detection_stays_within_idle_check_plus_timeout(self) -> None:
        self.device.silent = True
        dead_since = time.monotonic()

        self.assertTrue(wait_until(lambda: self.log.messages(logging.WARNING), timeout=15))
        detected_at = next(r[0] for r in self.log.records if r[1] == logging.WARNING)
        # First silent timeout with silence >= 3 s comes at 4 s; the check may wait only 1 s more.
        self.assertLessEqual(detected_at - dead_since, self.idle_check + self.timeout + 0.3)
        self.assertGreaterEqual(detected_at - dead_since, self.idle_check + self.timeout - 0.5)


for _name in [name for name in vars(WatchdogTest) if name.startswith("test_")]:
    setattr(UnevenTimeoutsTest, _name, None)  # run only the uneven-timeout test with these timings


class JournalGuardTest(unittest.TestCase):
    def test_the_fake_detects_pyzk_get_attendance(self) -> None:
        from zk import ZK

        device = FakeMA300()
        client = ZK("127.0.0.1", port=device.port, timeout=TIMEOUT, force_udp=True, ommit_ping=True)
        try:
            connection = client.connect()
            with self.assertRaises(Exception):
                connection.get_attendance()  # the fake refuses the buffered read after counting it
            self.assertEqual(device.journal_requests, 1)
        finally:
            device.close()
            getattr(client, "_ZK__sock").close()


class SessionCheckOffTest(unittest.TestCase):
    def test_zero_turns_the_session_check_off(self) -> None:
        device = FakeMA300()
        settings = Settings("127.0.0.1", device.port, TIMEOUT, 0, True, True, False, "127.0.0.1", 0, 0, 0)
        stopped = threading.Event()
        source = ZkLiveCaptureSource(settings)
        thread = threading.Thread(target=lambda: [None for _ in source.events(stopped)], daemon=True)
        thread.start()
        try:
            self.assertTrue(wait_until(lambda: device.count(CMD_REG_EVENT) >= 1))
            time.sleep(TIMEOUT * 3)
            self.assertEqual(device.count(CMD_GET_TIME), 0)
        finally:
            stopped.set()
            device.push_event("0")
            thread.join(timeout=TIMEOUT * 3)
            device.close()


if __name__ == "__main__":
    unittest.main()
