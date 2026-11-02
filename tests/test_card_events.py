import http.client
import json
import logging
import threading
import time
import unittest

from app import (
    CARD_REPEAT_SECONDS,
    EF_CARD,
    EVENT_MASK,
    LOG,
    LOG_BUFFER,
    AgentHttpServer,
    DeviceStatus,
    EventHub,
    LogBuffer,
    Settings,
    ZkLiveCaptureSource,
)
from fake_ma300 import FakeMA300
from test_watchdog import RecordingHandler, wait_until

CARD = "7654321"


class CardEventsTest(unittest.TestCase):
    """Real pyzk 0.9 and the agent's capture loop against FakeMA300: `userId` is always the card number."""

    def setUp(self) -> None:
        self.device = FakeMA300()
        self.log = RecordingHandler()
        self.previous_level = LOG.level
        LOG.setLevel(logging.DEBUG)
        LOG.addHandler(self.log)
        self.stopped = threading.Event()
        self.events = []
        self.thread = None

    def tearDown(self) -> None:
        self.stopped.set()
        if self.thread is not None:
            self.device.push_raw_event(0, b"")  # wakes the loop so it sees the stop flag
            self.thread.join(timeout=10)
        LOG.removeHandler(self.log)
        LOG.setLevel(self.previous_level)
        self.assertEqual(self.device.user_table_requests, 0, "the agent must not depend on the user table")
        self.device.close()

    def start(self) -> None:
        settings = Settings(
            device_host="127.0.0.1",
            device_port=self.device.port,
            device_timeout_seconds=1,
            device_password=0,
            force_udp=True,
            omit_ping=True,
            verbose_pyzk=False,
            listen_host="127.0.0.1",
            listen_port=0,
            reconnect_delay_seconds=0,
            idle_check_seconds=0,
        )
        source = ZkLiveCaptureSource(settings, DeviceStatus())

        def run() -> None:
            for event in source.events(self.stopped):
                self.events.append(event)

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.assertTrue(wait_until(lambda: self.device.registered_masks))
        time.sleep(0.2)

    def cards(self):
        return [event.user_id for event in self.events]

    def test_subscribes_to_everything_but_fingerprint_minutiae(self) -> None:
        self.start()
        self.assertEqual(self.device.registered_masks, [EVENT_MASK])

    def test_a_refused_mask_falls_back_to_cards_only(self) -> None:
        self.device.refuse_wide_mask = True
        self.start()
        self.assertTrue(wait_until(lambda: self.device.registered_masks[-1:] == [EF_CARD]))
        self.device.push_event(CARD)
        self.assertTrue(wait_until(lambda: self.cards() == [CARD]))

    def test_a_card_reaches_the_stream_by_its_number(self) -> None:
        self.start()
        self.device.push_event(CARD)
        self.assertTrue(wait_until(lambda: self.cards() == [CARD]))

    def test_packets_captured_from_the_real_ma300(self) -> None:
        self.start()
        self.device.push_raw_event(1024, bytes.fromhex("2498110000"))  # a card the terminal does not know
        self.device.push_raw_event(128, bytes.fromhex("ffffffffff"))
        self.device.push_raw_event(512, bytes.fromhex("3a000000"))
        self.device.push_raw_event(1024, bytes.fromhex("e9297b0000"))  # an enrolled card
        self.device.push_raw_event(1, bytes.fromhex("c607000002001a0b02142a08"))
        self.assertTrue(wait_until(lambda: self.cards() == ["1153060", "8071657"]))
        time.sleep(0.3)
        self.assertEqual(self.cards(), ["1153060", "8071657"])

    def test_an_attendance_is_not_a_card_read_and_is_logged(self) -> None:
        self.start()
        self.device.push_attendance("2265")
        self.assertTrue(wait_until(lambda: any("terminal user 2265" in m for m in self.log.messages(logging.INFO))))
        self.assertEqual(self.cards(), [])

    def test_a_card_held_at_the_terminal_is_one_event(self) -> None:
        self.start()
        self.device.push_event(CARD)
        self.device.push_event(CARD)
        self.assertTrue(wait_until(lambda: self.cards() == [CARD]))
        time.sleep(0.3)
        self.assertEqual(self.cards(), [CARD])

    def test_the_same_card_later_is_a_new_event(self) -> None:
        self.start()
        self.device.push_event(CARD)
        self.assertTrue(wait_until(lambda: len(self.cards()) == 1))
        time.sleep(CARD_REPEAT_SECONDS + 0.1)
        self.device.push_event(CARD)
        self.assertTrue(wait_until(lambda: len(self.cards()) == 2))

    def test_another_card_right_away_is_a_new_event(self) -> None:
        self.start()
        self.device.push_event(CARD)
        self.device.push_event("111222")
        self.assertTrue(wait_until(lambda: self.cards() == [CARD, "111222"]))

    def test_other_events_are_logged_for_diagnostics_and_give_no_read(self) -> None:
        self.start()
        self.device.push_raw_event(512, bytes.fromhex("3a000000"))
        self.assertTrue(wait_until(lambda: "MA300 event code=512 data=3a000000" in self.log.messages(logging.INFO)))
        self.assertEqual(self.cards(), [])


class LogPageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = AgentHttpServer(("127.0.0.1", 0), EventHub(), DeviceStatus())
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def get(self, path: str, host: str = "127.0.0.1"):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("GET", path, skip_host=True)
            connection.putheader("Host", host)
            connection.endheaders()
            response = connection.getresponse()
            return response, response.read()
        finally:
            connection.close()

    def test_the_page_opens_and_no_other_site_may_read_it(self) -> None:
        response, body = self.get("/logs")
        self.assertEqual(response.status, 200)
        self.assertIn("text/html", response.getheader("Content-Type"))
        self.assertIn("Логи MA300", body.decode())
        self.assertIsNone(response.getheader("Access-Control-Allow-Origin"))

    def test_data_returns_only_new_lines_and_the_device_state(self) -> None:
        LOG_BUFFER.add("first line")
        _, body = self.get("/logs/data?after=0")
        data = json.loads(body)
        self.assertEqual(data["device"]["state"], "starting")
        self.assertEqual(data["lines"][-1]["text"], "first line")
        LOG_BUFFER.add("second line")
        response, body = self.get(f"/logs/data?after={data['lines'][-1]['seq']}")
        self.assertEqual([line["text"] for line in json.loads(body)["lines"]], ["second line"])
        self.assertIsNone(response.getheader("Access-Control-Allow-Origin"))

    def test_a_foreign_host_name_gets_nothing(self) -> None:
        for path in ("/logs", "/logs/data"):
            response, _ = self.get(path, host="evil.example:8765")
            self.assertEqual(response.status, 403)

    def test_localhost_with_a_port_is_allowed(self) -> None:
        response, _ = self.get("/logs", host=f"localhost:{self.port}")
        self.assertEqual(response.status, 200)


class LogBufferTest(unittest.TestCase):
    def test_keeps_only_the_last_lines(self) -> None:
        buffer = LogBuffer(capacity=2)
        for line in ("a", "b", "c"):
            buffer.add(line)
        self.assertEqual([line["text"] for line in buffer.after(0)], ["b", "c"])
