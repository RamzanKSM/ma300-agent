import logging
import threading
import time
import unittest
from struct import pack

from app import CARD_REPEAT_SECONDS, EF_ATTLOG, EF_HIDNUM, EVENT_MASK, LOG, DeviceStatus, Settings, ZkLiveCaptureSource
from fake_ma300 import FakeMA300
from test_watchdog import RecordingHandler, wait_until

CARD = 7654321


class CardEventsTest(unittest.TestCase):
    """Real pyzk 0.9 and the agent's capture loop against FakeMA300: `userId` is always the card number."""

    def setUp(self) -> None:
        self.device = FakeMA300()
        self.device.cards = {"2265": CARD, "31": 0}
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
        self.assertTrue(wait_until(lambda: self.device.client is not None))
        time.sleep(0.2)

    def cards(self):
        return [event.user_id for event in self.events]

    def test_subscribes_to_everything_but_fingerprint_minutiae(self) -> None:
        self.start()
        self.assertEqual(self.device.registered_masks, [EVENT_MASK])

    def test_a_refused_mask_falls_back_to_attendance_only(self) -> None:
        self.device.refuse_wide_mask = True
        self.start()
        self.assertTrue(wait_until(lambda: self.device.registered_masks[-1:] == [EF_ATTLOG]))
        self.device.push_event("2265")
        self.assertTrue(wait_until(lambda: self.cards() == [str(CARD)]))

    def test_an_unknown_card_reaches_the_stream(self) -> None:
        self.start()
        self.device.push_raw_event(EF_HIDNUM, pack("<I", 998877))
        self.assertTrue(wait_until(lambda: self.cards() == ["998877"]))

    def test_an_enrolled_user_is_reported_by_the_card_not_by_the_terminal_id(self) -> None:
        self.start()
        self.device.push_event("2265")
        self.assertTrue(wait_until(lambda: self.cards() == [str(CARD)]))

    def test_one_touch_reported_twice_is_one_event(self) -> None:
        self.start()
        self.device.push_raw_event(EF_HIDNUM, pack("<I", CARD))
        self.device.push_event("2265")
        self.assertTrue(wait_until(lambda: self.cards() == [str(CARD)]))
        time.sleep(0.3)
        self.assertEqual(self.cards(), [str(CARD)])

    def test_the_same_card_later_is_a_new_event(self) -> None:
        self.start()
        self.device.push_event("2265")
        self.assertTrue(wait_until(lambda: len(self.cards()) == 1))
        time.sleep(CARD_REPEAT_SECONDS + 0.1)
        self.device.push_event("2265")
        self.assertTrue(wait_until(lambda: len(self.cards()) == 2))

    def test_a_user_without_a_card_gives_no_event(self) -> None:
        self.start()
        self.device.push_event("31")
        self.assertTrue(wait_until(lambda: any("31 has no card" in m for m in self.log.messages(logging.WARNING))))
        self.assertEqual(self.cards(), [])

    def test_a_user_enrolled_after_connecting_is_found(self) -> None:
        self.start()
        self.device.cards["40"] = 111222
        self.device.push_event("40")
        self.assertTrue(wait_until(lambda: self.cards() == ["111222"]))

    def test_other_events_are_logged_for_diagnostics_and_give_no_read(self) -> None:
        self.start()
        self.device.push_raw_event(512, bytes.fromhex("3a000000"))
        self.assertTrue(wait_until(lambda: "MA300 event code=512 data=3a000000" in self.log.messages(logging.INFO)))
        self.assertEqual(self.cards(), [])
