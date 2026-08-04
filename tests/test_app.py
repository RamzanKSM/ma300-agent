import unittest
from datetime import datetime

from app import DeviceAttendanceEvent


class Attendance:
    user_id = 2265
    timestamp = datetime(2026, 6, 25, 22, 46, 45)
    status = 2
    punch = 0


class DeviceAttendanceEventTest(unittest.TestCase):
    def test_converts_the_pyzk_attendance_shape_to_the_frontend_contract(self) -> None:
        event = DeviceAttendanceEvent.from_pyzk(Attendance())

        self.assertEqual(event.user_id, "2265")
        self.assertEqual(event.timestamp, "2026-06-25T22:46:45")
        self.assertEqual(event.status, 2)
        self.assertEqual(event.punch, 0)
        self.assertEqual(event.sse_payload()["userId"], "2265")
        self.assertEqual(event.sse_payload()["type"], "attendance")

    def test_rejects_an_attendance_without_user_id(self) -> None:
        class EmptyAttendance:
            user_id = ""

        with self.assertRaisesRegex(ValueError, "user_id"):
            DeviceAttendanceEvent.from_pyzk(EmptyAttendance())


if __name__ == "__main__":
    unittest.main()
