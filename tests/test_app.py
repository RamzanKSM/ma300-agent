import http.client
import json
import threading
import unittest
from datetime import datetime

from app import AgentHttpServer, DeviceAttendanceEvent, EventHub


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


class AgentHttpServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.hub = EventHub()
        self.server = AgentHttpServer(("127.0.0.1", 0), self.hub)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def test_answers_the_health_check_with_cors(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request("GET", "/healthz")
            response = connection.getresponse()

            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Access-Control-Allow-Origin"), "*")
            self.assertEqual(json.loads(response.read()), {"status": "ok"})
        finally:
            connection.close()

    def test_streams_a_published_attendance_to_the_frontend(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request("GET", "/events")
            response = connection.getresponse()

            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Content-Type"), "text/event-stream")
            self.assertEqual(response.getheader("Access-Control-Allow-Origin"), "*")
            self.assertEqual(response.readline(), b"event: connected\n")
            self.assertEqual(response.readline(), b"data: {}\n")
            self.assertEqual(response.readline(), b"\n")

            self.hub.publish(DeviceAttendanceEvent.from_pyzk(Attendance()))

            self.assertEqual(response.readline(), b"event: attendance\n")
            data = response.readline().decode()
            self.assertTrue(data.startswith("data: "))
            payload = json.loads(data[len("data: "):])
            self.assertEqual(payload["type"], "attendance")
            self.assertEqual(payload["userId"], "2265")
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
