import logging
import os
import socket
import sys
import tempfile
import unittest
from unittest import mock

import app
from app import (
    SO_EXCLUSIVEADDRUSE,
    AgentHttpServer,
    EventHub,
    address_in_use,
    configure_listen_socket,
    configure_logging,
    load_env_file,
)


class EnvFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.directory.name, ".env")

    def tearDown(self) -> None:
        self.directory.cleanup()

    def write(self, text: str, encoding: str = "utf-8") -> None:
        with open(self.path, "w", encoding=encoding) as env_file:
            env_file.write(text)

    def test_reads_key_value_lines_comments_and_quotes(self) -> None:
        self.write(
            "# MA300\n\nMA300_HOST=192.168.1.201\nMA300_PORT = 4370\n"
            "LOG_FILE=\"C:\\Агент MA300\\logs\\agent.log\"\nAGENT_HOST='127.0.0.1'\nexport LOG_LEVEL=DEBUG\n"
        )
        environ = {}

        problems = load_env_file(self.path, environ)

        self.assertEqual(problems, [])
        self.assertEqual(
            environ,
            {
                "MA300_HOST": "192.168.1.201",
                "MA300_PORT": "4370",
                "LOG_FILE": "C:\\Агент MA300\\logs\\agent.log",
                "AGENT_HOST": "127.0.0.1",
                "LOG_LEVEL": "DEBUG",
            },
        )

    def test_never_overrides_variables_that_are_already_set(self) -> None:
        self.write("MA300_HOST=192.168.1.201\nAGENT_PORT=8765\nLOG_LEVEL=INFO\n")
        environ = {"MA300_HOST": "10.0.0.5", "LOG_LEVEL": ""}

        load_env_file(self.path, environ)

        self.assertEqual(environ, {"MA300_HOST": "10.0.0.5", "LOG_LEVEL": "", "AGENT_PORT": "8765"})

    def test_accepts_the_byte_order_mark_of_windows_notepad(self) -> None:
        self.write("MA300_HOST=192.168.1.201\r\n", encoding="utf-8-sig")
        environ = {}

        load_env_file(self.path, environ)

        self.assertEqual(environ, {"MA300_HOST": "192.168.1.201"})

    def test_unquoted_hash_after_a_space_starts_a_comment_like_bash(self) -> None:
        self.write(
            "MA300_HOST=192.168.1.201 # reception\n"
            "MA300_PASSWORD=12#34\n"
            "LOG_FILE=\"C:\\logs #1\\agent.log\" # quoted keeps #\n"
            "AGENT_HOST='127.0.0.1 #x'\n"
            "LOG_LEVEL=INFO\t# tab\n"
        )
        environ = {}

        load_env_file(self.path, environ)

        self.assertEqual(
            environ,
            {
                "MA300_HOST": "192.168.1.201",
                "MA300_PASSWORD": "12#34",
                "LOG_FILE": "C:\\logs #1\\agent.log",
                "AGENT_HOST": "127.0.0.1 #x",
                "LOG_LEVEL": "INFO",
            },
        )

    def test_empty_value_followed_by_a_comment_is_empty(self) -> None:
        self.write("LOG_FILE= # optional\nLOG_LEVEL=\t# tab\nMA300_HOST=#not-a-comment\n")
        environ = {}

        self.assertEqual(load_env_file(self.path, environ), [])

        self.assertEqual(environ, {"LOG_FILE": "", "LOG_LEVEL": "", "MA300_HOST": "#not-a-comment"})

    def test_ansi_file_from_windows_notepad_is_read_as_cp1251_with_a_warning(self) -> None:
        self.write("# терминал на ресепшене\nMA300_HOST=192.168.1.201 # ресепшен\nLOG_FILE=C:\\Агент\\agent.log\n", encoding="cp1251")
        environ = {}

        problems = load_env_file(self.path, environ)

        self.assertEqual(environ, {"MA300_HOST": "192.168.1.201", "LOG_FILE": "C:\\Агент\\agent.log"})
        self.assertEqual(len(problems), 1)
        self.assertIn("is not UTF-8, read it as cp1251; save it in Notepad as UTF-8", problems[0])

    def test_reports_lines_without_key_value(self) -> None:
        self.write("MA300_HOST\n=value\n")
        environ = {}

        problems = load_env_file(self.path, environ)

        self.assertEqual(environ, {})
        self.assertEqual(len(problems), 2)

    def test_agent_env_file_overrides_the_default_path(self) -> None:
        self.write("MA300_HOST=192.168.1.201\n")
        environ = {"AGENT_ENV_FILE": self.path}

        load_env_file(environ=environ)

        self.assertEqual(environ["MA300_HOST"], "192.168.1.201")

    def test_missing_default_file_is_fine_but_a_missing_explicit_file_is_reported(self) -> None:
        with mock.patch.object(app, "APP_DIR", self.directory.name):
            self.assertEqual(load_env_file(environ={}), [])
        self.assertEqual(len(load_env_file(environ={"AGENT_ENV_FILE": self.path + ".missing"})), 1)


class LoggingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root_handlers = logging.getLogger().handlers[:]
        self.root_level = logging.getLogger().level

    def tearDown(self) -> None:
        root = logging.getLogger()
        for handler in root.handlers[:]:
            if handler not in self.root_handlers:
                handler.close()
                root.removeHandler(handler)
        for handler in self.root_handlers:
            if handler not in root.handlers:
                root.addHandler(handler)
        root.setLevel(self.root_level)
        self.directory.cleanup()

    def test_without_stderr_logs_to_the_default_file_and_print_does_not_fail(self) -> None:
        environment = {key: value for key, value in os.environ.items() if key not in ("LOG_FILE", "LOG_LEVEL")}
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            sys, "stderr", None
        ), mock.patch.object(sys, "stdout", None):
            log_file = configure_logging(self.directory.name)
            logging.getLogger("ma300_agent").info("pythonw line")
            logging.getLogger("ma300_agent").debug("hidden line")
            print("pyzk verbose output")
            sys.stderr.write("thread traceback\n")
            devnull_streams = (sys.stdout, sys.stderr)

        for stream in devnull_streams:
            stream.close()
        expected = os.path.join(self.directory.name, "logs", "ma300-agent.log")
        self.assertEqual(log_file, expected)
        with open(expected, encoding="utf-8") as log:
            content = log.read()
        self.assertIn("INFO ma300_agent: pythonw line", content)
        self.assertNotIn("hidden line", content)

    def test_log_file_rotates(self) -> None:
        target = os.path.join(self.directory.name, "custom", "agent.log")
        with mock.patch.dict(os.environ, {"LOG_FILE": target, "LOG_LEVEL": "INFO"}):
            self.assertEqual(configure_logging(self.directory.name), target)
        rotating = [h for h in logging.getLogger().handlers if isinstance(h, logging.handlers.RotatingFileHandler)]
        self.assertEqual(len(rotating), 1)
        self.assertEqual(rotating[0].maxBytes, 1024 * 1024)
        self.assertEqual(rotating[0].backupCount, 5)
        self.assertTrue(os.path.isdir(os.path.dirname(target)))


class FakeSocket:
    def __init__(self) -> None:
        self.options = []

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))


class SingleInstanceTest(unittest.TestCase):
    def test_windows_socket_is_exclusive_and_never_reuses_the_address(self) -> None:
        sock = FakeSocket()
        with mock.patch.object(app, "running_on_windows", return_value=True):
            configure_listen_socket(sock)

        self.assertEqual(sock.options, [(socket.SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)])
        self.assertNotIn(socket.SO_REUSEADDR, [option for _, option, _ in sock.options])
        self.assertFalse(AgentHttpServer.allow_reuse_address)

    def test_posix_socket_keeps_reuse_address_for_restarts(self) -> None:
        sock = FakeSocket()
        with mock.patch.object(app, "running_on_windows", return_value=False):
            configure_listen_socket(sock)

        self.assertEqual(sock.options, [(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)])

    def test_windows_bind_errors_count_as_address_in_use(self) -> None:
        for winerror in (10048, 10013):
            error = OSError(winerror, "bind failed")
            error.winerror = winerror
            self.assertTrue(address_in_use(error))
        self.assertFalse(address_in_use(PermissionError(13, "denied")))

    def test_a_second_server_on_the_same_port_fails(self) -> None:
        first = AgentHttpServer(("127.0.0.1", 0), EventHub())
        try:
            port = first.server_address[1]
            with self.assertRaises(OSError) as raised:
                AgentHttpServer(("127.0.0.1", port), EventHub())
            self.assertTrue(address_in_use(raised.exception))
        finally:
            first.server_close()

    def test_restart_on_the_same_port_after_stop_still_works(self) -> None:
        first = AgentHttpServer(("127.0.0.1", 0), EventHub())
        port = first.server_address[1]
        first.server_close()

        second = AgentHttpServer(("127.0.0.1", port), EventHub())
        second.server_close()

    def test_second_agent_exits_with_a_clear_message_before_contacting_the_ma300(self) -> None:
        first = AgentHttpServer(("127.0.0.1", 0), EventHub())
        port = first.server_address[1]
        root = logging.getLogger()
        saved_handlers, saved_level = root.handlers[:], root.level
        environment = {
            "AGENT_ENV_FILE": os.devnull,
            "MA300_HOST": "127.0.0.1",
            "AGENT_HOST": "127.0.0.1",
            "AGENT_PORT": str(port),
            "LOG_LEVEL": "INFO",
        }
        try:
            with mock.patch.dict(os.environ, environment), mock.patch.object(
                app.ZkLiveCaptureSource, "_connect", side_effect=AssertionError("connected to MA300")
            ) as connect, mock.patch.object(app.threading.Thread, "start") as thread_start, self.assertLogs(
                "ma300_agent", level="ERROR"
            ) as logs:
                code = app.main()
        finally:
            first.server_close()
            root.handlers[:] = saved_handlers
            root.setLevel(saved_level)

        self.assertNotEqual(code, 0)
        connect.assert_not_called()
        thread_start.assert_not_called()
        self.assertIn("already running", logs.output[0])
        self.assertIn("агент уже запущен", logs.output[0])


class StartupErrorTest(unittest.TestCase):
    """Under pythonw.exe (no stderr) startup errors must reach logs/ma300-agent.log."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        root = logging.getLogger()
        self.saved_handlers, self.saved_level = root.handlers[:], root.level

    def tearDown(self) -> None:
        root = logging.getLogger()
        for handler in root.handlers[:]:
            if handler not in self.saved_handlers:
                handler.close()
        root.handlers[:] = self.saved_handlers
        root.setLevel(self.saved_level)
        self.directory.cleanup()

    def run_main_without_console(self, environment):
        base = {key: value for key, value in os.environ.items() if not key.startswith(("MA300_", "AGENT_", "LOG_"))}
        base.update({"AGENT_ENV_FILE": os.devnull, "AGENT_HOST": "127.0.0.1", "AGENT_PORT": "0"})
        base.update(environment)
        with mock.patch.dict(os.environ, base, clear=True), mock.patch.object(app, "APP_DIR", self.directory.name), \
                mock.patch.object(sys, "stderr", None), mock.patch.object(sys, "stdout", None), mock.patch.object(
                    app.ZkLiveCaptureSource, "_connect", side_effect=AssertionError("connected to MA300")) as connect, \
                mock.patch.object(app.threading.Thread, "start") as thread_start:
            code = app.main()
            streams = (sys.stdout, sys.stderr)
        for stream in streams:
            stream.close()
        connect.assert_not_called()
        thread_start.assert_not_called()
        with open(os.path.join(self.directory.name, "logs", "ma300-agent.log"), encoding="utf-8") as log:
            return code, log.read()

    def test_missing_ma300_host(self) -> None:
        code, log = self.run_main_without_console({})
        self.assertNotEqual(code, 0)
        self.assertIn("ERROR ma300_agent: Invalid settings: MA300_HOST must be set", log)

    def test_invalid_log_level(self) -> None:
        code, log = self.run_main_without_console({"MA300_HOST": "127.0.0.1", "LOG_LEVEL": "LOUD"})
        self.assertNotEqual(code, 0)
        self.assertIn("ERROR ma300_agent: Invalid settings: LOG_LEVEL must be", log)
        self.assertIn("'LOUD'", log)

    def test_invalid_integer_setting(self) -> None:
        code, log = self.run_main_without_console({"MA300_HOST": "127.0.0.1", "MA300_TIMEOUT_SECONDS": "ten"})
        self.assertNotEqual(code, 0)
        self.assertIn("MA300_TIMEOUT_SECONDS must be an integer", log)

    def test_unreadable_settings_file(self) -> None:
        env_path = os.path.join(self.directory.name, "locked.env")
        with open(env_path, "w") as env_file:
            env_file.write("MA300_HOST=127.0.0.1\n")
        os.chmod(env_path, 0)
        try:
            if os.access(env_path, os.R_OK):
                self.skipTest("running as a user who can read any file")
            code, log = self.run_main_without_console({"AGENT_ENV_FILE": env_path, "MA300_HOST": "127.0.0.1"})
        finally:
            os.chmod(env_path, 0o600)
        self.assertNotEqual(code, 0)
        self.assertIn("ERROR ma300_agent: Cannot read the settings file:", log)

    def test_ansi_settings_file_starts_with_a_warning_instead_of_failing(self) -> None:
        env_path = os.path.join(self.directory.name, "ansi.env")
        with open(env_path, "w", encoding="cp1251") as env_file:
            env_file.write("# ресепшен\nLOG_LEVEL=LOUD\n")
        code, log = self.run_main_without_console({"AGENT_ENV_FILE": env_path, "MA300_HOST": "127.0.0.1"})
        self.assertNotEqual(code, 0)  # LOUD is still invalid: the file itself was read
        self.assertIn("WARNING ma300_agent: %s is not UTF-8" % env_path, log)
        self.assertIn("'LOUD'", log)

    def test_bind_error_other_than_address_in_use(self) -> None:
        # 192.0.2.1 (TEST-NET-1) is not a local address: bind fails with EADDRNOTAVAIL.
        code, log = self.run_main_without_console({"MA300_HOST": "127.0.0.1", "AGENT_HOST": "192.0.2.1"})
        self.assertNotEqual(code, 0)
        self.assertIn("ERROR ma300_agent: Cannot listen on 192.0.2.1:0", log)


if __name__ == "__main__":
    unittest.main()
