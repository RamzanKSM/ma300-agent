import codecs
import contextlib
import io
import importlib.util
import ntpath
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ElementTree

from unittest import mock

from app import AgentHttpServer, DeviceStatus, EventHub

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WINDOWS = os.path.join(REPO, "windows")
_spec = importlib.util.spec_from_file_location("ma300_setup", os.path.join(WINDOWS, "ma300_setup.py"))
setup = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(setup)

NS = {"t": setup.TASK_NAMESPACE}
AGENT_DIR = "C:\\Users\\Ресепшен\\Рабочий стол\\MA300 R&D <агент>"


class TaskXmlTest(unittest.TestCase):
    def setUp(self) -> None:
        paths = setup.agent_paths(AGENT_DIR, ntpath)
        self.paths = paths
        self.data = setup.task_xml_bytes(setup.task_xml("RECEPTION\\Ресепшен", paths["pythonw"], paths["app"], AGENT_DIR))
        self.root = ElementTree.fromstring(self.data.decode("utf-16"))

    def text(self, path: str) -> str:
        return self.root.find(path, NS).text

    def test_is_utf16_with_bom(self) -> None:
        self.assertTrue(self.data.startswith(codecs.BOM_UTF16_LE))
        self.assertTrue(self.data.decode("utf-16").startswith('<?xml version="1.0" encoding="UTF-16"?>'))

    def test_runs_pythonw_app_in_the_agent_folder_with_escaped_paths(self) -> None:
        self.assertEqual(self.text("t:Actions/t:Exec/t:Command"), AGENT_DIR + "\\.venv\\Scripts\\pythonw.exe")
        self.assertEqual(self.text("t:Actions/t:Exec/t:Arguments"), '"' + AGENT_DIR + '\\app.py"')
        self.assertEqual(self.text("t:Actions/t:Exec/t:WorkingDirectory"), AGENT_DIR)
        raw = self.data.decode("utf-16")
        self.assertIn("MA300 R&amp;D &lt;агент&gt;", raw)

    def test_starts_at_logon_without_a_password(self) -> None:
        self.assertEqual(self.text("t:Triggers/t:LogonTrigger/t:UserId"), "RECEPTION\\Ресепшен")
        self.assertEqual(self.text("t:Principals/t:Principal/t:LogonType"), "InteractiveToken")
        self.assertEqual(self.text("t:Principals/t:Principal/t:UserId"), "RECEPTION\\Ресепшен")
        self.assertEqual(self.text("t:Principals/t:Principal/t:RunLevel"), "LeastPrivilege")

    def test_runs_forever_on_battery_restarts_on_failure_and_never_twice(self) -> None:
        self.assertEqual(self.text("t:Settings/t:ExecutionTimeLimit"), "PT0S")
        self.assertEqual(self.text("t:Settings/t:MultipleInstancesPolicy"), "IgnoreNew")
        self.assertEqual(self.text("t:Settings/t:DisallowStartIfOnBatteries"), "false")
        self.assertEqual(self.text("t:Settings/t:StopIfGoingOnBatteries"), "false")
        self.assertEqual(self.text("t:Settings/t:IdleSettings/t:StopOnIdleEnd"), "false")
        self.assertEqual(self.text("t:Settings/t:RestartOnFailure/t:Interval"), "PT1M")
        self.assertEqual(self.text("t:Settings/t:RestartOnFailure/t:Count"), "999")
        self.assertEqual(self.root.get("version"), "1.2")

    def test_user_id_comes_from_the_windows_session(self) -> None:
        self.assertEqual(setup.current_user_id({"USERDOMAIN": "PC", "USERNAME": "Ресепшен"}), "PC\\Ресепшен")
        self.assertEqual(setup.current_user_id({"USERNAME": "admin"}), "admin")
        with self.assertRaises(setup.SetupError):
            setup.current_user_id({})


class CmdScriptTest(unittest.TestCase):
    def test_scripts_are_ascii_with_crlf(self) -> None:
        for name in ("install.cmd", "uninstall.cmd", "firewall.cmd"):
            with open(os.path.join(WINDOWS, name), "rb") as script:
                data = script.read()
            data.decode("ascii")
            self.assertEqual(data.count(b"\n"), data.count(b"\r\n"), name)
            self.assertIn(b'"%HELPER%"', data)
            self.assertIn(b"%~dp0", data)

    def test_install_passes_its_arguments_to_the_helper(self) -> None:
        with open(os.path.join(WINDOWS, "install.cmd"), "rb") as script:
            data = script.read()
        self.assertIn(b'"%PYEXE%" %PYARGS% "%HELPER%" install %*', data)
        self.assertIn(b"py -3", data)
        self.assertIn(b"python -c", data)


    @staticmethod
    def script(name: str) -> str:
        with open(os.path.join(WINDOWS, name), "rb") as script:
            return script.read().decode("ascii")

    def test_firewall_cmd_asks_for_uac_once_and_keeps_the_action(self) -> None:
        text = self.script("firewall.cmd")
        run_helper = text.index('"%PYEXE%" "%HELPER%" firewall %MODE%\r\n')
        guard = text.index("if defined ELEVATED goto still_not_admin\r\n")
        elevate = text.index(
            'powershell -NoProfile -Command "Start-Process -FilePath $env:MA300_FIREWALL_CMD '
            '-ArgumentList $env:MA300_FIREWALL_ARGS -Verb RunAs"\r\n'
        )
        self.assertLess(run_helper, guard)
        self.assertLess(guard, elevate)  # the elevated copy never elevates again
        self.assertEqual(text.count("Start-Process"), 1)
        # The elevated copy gets the same action (/remove survives) plus /elevated.
        self.assertIn('if /i "%~1"=="/remove" set "MODE=/remove"\r\n', text)
        self.assertIn('if /i "%~1"=="/elevated" set "ELEVATED=1"\r\n', text)
        self.assertIn('set "MA300_FIREWALL_ARGS=%MODE% /elevated"\r\n', text)
        self.assertLess(text.index('set "MA300_FIREWALL_ARGS=%MODE% /elevated"'), elevate)

    def test_firewall_cmd_reports_a_refused_uac_and_a_failed_elevation(self) -> None:
        text = self.script("firewall.cmd")
        self.assertIn('-Verb RunAs"\r\nif errorlevel 1 goto refused\r\n', text)
        refused = text[text.index(":refused\r\n"):]
        self.assertTrue(refused.startswith(
            ":refused\r\necho Administrator rights were not granted: the firewall rule was not changed.\r\n"
            'set "RC=1"\r\ngoto end\r\n'))
        still = text[text.index(":still_not_admin\r\n"):]
        self.assertIn("Sign in with an administrator account", still.split(":end")[0])
        self.assertIn('set "RC=1"\r\n', still.split(":end")[0])

    def test_one_pause_per_window(self) -> None:
        firewall = self.script("firewall.cmd")
        self.assertIn(':end\r\nif defined NOPAUSE exit /b %RC%\r\necho.\r\npause\r\n', firewall)
        self.assertEqual(firewall.count("pause\r\n"), 1)
        self.assertIn('call "%~dp0firewall.cmd" /nopause\r\n', self.script("install.cmd"))
        self.assertIn('call "%~dp0firewall.cmd" /remove /nopause\r\n', self.script("uninstall.cmd"))

    def test_install_cmd_turns_codes_5_and_6_into_the_firewall_result(self) -> None:
        text = self.script("install.cmd")
        self.assertIn(
            '"%PYEXE%" %PYARGS% "%HELPER%" install %*\r\nset "RC=%ERRORLEVEL%"\r\n', text)
        self.assertIn('if "%RC%"=="5" goto firewall\r\nif "%RC%"=="6" goto firewall\r\ngoto end\r\n', text)
        self.assertIn(
            ':firewall\r\nset "WAS=%RC%"\r\ncall "%~dp0firewall.cmd" /nopause\r\nset "RC=%ERRORLEVEL%"\r\n'
            'if "%WAS%"=="6" set "RC=1"\r\n\r\n:end\r\n', text)

    def test_uninstall_cmd_turns_code_5_into_the_firewall_result(self) -> None:
        self.assertIn(
            'if not "%RC%"=="5" goto end\r\ncall "%~dp0firewall.cmd" /remove /nopause\r\nset "RC=%ERRORLEVEL%"\r\n\r\n:end\r\n',
            self.script("uninstall.cmd"))

    def test_firewall_cmd_elevates_itself_through_uac(self) -> None:
        with open(os.path.join(WINDOWS, "firewall.cmd"), "rb") as script:
            data = script.read()
        self.assertIn(b'"%PYEXE%" "%HELPER%" firewall %MODE%', data)
        self.assertIn(b'if not "%RC%"=="5" goto end', data)
        self.assertIn(b"Start-Process -FilePath $env:MA300_FIREWALL_CMD", data)
        self.assertEqual(data.count(b"-Verb RunAs"), 1)
        self.assertIn(b'set "MA300_FIREWALL_CMD=%~f0"', data)

    def test_install_and_uninstall_hand_the_firewall_to_firewall_cmd(self) -> None:
        self.assertEqual((setup.NEED_ADMIN, setup.NEED_ADMIN_UNHEALTHY), (5, 6))


class TaskUserTest(unittest.TestCase):
    environ = {"USERDOMAIN": "RECEPTION", "USERNAME": "Администратор"}

    def test_console_user_wins_over_an_elevated_administrator(self) -> None:
        user, note = setup.choose_task_user(self.environ, "RECEPTION\\Ресепшен", None)
        self.assertEqual(user, "RECEPTION\\Ресепшен")
        self.assertIn("RECEPTION\\Администратор", note)

    def test_same_user_needs_no_note(self) -> None:
        self.assertEqual(setup.choose_task_user(self.environ, "reception\\администратор", None), ("RECEPTION\\Администратор", None))

    def test_explicit_user_wins(self) -> None:
        self.assertEqual(setup.choose_task_user(self.environ, "RECEPTION\\Ресепшен", "PC\\Касса"), ("PC\\Касса", None))

    def test_unknown_console_user_falls_back_with_a_hint(self) -> None:
        user, note = setup.choose_task_user(self.environ, None, None)
        self.assertEqual(user, "RECEPTION\\Администратор")
        self.assertIn("/user:", note)

    def test_console_user_is_none_outside_windows(self) -> None:
        if setup.sys.platform == "win32":
            self.skipTest("Windows")
        self.assertIsNone(setup.console_user())


class HelperFunctionsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.agent_dir = os.path.join(self.directory.name, "Агент MA300")
        os.makedirs(self.agent_dir)
        self.paths = setup.agent_paths(self.agent_dir)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_arguments(self) -> None:
        self.assertEqual(setup.parse_arguments(["install"])["firewall"], False)
        options = setup.parse_arguments(["install", "C:\\Python38\\python.exe", "/FIREWALL", "/user:PC\\Ресепшен"])
        self.assertEqual((options["command"], options["firewall"], options["user"]), ("install", True, "PC\\Ресепшен"))
        self.assertEqual(setup.parse_arguments(["uninstall"])["command"], "uninstall")
        self.assertEqual(setup.parse_arguments(["firewall"])["remove"], False)
        self.assertEqual(setup.parse_arguments(["firewall", "/remove"])["remove"], True)
        health = setup.parse_arguments(["health", "http://127.0.0.1:8765/healthz", "30"])
        self.assertEqual((health["url"], health["seconds"]), ("http://127.0.0.1:8765/healthz", 30.0))
        for wrong in ([], ["remove"], ["install", "/force"], ["install", "/remove"], ["uninstall", "/firewall"], ["health"]):
            with self.assertRaises(setup.SetupError):
                setup.parse_arguments(wrong)

    def test_env_file_is_created_only_when_missing(self) -> None:
        with open(self.paths["env_example"], "w") as example:
            example.write("MA300_HOST=192.168.1.201\n")

        self.assertTrue(setup.ensure_env_file(self.paths))
        with open(self.paths["env"], "w") as env:
            env.write("MA300_HOST=10.0.0.9\n")
        self.assertFalse(setup.ensure_env_file(self.paths))
        with open(self.paths["env"]) as env:
            self.assertEqual(env.read(), "MA300_HOST=10.0.0.9\n")

    def test_agent_settings_read_env_without_overriding_the_environment(self) -> None:
        with open(self.paths["env"], "w") as env:
            env.write("MA300_HOST=192.168.1.201\nAGENT_PORT=9876\nAGENT_HOST=0.0.0.0\n")

        settings = setup.agent_settings(self.paths, {"AGENT_PORT": "8766"})

        self.assertEqual(settings["ma300_host"], "192.168.1.201")
        self.assertEqual(settings["agent_port"], "8766")
        self.assertEqual(setup.health_url(settings["agent_host"], settings["agent_port"]), "http://127.0.0.1:8766/healthz")
        self.assertEqual(settings["log_file"], os.path.join(self.agent_dir, "logs", "ma300-agent.log"))

    def test_listening_pids_ignore_language_and_other_ports(self) -> None:
        netstat = "\r\n".join(
            [
                "Активные подключения",
                "  Имя    Локальный адрес        Внешний адрес          Состояние       PID",
                "  TCP    127.0.0.1:8765         0.0.0.0:0              ПРОСЛУШИВАНИЕ   4321",
                "  TCP    127.0.0.1:8765         127.0.0.1:50211        ESTABLISHED     4321",
                "  TCP    127.0.0.1:50211        127.0.0.1:8765         ESTABLISHED     900",
                "  TCP    0.0.0.0:18765          0.0.0.0:0              LISTENING       77",
                "  TCP    [::]:8765              [::]:0                 LISTENING       4321",
            ]
        )
        self.assertEqual(setup.listening_pids(netstat, "8765"), [4321])

    def test_firewall_rule_covers_venv_and_base_interpreters(self) -> None:
        os.makedirs(self.paths["venv"])
        with open(os.path.join(self.paths["venv"], "pyvenv.cfg"), "w") as cfg:
            cfg.write("home = C:\\Python38\nversion = 3.8.10\n")

        programs = setup.firewall_programs(self.paths)
        commands = setup.firewall_add_commands(programs, "192.168.1.201")

        self.assertEqual(
            programs,
            [self.paths["python"], self.paths["pythonw"], "C:\\Python38/python.exe".replace("/", os.sep), "C:\\Python38/pythonw.exe".replace("/", os.sep)],
        )
        for command in commands:
            self.assertEqual(command[:5], ["netsh", "advfirewall", "firewall", "add", "rule"])
            self.assertIn("name=" + setup.FIREWALL_RULE, command)
            self.assertIn("dir=in", command)
            self.assertIn("protocol=UDP", command)
            self.assertIn("remoteip=192.168.1.201", command)
        self.assertEqual(setup.firewall_delete_command()[-1], "name=" + setup.FIREWALL_RULE)

    def test_firewall_hint_names_the_exact_steps(self) -> None:
        hint = setup.elevated_firewall_hint(AGENT_DIR)
        self.assertIn("windows\\firewall.cmd", hint)
        self.assertIn("Запуск от имени администратора", hint)
        self.assertIn('cd /d "%s"' % AGENT_DIR, hint)
        self.assertIn("windows\\install.cmd /firewall", hint)
        self.assertIn("windows\\firewall.cmd /remove", setup.elevated_firewall_hint(AGENT_DIR, remove=True))

    def test_health_is_checked_with_the_venv_python(self) -> None:
        command = setup.health_command(self.paths, "http://127.0.0.1:8765/healthz", 30)
        self.assertEqual(command[0], self.paths["python"])
        self.assertEqual(command[1], os.path.join(WINDOWS, "ma300_setup.py"))
        self.assertEqual(command[2:], ["health", "http://127.0.0.1:8765/healthz", "30"])

    def test_helper_refuses_to_run_outside_windows(self) -> None:
        if setup.sys.platform == "win32":
            self.skipTest("Windows")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(setup.main(["install"]), 1)
        self.assertIn("Windows", output.getvalue())


class FakeRun:
    """Stands in for subprocess calls of the helper (schtasks, netsh, pip, health)."""

    def __init__(self, rule_exists: bool = False, healthy: bool = True) -> None:
        self.rule_exists = rule_exists
        self.healthy = healthy
        self.commands = []

    def __call__(self, command, check=True):
        command = list(command)
        self.commands.append(command)
        code = 0
        if command[:5] == ["netsh", "advfirewall", "firewall", "show", "rule"]:
            code = 0 if self.rule_exists else 1
        elif "health" in command[2:3]:
            code = 0 if self.healthy else 1
        return subprocess.CompletedProcess(command, code, stdout="")

    def netsh(self, verb: str):
        return [c for c in self.commands if c[:4] == ["netsh", "advfirewall", "firewall", verb]]


class FirewallFlowTest(unittest.TestCase):
    """Exit codes that install.cmd / uninstall.cmd / firewall.cmd act on."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.agent_dir = os.path.join(self.directory.name, "Агент MA300")
        self.paths = setup.agent_paths(self.agent_dir)
        os.makedirs(os.path.dirname(self.paths["python"]))
        for name in ("python", "pythonw"):
            open(self.paths[name], "w").close()
        with open(self.paths["env_example"], "w") as example:
            example.write("MA300_HOST=192.168.1.201\n")
        self.output = io.StringIO()
        patches = [
            mock.patch.object(setup, "console_user", return_value=None),
            mock.patch.object(setup, "stop_running_agent"),
            mock.patch.dict(os.environ, {"USERDOMAIN": "PC", "USERNAME": "Ресепшен"}),
            contextlib.redirect_stdout(self.output),
        ]
        for patch in patches:
            patch.__enter__()
            self.addCleanup(patch.__exit__, None, None, None)
        self.addCleanup(self.directory.cleanup)

    def call(self, function, *args, admin=False, **fake):
        fake_run = FakeRun(**fake)
        with mock.patch.object(setup, "run", fake_run), mock.patch.object(setup, "is_admin", return_value=admin):
            return function(*args), fake_run

    def test_install_with_firewall_without_rights_returns_5_and_adds_no_rule(self) -> None:
        code, fake = self.call(setup.install, self.paths, True)
        self.assertEqual(code, setup.NEED_ADMIN)
        self.assertEqual(fake.netsh("add"), [])
        self.assertIn("firewall.cmd", self.output.getvalue())

    def test_install_with_firewall_offers_it_even_when_health_failed(self) -> None:
        code, fake = self.call(setup.install, self.paths, True, healthy=False)
        self.assertEqual(code, setup.NEED_ADMIN_UNHEALTHY)
        self.assertIn("агент не ответил", self.output.getvalue())

    def test_install_with_firewall_as_admin_adds_the_rule(self) -> None:
        code, fake = self.call(setup.install, self.paths, True, admin=True)
        self.assertEqual(code, 0)
        self.assertEqual(len(fake.netsh("add")), 2)
        self.assertTrue(all("remoteip=192.168.1.201" in command for command in fake.netsh("add")))

    def test_install_without_firewall_never_asks_for_rights(self) -> None:
        self.assertEqual(self.call(setup.install, self.paths, False)[0], 0)
        self.assertEqual(self.call(setup.install, self.paths, False, healthy=False)[0], 1)

    def test_install_refuses_a_folder_that_cmd_cannot_elevate(self) -> None:
        for name in ("MA300 (копия)", "R&D", "100%", "a^b", "wow!"):
            paths = setup.agent_paths(os.path.join(self.directory.name, name))
            with self.assertRaises(setup.SetupError) as raised:
                self.call(setup.install, paths, False)
            self.assertIn("Переименуйте или перенесите папку", str(raised.exception))
        setup.check_agent_dir("C:\\Users\\Ресепшен\\Рабочий стол\\ma300 agent")  # spaces and Cyrillic are fine

    def test_uninstall_with_a_rule_and_without_rights_returns_5(self) -> None:
        code, fake = self.call(setup.uninstall, self.paths, rule_exists=True)
        self.assertEqual(code, setup.NEED_ADMIN)
        self.assertEqual(fake.netsh("delete"), [])

    def test_uninstall_removes_the_rule_as_admin_and_ignores_a_missing_one(self) -> None:
        code, fake = self.call(setup.uninstall, self.paths, admin=True, rule_exists=True)
        self.assertEqual((code, len(fake.netsh("delete"))), (0, 1))
        code, fake = self.call(setup.uninstall, self.paths, rule_exists=False)
        self.assertEqual((code, fake.netsh("delete")), (0, []))

    def test_firewall_command_without_rights_returns_5(self) -> None:
        self.assertEqual(self.call(setup.firewall, self.paths, False)[0], setup.NEED_ADMIN)
        self.assertEqual(self.call(setup.firewall, self.paths, True, rule_exists=True)[0], setup.NEED_ADMIN)

    def test_firewall_command_as_admin_adds_or_removes(self) -> None:
        setup.ensure_env_file(self.paths)
        code, fake = self.call(setup.firewall, self.paths, False, admin=True)
        self.assertEqual((code, len(fake.netsh("delete")), len(fake.netsh("add"))), (0, 1, 2))
        code, fake = self.call(setup.firewall, self.paths, True, admin=True, rule_exists=True)
        self.assertEqual((code, len(fake.netsh("delete")), fake.netsh("add")), (0, 1, []))
        self.assertEqual(self.call(setup.firewall, self.paths, True, rule_exists=False)[0], 0)

    def test_installer_reads_an_ansi_env_and_reports_an_unreadable_one(self) -> None:
        with open(self.paths["env"], "w", encoding="cp1251") as env:
            env.write("# ресепшен\nMA300_HOST=10.0.0.9\n")
        self.assertEqual(setup.agent_settings(self.paths, {})["ma300_host"], "10.0.0.9")
        self.assertIn("save it in Notepad as UTF-8", self.output.getvalue())
        os.chmod(self.paths["env"], 0)
        try:
            if os.access(self.paths["env"], os.R_OK):
                self.skipTest("running as a user who can read any file")
            with self.assertRaises(setup.SetupError) as raised:
                setup.agent_settings(self.paths, {})
            self.assertIn("Не удалось прочитать", str(raised.exception))
        finally:
            os.chmod(self.paths["env"], 0o600)


class HealthCheckTest(unittest.TestCase):
    def test_reads_the_agent_health_and_ignores_other_servers(self) -> None:
        status = DeviceStatus()
        status.connected()
        server = AgentHttpServer(("127.0.0.1", 0), EventHub(), status)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = str(server.server_address[1])
        url = setup.health_url("127.0.0.1", port)
        try:
            payload = setup.wait_for_health(url, 5, interval=0.1)
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["device"]["state"], "connected")
        finally:
            server.shutdown()
            server.server_close()
        self.assertIsNone(setup.fetch_health(url, timeout=0.5))
        self.assertTrue(setup.wait_until_stopped(url, 1, interval=0.1))

    def test_health_subcommand_runs_in_a_separate_python(self) -> None:
        # Stand-in for .venv\\Scripts\\python.exe: the interpreter running the tests.
        server = AgentHttpServer(("127.0.0.1", 0), EventHub(), DeviceStatus())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = setup.health_url("127.0.0.1", str(server.server_address[1]))
        paths = dict(setup.agent_paths(REPO), python=sys.executable)
        try:
            ok = subprocess.run(setup.health_command(paths, url, 5), stdout=subprocess.PIPE, universal_newlines=True)
        finally:
            server.shutdown()
            server.server_close()
        down = subprocess.run(setup.health_command(paths, url, 0), stdout=subprocess.PIPE, universal_newlines=True)

        self.assertEqual(ok.returncode, 0, ok.stdout)
        self.assertIn('"status": "ok"', ok.stdout)
        self.assertEqual(down.returncode, 1)


if __name__ == "__main__":
    unittest.main()
