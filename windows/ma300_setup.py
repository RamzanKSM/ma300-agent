"""Install or remove the MA300 agent autostart on Windows 7 and newer.

Called by install.cmd / uninstall.cmd next to this file. Runs on Python 3.8+
and uses the standard library only. The pure functions (paths, task XML,
netstat parsing, health check) are covered by tests on any OS.
"""

import codecs
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Dict, List, Mapping, Optional, Sequence, Tuple
from xml.sax.saxutils import escape

TASK_NAME = "MA300 Agent"
FIREWALL_RULE = "MA300 Agent (UDP from MA300)"
MIN_PYTHON = (3, 8)
NEED_ADMIN = 5  # exit code: firewall.cmd re-runs itself elevated (UAC)
NEED_ADMIN_UNHEALTHY = 6  # install: same as NEED_ADMIN, but /healthz did not answer
# cmd.exe drops the quotes around a path with these characters when Windows
# elevates a .cmd (runas -> cmd /C "%1"), and %, ! are expanded by cmd itself.
UNSAFE_PATH_CHARS = "()&^%!"
HEALTH_WAIT_SECONDS = 30
STOP_WAIT_SECONDS = 10
AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def agent_paths(agent_dir: str, path=os.path) -> Dict[str, str]:
    """Agent files; tests pass ntpath to build Windows paths on any OS."""
    venv = path.join(agent_dir, ".venv")
    return {
        "agent_dir": agent_dir,
        "venv": venv,
        "python": path.join(venv, "Scripts", "python.exe"),
        "pythonw": path.join(venv, "Scripts", "pythonw.exe"),
        "app": path.join(agent_dir, "app.py"),
        "env": path.join(agent_dir, ".env"),
        "env_example": path.join(agent_dir, ".env.example"),
        "requirements": path.join(agent_dir, "requirements.txt"),
    }


def task_xml(user_id: str, pythonw: str, app_path: str, working_dir: str) -> str:
    """Task Scheduler 1.2 (Windows 7) definition: start at logon of user_id, forever."""
    user = escape(user_id)
    return "\r\n".join(
        [
            '<?xml version="1.0" encoding="UTF-16"?>',
            '<Task version="1.2" xmlns="%s">' % TASK_NAMESPACE,
            "  <RegistrationInfo>",
            "    <Description>MA300 agent: live MA300 events for the reception frontend.</Description>",
            "  </RegistrationInfo>",
            "  <Triggers>",
            "    <LogonTrigger>",
            "      <Enabled>true</Enabled>",
            "      <UserId>%s</UserId>" % user,
            "    </LogonTrigger>",
            "  </Triggers>",
            "  <Principals>",
            '    <Principal id="Author">',
            "      <UserId>%s</UserId>" % user,
            "      <LogonType>InteractiveToken</LogonType>",
            "      <RunLevel>LeastPrivilege</RunLevel>",
            "    </Principal>",
            "  </Principals>",
            "  <Settings>",
            "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
            "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
            "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
            "    <AllowHardTerminate>true</AllowHardTerminate>",
            "    <StartWhenAvailable>true</StartWhenAvailable>",
            "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>",
            "    <IdleSettings>",
            "      <StopOnIdleEnd>false</StopOnIdleEnd>",
            "      <RestartOnIdle>false</RestartOnIdle>",
            "    </IdleSettings>",
            "    <AllowStartOnDemand>true</AllowStartOnDemand>",
            "    <Enabled>true</Enabled>",
            "    <Hidden>false</Hidden>",
            "    <RunOnlyIfIdle>false</RunOnlyIfIdle>",
            "    <WakeToRun>false</WakeToRun>",
            "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
            "    <Priority>7</Priority>",
            "    <RestartOnFailure>",
            "      <Interval>PT1M</Interval>",
            "      <Count>999</Count>",
            "    </RestartOnFailure>",
            "  </Settings>",
            '  <Actions Context="Author">',
            "    <Exec>",
            "      <Command>%s</Command>" % escape(pythonw),
            '      <Arguments>"%s"</Arguments>' % escape(app_path),
            "      <WorkingDirectory>%s</WorkingDirectory>" % escape(working_dir),
            "    </Exec>",
            "  </Actions>",
            "</Task>",
            "",
        ]
    )


def task_xml_bytes(xml: str) -> bytes:
    """schtasks /XML expects UTF-16 with a byte order mark."""
    return codecs.BOM_UTF16_LE + xml.encode("utf-16-le")


def current_user_id(environ: Mapping[str, str]) -> str:
    user = environ.get("USERNAME", "")
    domain = environ.get("USERDOMAIN", "")
    if not user:
        raise SetupError("Не удалось определить пользователя Windows (переменная USERNAME пуста).")
    return "%s\\%s" % (domain, user) if domain else user


def console_user() -> Optional[str]:
    """DOMAIN\\user signed in at the Windows console, even when we run elevated as another admin."""
    try:
        import ctypes
        from ctypes import wintypes

        wtsapi = ctypes.windll.wtsapi32
        get_session = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId
        get_session.restype = wintypes.DWORD
        session = get_session()
        if session == 0xFFFFFFFF:
            return None

        def query(info_class: int) -> str:
            buffer = wintypes.LPWSTR()
            size = wintypes.DWORD()
            if not wtsapi.WTSQuerySessionInformationW(None, session, info_class, ctypes.byref(buffer), ctypes.byref(size)):
                return ""
            try:
                return buffer.value or ""
            finally:
                wtsapi.WTSFreeMemory(buffer)

        user, domain = query(5), query(7)  # WTSUserName, WTSDomainName
    except Exception:
        return None
    if not user:
        return None
    return "%s\\%s" % (domain, user) if domain else user


def choose_task_user(environ: Mapping[str, str], console: Optional[str], explicit: Optional[str]) -> Tuple[str, Optional[str]]:
    """The account whose logon starts the agent, and a note to print about the choice.

    When UAC asked for another administrator account, USERNAME is that
    administrator; the task must still follow the reception user at the console.
    """
    if explicit:
        return explicit, None
    current = current_user_id(environ)
    if console is None:
        return current, (
            "Не удалось определить пользователя, вошедшего в Windows; задание будет на %s. "
            "Если это не пользователь ресепшена, повторите: install.cmd /user:ИМЯ_ПК\\пользователь" % current
        )
    if console.lower() != current.lower():
        return console, (
            "Установка запущена от имени %s, а в Windows вошёл %s: автозапуск будет при входе %s." % (current, console, console)
        )
    return current, None


def check_agent_dir(agent_dir: str) -> None:
    unsafe = sorted(set(char for char in agent_dir if char in UNSAFE_PATH_CHARS))
    if unsafe:
        raise SetupError(
            "В пути к папке агента есть символы %s: %s\n"
            "С ними Windows не может надёжно запустить скрипты от имени администратора. "
            "Переименуйте или перенесите папку (пробелы и русские буквы можно) и запустите установку снова."
            % (" ".join(unsafe), agent_dir)
        )


def ensure_env_file(paths: Mapping[str, str]) -> bool:
    """Create .env from .env.example only when .env is missing."""
    if os.path.exists(paths["env"]):
        return False
    with open(paths["env_example"], "rb") as source, open(paths["env"], "wb") as target:
        target.write(source.read())
    return True


def agent_settings(paths: Mapping[str, str], environ: Mapping[str, str]) -> Dict[str, str]:
    """The values app.py would see at start: real environment first, then .env."""
    sys.path.insert(0, paths["agent_dir"])
    try:
        from app import DEFAULT_LOG_FILE, load_env_file
    finally:
        sys.path.pop(0)
    values = dict(environ)
    env_file = values.get("AGENT_ENV_FILE", "").strip() or paths["env"]
    if os.path.isfile(env_file):
        try:
            for problem in load_env_file(env_file, values):
                print("Внимание: %s" % problem)
        except OSError as error:
            raise SetupError("Не удалось прочитать %s: %s" % (env_file, error))
    log_file = values.get("LOG_FILE", "").strip() or DEFAULT_LOG_FILE
    return {
        "agent_host": values.get("AGENT_HOST", "").strip() or "127.0.0.1",
        "agent_port": values.get("AGENT_PORT", "").strip() or "8765",
        "ma300_host": values.get("MA300_HOST", "").strip(),
        "log_file": os.path.join(paths["agent_dir"], log_file),
    }


def health_url(host: str, port: str) -> str:
    if host in ("", "0.0.0.0", "::", "[::]"):
        host = "127.0.0.1"
    return "http://%s:%s/healthz" % (host, port)


def fetch_health(url: str, timeout: float = 2.0) -> Optional[dict]:
    """The /healthz JSON of a running MA300 agent, or None."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as response:
            if not response.headers.get("Server", "").startswith("MA300Agent/"):
                return None
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return payload if isinstance(payload, dict) and payload.get("status") == "ok" else None


def wait_for_health(url: str, seconds: float, interval: float = 1.0) -> Optional[dict]:
    deadline = time.monotonic() + seconds
    while True:
        payload = fetch_health(url)
        if payload is not None or time.monotonic() >= deadline:
            return payload
        time.sleep(interval)


def wait_until_stopped(url: str, seconds: float, interval: float = 0.5) -> bool:
    deadline = time.monotonic() + seconds
    while fetch_health(url) is not None:
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)
    return True


def listening_pids(netstat_output: str, port: str) -> List[int]:
    """PIDs listening on TCP port, from `netstat -ano` in any Windows language."""
    pids = []
    for line in netstat_output.splitlines():
        parts = line.split()
        if len(parts) != 5 or parts[0].upper() != "TCP":
            continue
        local, foreign, pid = parts[1], parts[2], parts[4]
        if local.rsplit(":", 1)[-1] != str(port) or foreign not in ("0.0.0.0:0", "[::]:0"):
            continue
        if pid.isdigit() and int(pid) not in pids and int(pid) != 0:
            pids.append(int(pid))
    return pids


def base_interpreters(venv_dir: str) -> List[str]:
    """python.exe/pythonw.exe that a venv launcher really runs (pyvenv.cfg `home`)."""
    config = os.path.join(venv_dir, "pyvenv.cfg")
    if not os.path.isfile(config):
        return []
    with open(config, encoding="utf-8", errors="replace") as cfg:
        for line in cfg:
            key, _, value = line.partition("=")
            if key.strip().lower() == "home" and value.strip():
                home = value.strip()
                return [os.path.join(home, "python.exe"), os.path.join(home, "pythonw.exe")]
    return []


def firewall_programs(paths: Mapping[str, str]) -> List[str]:
    programs = [paths["python"], paths["pythonw"]]
    for program in base_interpreters(paths["venv"]):
        if program.lower() not in [known.lower() for known in programs]:
            programs.append(program)
    return programs


def firewall_add_commands(programs: Sequence[str], remote_ip: str) -> List[List[str]]:
    return [
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=%s" % FIREWALL_RULE,
            "dir=in",
            "action=allow",
            "protocol=UDP",
            "remoteip=%s" % remote_ip,
            "program=%s" % program,
            "profile=any",
            "enable=yes",
        ]
        for program in programs
    ]


def firewall_delete_command() -> List[str]:
    return ["netsh", "advfirewall", "firewall", "delete", "rule", "name=%s" % FIREWALL_RULE]


def firewall_show_command() -> List[str]:
    return ["netsh", "advfirewall", "firewall", "show", "rule", "name=%s" % FIREWALL_RULE]


USAGE = (
    "Использование: ma300_setup.py install [путь\\к\\python.exe] [/firewall] [/user:ПК\\пользователь] | "
    "uninstall | firewall [/remove] | health URL [секунд]"
)


def parse_arguments(argv: Sequence[str]) -> Dict[str, object]:
    if not argv or argv[0] not in ("install", "uninstall", "firewall", "health"):
        raise SetupError(USAGE)
    options = {"command": argv[0], "firewall": False, "remove": False, "user": None, "url": None, "seconds": 0.0}
    if argv[0] == "health":
        if len(argv) not in (2, 3):
            raise SetupError(USAGE)
        options["url"] = argv[1]
        options["seconds"] = float(argv[2]) if len(argv) == 3 else 0.0
        return options
    for argument in argv[1:]:
        lowered = argument.lower()
        if argv[0] == "install" and lowered in ("/firewall", "--firewall"):
            options["firewall"] = True
        elif argv[0] == "install" and lowered.startswith("/user:") and len(argument) > len("/user:"):
            options["user"] = argument[len("/user:"):]
        elif argv[0] == "firewall" and lowered in ("/remove", "--remove"):
            options["remove"] = True
        elif argument.startswith("/") or argument.startswith("-"):
            raise SetupError("Неизвестный параметр %s.\n%s" % (argument, USAGE))
        # Any other argument is the Python path that install.cmd already used to start us.
    return options


def elevated_firewall_hint(agent_dir: str, remove: bool = False) -> str:
    command = "windows\\firewall.cmd /remove" if remove else "windows\\install.cmd /firewall"
    return (
        "Дважды щёлкните windows\\firewall.cmd%s - Windows сама спросит права администратора.\n"
        "Или: Пуск -> в поиске наберите cmd -> правой кнопкой по cmd.exe -> 'Запуск от имени администратора' -> \n"
        '    cd /d "%s"\n'
        "    %s" % (" /remove" if remove else "", agent_dir, command)
    )


class SetupError(Exception):
    pass


def run(command: Sequence[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="oem" if sys.platform == "win32" else "utf-8",
        errors="replace",
    )
    if check and result.returncode != 0:
        raise SetupError("Команда завершилась с кодом %s: %s\n%s" % (result.returncode, " ".join(command), result.stdout.strip()))
    return result


def is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def stop_running_agent(url: str, port: str) -> None:
    """End the scheduled task and any agent still answering on the agent port."""
    run(["schtasks", "/End", "/TN", TASK_NAME], check=False)
    if wait_until_stopped(url, 3):
        return
    netstat = run(["netstat", "-ano", "-p", "TCP"], check=False).stdout
    for pid in listening_pids(netstat, port):
        print("Останавливаю процесс агента PID %s" % pid)
        run(["taskkill", "/PID", str(pid), "/T", "/F"], check=False)
    if not wait_until_stopped(url, STOP_WAIT_SECONDS):
        raise SetupError("Агент на %s не остановился. Закройте его окно вручную и повторите." % url)


def apply_firewall_rule(paths: Mapping[str, str], settings: Mapping[str, str]) -> None:
    if not settings["ma300_host"]:
        raise SetupError("MA300_HOST не задан в .env - не из чего строить правило брандмауэра.")
    run(firewall_delete_command(), check=False)
    for command in firewall_add_commands(firewall_programs(paths), settings["ma300_host"]):
        run(command)
    print("Брандмауэр: разрешены входящие UDP с %s для Python из .venv (правило '%s')." % (settings["ma300_host"], FIREWALL_RULE))


def firewall(paths: Dict[str, str], remove: bool) -> int:
    """Called by firewall.cmd; NEED_ADMIN makes it re-run itself through UAC."""
    if remove:
        if run(firewall_show_command(), check=False).returncode != 0:
            print("Правила брандмауэра '%s' нет - удалять нечего." % FIREWALL_RULE)
            return 0
        if not is_admin():
            print("Для удаления правила нужны права администратора.\n" + elevated_firewall_hint(paths["agent_dir"], remove=True))
            return NEED_ADMIN
        run(firewall_delete_command())
        print("Правило брандмауэра '%s' удалено." % FIREWALL_RULE)
        return 0
    check_agent_dir(paths["agent_dir"])
    if not os.path.isfile(paths["python"]):
        raise SetupError("Агент ещё не установлен: сначала запустите windows\\install.cmd.")
    if not is_admin():
        print("Для правила брандмауэра нужны права администратора.\n" + elevated_firewall_hint(paths["agent_dir"]))
        return NEED_ADMIN
    apply_firewall_rule(paths, agent_settings(paths, os.environ))
    return 0


def health_command(paths: Mapping[str, str], url: str, seconds: float) -> List[str]:
    """Check /healthz with the agent's own .venv Python (contract: means of the .venv)."""
    return [paths["python"], os.path.abspath(__file__), "health", url, "%g" % seconds]


def health(url: str, seconds: float) -> int:
    payload = wait_for_health(url, seconds)
    if payload is None:
        print("%s не ответил за %g с." % (url, seconds))
        return 1
    print("%s -> %s" % (url, json.dumps(payload, ensure_ascii=False)))
    return 0


def install(paths: Dict[str, str], firewall: bool, user: Optional[str] = None) -> int:
    print("Папка агента: %s" % paths["agent_dir"])
    check_agent_dir(paths["agent_dir"])
    print("Python для установки: %s (%s)" % (sys.executable, sys.version.split()[0]))
    if not os.path.isfile(paths["python"]) or not os.path.isfile(paths["pythonw"]):
        print("Создаю .venv ...")
        run([sys.executable, "-m", "venv", paths["venv"]])
    print("Ставлю зависимости из requirements.txt (нужен интернет) ...")
    try:
        run([paths["python"], "-m", "pip", "install", "--disable-pip-version-check", "-r", paths["requirements"]])
    except SetupError as error:
        raise SetupError("%s\nПроверьте доступ в интернет и запустите установку ещё раз." % error)
    if ensure_env_file(paths):
        print("Создан .env из .env.example - проверьте MA300_HOST в %s" % paths["env"])
    else:
        print(".env уже есть - не трогаю.")
    settings = agent_settings(paths, os.environ)
    url = health_url(settings["agent_host"], settings["agent_port"])

    firewall_pending = False
    if firewall:
        if is_admin():
            apply_firewall_rule(paths, settings)
        else:
            firewall_pending = True
            print("Брандмауэр: правило пока НЕ создано - нужны права администратора (попрошу в конце).")

    task_user, note = choose_task_user(os.environ, console_user(), user)
    if note:
        print(note)
    xml_path = os.path.join(tempfile.gettempdir(), "ma300-agent-task.xml")
    with open(xml_path, "wb") as xml_file:
        xml_file.write(task_xml_bytes(task_xml(task_user, paths["pythonw"], paths["app"], paths["agent_dir"])))
    try:
        result = run(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", xml_path, "/F"], check=False)
    finally:
        os.remove(xml_path)
    if result.returncode != 0:
        raise SetupError(
            "Планировщик заданий не принял задание (код %s):\n%s\n"
            "Если это отказ в доступе - запустите install.cmd от имени администратора."
            % (result.returncode, result.stdout.strip())
        )
    print("Автозапуск при входе в Windows зарегистрирован: задание '%s'." % TASK_NAME)

    stop_running_agent(url, settings["agent_port"])
    run(["schtasks", "/Run", "/TN", TASK_NAME])
    print("Проверяю %s средствами Python из .venv ..." % url)
    checked = run(health_command(paths, url, HEALTH_WAIT_SECONDS), check=False)
    print(checked.stdout.strip())
    print("Лог агента: %s" % settings["log_file"])
    healthy = checked.returncode == 0
    if healthy:
        print("Агент запущен. Откройте %s в браузере для проверки." % url)
    else:
        print("ВНИМАНИЕ: агент не ответил. Посмотрите лог.")
    if firewall_pending:
        # The firewall rule does not depend on /healthz: offer it in both cases.
        print("Правило брандмауэра ещё не создано. Сейчас откроется запрос прав администратора.\n"
              + elevated_firewall_hint(paths["agent_dir"]))
        return NEED_ADMIN if healthy else NEED_ADMIN_UNHEALTHY
    return 0 if healthy else 1


def uninstall(paths: Dict[str, str]) -> int:
    settings = agent_settings(paths, os.environ)
    url = health_url(settings["agent_host"], settings["agent_port"])
    stop_running_agent(url, settings["agent_port"])
    deleted = run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"], check=False)
    print("Задание '%s' %s." % (TASK_NAME, "удалено" if deleted.returncode == 0 else "не найдено"))
    print(".env, logs\\ и .venv оставлены в %s - удалите папку вручную, если агент больше не нужен." % paths["agent_dir"])
    if run(firewall_show_command(), check=False).returncode == 0:
        if is_admin():
            run(firewall_delete_command())
            print("Правило брандмауэра '%s' удалено." % FIREWALL_RULE)
        else:
            print("Правило брандмауэра '%s' осталось - сейчас откроется запрос прав администратора.\n%s"
                  % (FIREWALL_RULE, elevated_firewall_hint(paths["agent_dir"], remove=True)))
            return NEED_ADMIN
    return 0


def main(argv: Sequence[str]) -> int:
    try:
        options = parse_arguments(argv)
        if sys.version_info < MIN_PYTHON:
            raise SetupError("Нужен Python 3.8 или новее, а запущен %s." % sys.version.split()[0])
        if options["command"] == "health":
            return health(options["url"], options["seconds"])
        if sys.platform != "win32":
            raise SetupError("Этот помощник предназначен для Windows.")
        paths = agent_paths(AGENT_DIR)
        if options["command"] == "install":
            return install(paths, options["firewall"], options["user"])
        if options["command"] == "firewall":
            return firewall(paths, options["remove"])
        return uninstall(paths)
    except SetupError as error:
        print("ОШИБКА: %s" % error)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
