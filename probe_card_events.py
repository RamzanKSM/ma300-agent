"""Show everything the MA300 reports when a card is presented; changes nothing on the terminal.

Stop the agent first: windows\\probe_cards.cmd does that and starts it again afterwards.
The report goes to the console and to logs/card-probe-<time>.txt.
"""

import os
import socket
import sys
import time
from struct import unpack

from app import APP_DIR, boolean_setting, integer_setting, load_env_file

ALL_EVENTS = 0xFFFF
ATTLOG_ONLY = 1
CMD_REG_EVENT = 500
SECONDS = 120
EVENT_NAMES = {
    1: "ATTLOG", 2: "FINGER", 4: "ENROLLUSER", 8: "ENROLLFINGER", 16: "BUTTON", 32: "UNLOCK",
    128: "VERIFY", 256: "FPFTR", 512: "ALARM", 4096: "HIDNUM",
}


def main() -> int:
    load_env_file()
    from zk import ZK

    host = os.environ.get("MA300_HOST", "").strip()
    if not host:
        print("MA300_HOST is not set in .env")
        return 1
    logs = os.path.join(APP_DIR, "logs")
    os.makedirs(logs, exist_ok=True)
    report_path = os.path.join(logs, time.strftime("card-probe-%Y%m%d-%H%M%S.txt"))
    with open(report_path, "w", encoding="utf-8") as report:
        def say(line: str) -> None:
            print(line, flush=True)
            report.write(line + "\n")
            report.flush()

        connection = ZK(
            host,
            port=integer_setting("MA300_PORT", 4370),
            timeout=integer_setting("MA300_TIMEOUT_SECONDS", 10),
            password=integer_setting("MA300_PASSWORD", 0),
            force_udp=boolean_setting("MA300_FORCE_UDP", True),
            ommit_ping=boolean_setting("MA300_OMIT_PING", True),
        ).connect()
        try:
            describe_terminal(connection, say)
            connection.cancel_capture()
            connection.verify_user()
            connection.enable_device()
            subscribe(connection, say)
            say(f"Listening for {SECONDS} s. Present a NEW card, wait 5 s, then a card already in the terminal.")
            listen(connection, say)
        finally:
            connection.disconnect()
        say(f"Done. Report: {report_path}")
    return 0


def describe_terminal(connection, say) -> None:
    for label, read in (
        ("firmware", connection.get_firmware_version),
        ("platform", connection.get_platform),
        ("device", connection.get_device_name),
    ):
        try:
            say(f"{label}: {read()}")
        except Exception as error:  # the device list is a hint, a refusal is not a failure.
            say(f"{label}: not available ({error})")
    users = connection.get_users()
    with_card = [user for user in users if user.card]
    say(f"users: {len(users)}, with a card number: {len(with_card)}")
    for user in with_card[:5]:
        say(f"  user_id={user.user_id} card={user.card}")


def subscribe(connection, say) -> None:
    try:
        connection.reg_event(ALL_EVENTS)
        say(f"subscribed to all events ({ALL_EVENTS:#x})")
    except Exception as error:  # some firmware refuses the full mask.
        say(f"all events refused ({error}), listening to ATTLOG only")
        connection.reg_event(ATTLOG_ONLY)


def listen(connection, say) -> None:
    sock = getattr(connection, "_ZK__sock")
    acknowledge = getattr(connection, "_ZK__ack_ok")
    sock.settimeout(1)
    deadline = time.monotonic() + SECONDS
    packets = 0
    while time.monotonic() < deadline:
        try:
            packet = sock.recv(2048)
        except socket.timeout:
            continue
        acknowledge()
        packets += 1
        if len(packet) < 8:
            say(f"{time.strftime('%H:%M:%S')} short packet {packet.hex()}")
            continue
        command, _checksum, session, reply = unpack("<4H", packet[:8])
        kind = EVENT_NAMES.get(session, "?") if command == CMD_REG_EVENT else "not an event"
        say(
            f"{time.strftime('%H:%M:%S')} command={command} field={session} ({kind}) reply={reply} "
            f"size={len(packet) - 8} data={packet[8:].hex()}"
        )
    say(f"packets received: {packets}")


if __name__ == "__main__":
    sys.exit(main())
