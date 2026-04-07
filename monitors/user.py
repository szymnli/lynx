import fcntl
import os
import re
import subprocess
from datetime import datetime, timedelta

from alerts.alert import Alert
from core.config import FAILURE_THRESHOLD, FAILURE_WINDOW_SECONDS


def start_journal_stream():
    p = subprocess.Popen(
        ["journalctl", "_COMM=sudo", "--follow", "--output=short-iso", "--since=now"],
        stdout=subprocess.PIPE,
    )
    fcntl.fcntl(p.stdout, fcntl.F_SETFL, os.O_NONBLOCK)
    return p


def read_new_lines(stream) -> list:
    lines = []
    try:
        while True:
            line = stream.stdout.readline()
            if not line:
                break
            lines.append(line.decode("utf-8").strip())
    except BlockingIOError:
        pass
    return lines


def parse_sudo_failure(line) -> str | None:
    if "authentication failure" not in line:
        return None
    m = re.search(r"user=(\w+)$", line)
    return m.group(1) if m else None


def check_sudo_failures(new_lines, failure_tracker, notifier):
    now = datetime.now()
    window = timedelta(seconds=FAILURE_WINDOW_SECONDS)

    for line in new_lines:
        username = parse_sudo_failure(line)
        if not username:
            continue

        failure_tracker[username].append(now)
        # prune entries outside the windows
        failure_tracker[username] = [
            t for t in failure_tracker[username] if now - t <= window
        ]

        count = len(failure_tracker[username])
        if count >= FAILURE_THRESHOLD:
            alert = Alert(
                severity="HIGH",
                event_type="SUDO_BRUTEFORCE",
                location="/usr/bin/sudo",
                source="user_monitor",
                context={
                    "username": username,
                    "failures_in_window": count,
                    "window_seconds": FAILURE_WINDOW_SECONDS,
                },
            )
            notifier.notify(alert)
            # reset after alerting
            failure_tracker[username].clear()
