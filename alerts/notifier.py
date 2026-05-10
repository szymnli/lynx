import os
import subprocess

from core.config import NOTIFY_SEND_PATH


class Notifier:
    def __init__(self, logger):
        self.logger = logger

    def notify(self, alert):
        self.logger.log_alert(alert)  # always log

        if alert.severity in ("HIGH", "CRITICAL"):
            print(alert.summary())  # console output for HIGH+

        if alert.severity == "CRITICAL":
            self._desktop_notify(alert)  # desktop for CRITICAL only

    def _desktop_notify(self, alert):
        uid = os.environ.get("SUDO_UID")
        if not uid:
            return

        env = os.environ.copy()
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"

        subprocess.run(
            [
                NOTIFY_SEND_PATH,
                f"Lynx: {alert.event_type}",
                alert.summary(),
                "--urgency=critical",
            ],
            env=env,
            user=int(uid),  # drop to the original user
            check=False,
        )
