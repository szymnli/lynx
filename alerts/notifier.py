class Notifier:
    def __init__(self, logger):
        self.logger = logger

    def notify(self, alert):
        self.logger.log_alert(alert)  # always log

        if alert.severity in ("HIGH", "CRITICAL"):
            print(alert.summary())  # console output for HIGH+

        if alert.severity == "CRITICAL":
            self._desktop_notify(alert)  # desktop for CRITICAL only

        # LOW and MEDIUM are silently logged — this is intentional

    def _desktop_notify(self, alert):
        # TODO: implement with notify2 or plyer in week 4
        # title = f"Lynx Alert: {alert.event_type}"
        # body = alert.summary()
        pass
