import datetime
import json

from core.config import LOG_FILE


class Log:
    def __init__(self, severity, type, path, details):
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        self.severity = severity  # LOW / MEDIUM / HIGH / CRITICAL
        self.type = type  # CREATE / DELETE / MODIFY / DELETE_SELF / ...
        self.path = path
        self.details = details

    def to_dict(self):
        """Convert the log entry to a dictionary."""
        return {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "type": self.type,
            "path": self.path,
            "details": self.details,
        }


class Logger:
    def __init__(self, log_file=LOG_FILE):
        self.log_file = log_file

    def log(self, severity, type, path, details):
        """Log an event to the log file."""
        entry = Log(severity, type, path, details)
        with open(self.log_file, "a") as f:
            json.dump(entry.to_dict(), f, indent=4)
            f.write("\n")
        return entry

    def log_baseline_checkpoint(self, baseline_path):
        """Log a baseline checkpoint event to the log file."""
        self.log(
            severity="LOW",
            type="BASELINE_CHECKPOINT",
            path=baseline_path,
            details="Created a baseline checkpoint",
        )

    def read_logs(self):
        """Read all logs from the log file."""
        try:
            with open(self.log_file, "r") as f:
                return [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            return []
