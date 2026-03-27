import hashlib
import json
import os

from inotify_simple import INotify, flags

from alerts.alert import Alert
from core.config import ACTIVITY_DIRS, BASELINE_PATH, INTEGRITY_DIRS


def build_baseline(directories=INTEGRITY_DIRS):
    """Build a baseline of file hashes for the given directories."""
    baseline = {}
    for directory in directories:
        # Walk through the directory and build a baseline of file hashes
        for root, subdirs, files in os.walk(directory, topdown=True):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Compute the hash of the file and add it to the baseline
                    with open(file_path, "rb") as f:
                        baseline[file_path] = hashlib.sha256(f.read()).hexdigest()
                except (PermissionError, OSError) as e:
                    print(f"[SKIP] Cannot read {file_path}: {e}")
                    continue
    return baseline


def save_baseline(notifier, baseline, path=BASELINE_PATH):
    """Save the baseline of file hashes to disk."""
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)
    checkpoint = Alert(
        severity="LOW",
        event_type="BASELINE_CHECKPOINT",
        location=path,
        source="system",
        context={"file_count": len(baseline)},
    )
    notifier.notify(checkpoint)


def compare_baseline():
    """Compare the stored file hashes against the baseline and print any modifications."""
    with open(BASELINE_PATH, "r") as f:
        baseline = json.load(f)
    for file_path, stored_hash in baseline.items():
        try:
            with open(file_path, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() != stored_hash:
                    print(f"[WARNING] File {file_path} has been modified.")
        except (PermissionError, OSError) as e:
            print(f"[SKIP] Cannot read {file_path}: {e}")
            continue
    return baseline


def start_monitoring():
    """Start monitoring directories for file integrity using inotify."""
    # Initialize inotify and set up watches for monitoring directories
    inotify = INotify()
    # Define watch flags (CREATE, DELETE, MODIFY, DELETE_SELF)
    watch_flags = flags.CREATE | flags.DELETE | flags.MODIFY | flags.DELETE_SELF
    wd_to_path = {}
    # Initialize inotify watches for each directory
    for dir in ACTIVITY_DIRS:
        # Walk through the directory and add watches for each subdirectory
        for root, dirs, files in os.walk(dir, topdown=True):
            wd = inotify.add_watch(root, watch_flags)
            wd_to_path[wd] = root
    return inotify, wd_to_path, watch_flags


def handle_events(notifier, inotify, wd_to_path, watch_flags, baseline):
    """Handle events from inotify and compare them against the baseline."""
    # Read events from inotify and process them
    events = inotify.read(timeout=5000)
    for event in events:
        flag_names = [f.name for f in flags.from_mask(event.mask)]
        path = os.path.join(wd_to_path[event.wd], event.name)
        event_type = ", ".join(flag_names)

        # Set default severity and path
        severity = "LOW"
        # Check if the path is in the baseline and update severity if it is
        if path in baseline:
            severity = "HIGH"

        # If a baseline hash exists for the path, check if it has been modified
        if "MODIFY" in flag_names and path in baseline:
            try:
                with open(path, "rb") as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != baseline[path]:
                    severity = "CRITICAL"
            except (PermissionError, OSError):
                pass

        # Watch new directories automatically
        if "CREATE" in flag_names and event.mask & flags.ISDIR:
            wd = inotify.add_watch(path, watch_flags)
            wd_to_path[wd] = path
            print(f"[!] Watching new directory: '{path}'")

        context = {
            "filename": event.name,
            "inotify_flags": flag_names,
            "in_baseline": path in baseline,
        }

        alert = Alert(
            severity=severity,
            event_type=event_type,
            location=path,
            source="file_integrity",
            context=context,
        )
        notifier.notify(alert)


def cleanup(inotify, wd_to_path):
    """Clean up inotify watches when the program exits."""
    for wd in wd_to_path:
        inotify.rm_watch(wd)
