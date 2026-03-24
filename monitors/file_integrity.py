import hashlib
import json
import os

from inotify_simple import INotify, flags

from core.config import BASELINE_PATH, INTEGRITY_DIRS, MONITORING_DIRS


def build_baseline(directories=INTEGRITY_DIRS):
    baseline = {}
    for directory in directories:
        for root, subdirs, files in os.walk(directory, topdown=True):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "rb") as f:
                        baseline[file_path] = hashlib.sha256(f.read()).hexdigest()
                except (PermissionError, OSError) as e:
                    print(f"[SKIP] Cannot read {file_path}: {e}")
                    continue
    return baseline


def save_baseline(baseline, path=BASELINE_PATH):
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)


def compare_baseline():
    with open(BASELINE_PATH, "r") as f:
        baseline = json.load(f)
    for file_path, current_hash in baseline.items():
        try:
            with open(file_path, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() != current_hash:
                    print(f"[WARNING] File {file_path} has been modified.")
        except (PermissionError, OSError) as e:
            print(f"[SKIP] Cannot read {file_path}: {e}")
            continue
    return baseline


def start_monitoring():
    inotify = INotify()
    # Define watch flags (CREATE, DELETE, MODIFY, DELETE_SELF)
    watch_flags = flags.CREATE | flags.DELETE | flags.MODIFY | flags.DELETE_SELF
    wd_to_path = {}
    # Initialize inotify watches for each directory
    for dir in MONITORING_DIRS:
        # Walk through the directory and add watches for each subdirectory
        for root, dirs, files in os.walk(dir, topdown=True):
            wd = inotify.add_watch(root, watch_flags)
            wd_to_path[wd] = root
    return inotify, wd_to_path, watch_flags


def handle_events(inotify, wd_to_path, watch_flags, baseline):
    # Read events from inotify and process them
    events = inotify.read()
    for event in events:
        # Print event details
        flag_names = [f.name for f in flags.from_mask(event.mask)]
        print(
            f"  - {', '.join(flag_names)} on '{event.name}' | full path: {wd_to_path[event.wd]}/{event.name}"
        )

        if "MODIFY" in flag_names:
            full_path = os.path.join(wd_to_path[event.wd], event.name)
            if full_path in baseline:
                try:
                    with open(full_path, "rb") as f:
                        current_hash = hashlib.sha256(f.read()).hexdigest()
                    if current_hash != baseline[full_path]:
                        print(f"[ALERT] {full_path} has been modified!")
                except (PermissionError, OSError):
                    pass

        # Watch new directories automatically
        if "CREATE" in flag_names and event.mask & flags.ISDIR:
            path = os.path.join(wd_to_path[event.wd], event.name)
            wd = inotify.add_watch(path, watch_flags)
            wd_to_path[wd] = path
            print(f"[!] Watching new directory: '{path}'")


def cleanup(inotify, wd_to_path):
    for wd in wd_to_path:
        inotify.rm_watch(wd)
