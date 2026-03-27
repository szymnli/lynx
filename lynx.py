import os
import sys

from alerts.notifier import Notifier
from core.config import BASELINE_PATH, INTEGRITY_DIRS
from core.logger import Logger
from monitors.file_integrity import (
    build_baseline,
    cleanup,
    compare_baseline,
    handle_events,
    save_baseline,
    start_monitoring,
)
from monitors.processes import (
    build_suid_baseline,
    check_deleted_binaries,
    check_new_processes,
    check_suid_binaries,
    get_process_snapshot,
)


def main():
    """Main entry point for the Lynx system monitoring tool."""
    # Initialize logger and notifier
    logger = Logger()
    notifier = Notifier(logger)

    header = r"""
        __
       ╱╲ ╲
       ╲ ╲ ╲      __  __    ___    __  _
        ╲ ╲ ╲  __╱╲ ╲╱╲ ╲ ╱' _ `╲ ╱╲ ╲╱'╲
         ╲ ╲ ╲_╲ ╲ ╲ ╲_╲ ╲╱╲ ╲╱╲ ╲╲╱>  <╱
          ╲ ╲____╱╲╱`____ ╲ ╲_╲ ╲_╲╱╲_╱╲_╲
           ╲╱___╱  `╱___╱  ╲╱_╱╲╱_╱╲╱╱╲╱_╱
                      ╱╲___╱
                      ╲╱__╱
        """

    # Handle baseline build argument
    if len(sys.argv) == 2 and sys.argv[1] in ("--baseline", "-b"):
        # Make directories if not present
        try:
            os.mkdir("data")
            os.mkdir("logs")
        except OSError:
            pass
        print("Building baseline...")
        baseline = build_baseline()
        save_baseline(notifier, baseline)
        print("Baseline saved.")
        print("Exiting...")
        sys.exit(0)
    elif len(sys.argv) > 1:
        print(
            "Invalid argument. Use --baseline or -b to build a baseline or no arguments to start monitoring."
        )
        sys.exit(1)
    elif not os.path.exists(BASELINE_PATH):
        print("Baseline file not found. Use --baseline or -b to build a baseline.")
        sys.exit(1)

    print(header)

    print("Comparing baseline...")
    baseline = compare_baseline()
    print("Baseline comparison complete.")

    print("Initiating monitoring...")
    inotify, wd_to_path, watch_flags = start_monitoring()
    print("Taking process snapshot...")
    old_snapshot = get_process_snapshot()
    suid_baseline = build_suid_baseline(INTEGRITY_DIRS)

    while True:
        try:
            # Read events from inotify and process them
            handle_events(notifier, inotify, wd_to_path, watch_flags, baseline)

            new_snapshot = get_process_snapshot()
            check_new_processes(old_snapshot, new_snapshot, notifier)
            check_deleted_binaries(new_snapshot, notifier)
            check_suid_binaries(suid_baseline, INTEGRITY_DIRS, notifier)
            old_snapshot = new_snapshot
        except KeyboardInterrupt:
            # Clean up inotify watches on exit
            print("\nExiting...")
            cleanup(inotify, wd_to_path)
            break


if __name__ == "__main__":
    main()
