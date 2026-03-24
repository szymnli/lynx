import os
import sys

from core.config import BASELINE_PATH
from core.logger import Logger
from monitors.file_integrity import (
    build_baseline,
    cleanup,
    compare_baseline,
    handle_events,
    save_baseline,
    start_monitoring,
)


def main():
    """Main entry point for the Lynx system monitoring tool."""
    # Initialize logger
    logger = Logger()

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
    if len(sys.argv) == 2 and (sys.argv[1] == "--baseline" or sys.argv[1] == "-b"):
        print("Building baseline...")

        # Build baseline and save it
        baseline = build_baseline()
        save_baseline(logger, baseline)

        print("Baseline saved.")
        print("Exiting...")
        sys.exit(0)
    # Handle invalid arguments
    elif len(sys.argv) > 1:
        print(
            "Invalid argument. Use --baseline or -b to build a baseline or no arguments to start monitoring."
        )
        sys.exit(1)
    elif not os.path.exists(BASELINE_PATH):
        print("Baseline file not found. Use --baseline or -b to build a baseline.")
        sys.exit(1)

    print(header)

    # Compare baseline before monitoring
    print("Comparing baseline...")
    baseline = compare_baseline()
    print("Baseline comparison complete.")

    # Initiate monitoring
    print("Initiating monitoring...")
    inotify, wd_to_path, watch_flags = start_monitoring()

    while True:
        try:
            # Read events from inotify and process them
            handle_events(logger, inotify, wd_to_path, watch_flags, baseline)
        except KeyboardInterrupt:
            # Clean up inotify watches on exit
            print("\nExiting...")
            cleanup(inotify, wd_to_path)
            break


if __name__ == "__main__":
    main()
