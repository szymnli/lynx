import sys

from monitors.file_integrity import (
    build_baseline,
    cleanup,
    compare_baseline,
    handle_events,
    save_baseline,
    start_monitoring,
)


def main():
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

    if len(sys.argv) == 2 and (sys.argv[1] == "--baseline" or sys.argv[1] == "-b"):
        print("Building baseline...")
        baseline = build_baseline()
        save_baseline(baseline)
        print("Baseline saved.")
        print("Exiting...")
        sys.exit(0)
    elif len(sys.argv) > 1:
        print(
            "Invalid argument. Use --baseline or -b to build a baseline or no arguments to start monitoring."
        )
        sys.exit(1)

    print(header)

    print("Comparing baseline...")
    baseline = compare_baseline()
    print("Baseline comparison complete.")

    print("Initiating monitoring...")
    inotify, wd_to_path, watch_flags = start_monitoring()

    while True:
        try:
            handle_events(inotify, wd_to_path, watch_flags, baseline)
        except KeyboardInterrupt:
            # Clean up inotify watches on exit
            print("\nExiting...")
            cleanup(inotify, wd_to_path)
            break


if __name__ == "__main__":
    main()
