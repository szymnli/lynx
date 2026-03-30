import os
import stat

from alerts.alert import Alert


def get_process_snapshot() -> dict:
    """Take a snapshot of the current processes."""
    snapshot = {}
    for pid in os.listdir("/proc"):
        # Skip non-digit entries (e.g., "sys", "kthreadd", etc.)
        if not pid.isdigit():
            continue
        try:
            # Read the process status file to get process details
            with open(f"/proc/{pid}/status") as f:
                status = f.read()

            # Parse the status file to extract process information
            name, uid, ppid = None, None, None
            for line in status.split("\n"):
                if line.startswith("Name:"):
                    name = line.split()[1]
                elif line.startswith("Uid:"):
                    uid = int(line.split()[1])
                elif line.startswith("PPid:"):
                    ppid = int(line.split()[1])

            # Read the process command line to get the executable path
            with open(f"/proc/{pid}/cmdline") as f:
                cmdline = f.read().strip("\x00").split("\x00")

            exe = os.readlink(f"/proc/{pid}/exe")

            snapshot[pid] = {
                "name": name,
                "uid": uid,
                "ppid": ppid,
                "cmdline": cmdline,
                "exe": exe,
            }
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return snapshot


def check_new_processes(old_snapshot, new_snapshot, notifier):
    """Check for new processes that have not been seen before."""
    new_pids = set(new_snapshot) - set(old_snapshot)
    for pid in new_pids:
        proc = new_snapshot[pid]
        severity = "HIGH" if proc["uid"] == 0 else "LOW"
        alert = Alert(
            severity=severity,
            event_type="NEW_PROCESS",
            location=proc["exe"],
            source="process_monitor",
            context={
                "pid": pid,
                "name": proc["name"],
                "uid": proc["uid"],
                "ppid": proc["ppid"],
                "cmdline": proc["cmdline"],
            },
        )
        notifier.notify(alert)


def check_deleted_binaries(snapshot, notifier):
    """Check for deleted binaries in the snapshot and notify if found."""
    for pid, proc in snapshot.items():
        if proc["exe"].endswith(" (deleted)"):
            alert = Alert(
                severity="CRITICAL",
                event_type="DELETED_BINARY",
                location=proc["exe"],
                source="process_monitor",
                context={
                    "pid": pid,
                    "name": proc["name"],
                    "uid": proc["uid"],
                    "cmdline": proc["cmdline"],
                },
            )
            notifier.notify(alert)


def build_suid_baseline(directories) -> set:
    """Build a baseline of SUID binaries from the given directories."""
    suid_paths = set()
    for directory in directories:
        for root, dirs, files in os.walk(directory, topdown=True):
            for file in files:
                path = os.path.join(root, file)
                try:
                    if os.stat(path).st_mode & stat.S_ISUID:
                        suid_paths.add(path)
                except (PermissionError, OSError):
                    continue
    return suid_paths


def check_suid_binaries(suid_baseline, directories, notifier):
    """Check for new SUID binaries in the current snapshot and notify if found."""
    current_suid = build_suid_baseline(directories)
    new_suid = current_suid - suid_baseline
    for path in new_suid:
        alert = Alert(
            severity="CRITICAL",
            event_type="NEW_SUID_BINARY",
            location=path,
            source="process_monitor",
            context={"path": path},
        )
        notifier.notify(alert)
