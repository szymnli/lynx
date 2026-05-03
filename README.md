# Lynx

A Python daemon that watches your Linux system for signs of compromise. File changes, suspicious processes, sudo abuse — logged and alerted on in real time.

Still in progress. Here's where it stands.

## What works

**File integrity** — SHA-256 baselines for critical paths (`/etc/passwd`, `/etc/sudoers`, `/bin/`, etc.), with inotify watching for changes live. Modifications to baselined files come out as CRITICAL. Run `-b` once to build the baseline before starting.

**Process monitoring** — `/proc` polling to catch new processes, deleted-binary detection (a process whose executable has been removed from disk is a classic malware indicator), and SUID binary diffing against a startup baseline.

**User monitoring** — real-time `journalctl` streaming to catch sudo failures, with a configurable window and threshold for brute-force detection. Sudoers file changes are caught via inotify on `/etc/`.

**Alert routing** — JSON log for everything, console output for HIGH+, desktop notifications for CRITICAL (stubbed, not yet wired up).

## What's not done yet

Desktop notifications need `notify-send` plumbed through correctly — the tricky part is getting a root process to talk to the user's D-Bus session. That's next.

After that: a systemd service file, a `--logs` CLI flag for reading recent alerts without grepping raw JSON, and formalizing the deleted-binary whitelist in `config.yaml` (some legitimate tools like LSP servers show up as deleted-but-running during normal use).

Rootkit detection is planned but not started — hidden process checks, kernel module inspection, that kind of thing.

## Usage

```bash
git clone https://github.com/szymnli/lynx.git
cd lynx
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo venv/bin/python lynx.py -b
sudo venv/bin/python lynx.py
```

Needs root to read other users' `/proc` entries and stream from journald.
