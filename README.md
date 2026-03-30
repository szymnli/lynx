# Lynx
A daemon written in Python that monitors your Linux system in real time for signs of compromise or suspicious activity.

## Current progress
### File monitoring
Lynx uses `inotify` (`inotify_simple` python wrapper) to detect and monitor changes to files and directories in given locations. 
### Integrity
Lynx ensures integrity of the critical system files by saving the files' hashes to the `baseline.json` file (use `-b` flag to create a baseline). On startup Lynx compares current hashes with baseline to check for unwanted modifications.
### Logging
All events are automatically logged to the `lynx.log` file.
### Config
All crucial configuration variables are stored in the `config.yaml` file.
### Usage
Steps to start using Lynx
```
$ git clone https://github.com/szymnli/lynx.git
$ cd lynx
$ python -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ python lynx.py -b
$ python lynx.py
```

### Processes
| Event | Severity |
|---|---|
| File event on non-baseline path | LOW |
| File event on baseline pathHIGHFile content changed vs baseline hash | CRITICAL |
| New process, non-rootLOWNew process, UID 0 | HIGH |
| Process running deleted binary | CRITICAL |
| New SUID binary appeared | CRITICAL |
