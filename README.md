# IntegrityEye
 
[![Python](https://img.shields.io/badge/Python-3.x-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange)](https://linux.org)
[![Framework](https://img.shields.io/badge/Web-Flask-lightgrey)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green)]()
[![Release](https://img.shields.io/badge/Release-v1.0.0-brightgreen)]()
[![Status](https://img.shields.io/badge/Status-Production-brightgreen)]()
 
> **Real-time file integrity and metadata monitoring for Linux — with a full web dashboard.**
 
IntegrityEye is a host-based file integrity monitoring (FIM) system built for Linux. It uses kernel-level `inotify` events to detect file changes the moment they happen — no polling, no delays. Every monitored path gets a cryptographic baseline snapshot, and any deviation in content, permissions, ownership, or metadata fires a classified alert.
 
Runs persistently as a **systemd service** and exposes a dark-themed **Flask web dashboard** for live monitoring, alert triage, forensic analysis, and configuration — all from the browser.
 
---
 
## Key Features
 
- **Real-time detection** via `pyinotify` (kernel `inotify` — no polling)
- **Detects:** file creation, modification, deletion, permission changes, ownership changes, SUID changes, moves/renames
- **SHA-256 hashing** — content integrity verified on every change
- **Immutable baseline** — original snapshot preserved; every change appended to history, never overwritten
- **Per-file change history** — full attribute snapshot logged at every event
- **Severity classification** — Critical / High / Medium / Low
- **Web dashboard** — dark-themed Flask UI with:
  - Dashboard with live alert counts and Chart.js time-series + distribution charts
  - Alerts and Logs views with search and pagination
  - **File Analysis** — searchable paginated file browser with baseline diff and history timeline
  - **Statistics** — most-changed files, hourly heatmap, event type breakdown, directory breakdown, baseline drift %
  - Settings — add/remove monitored paths, exclusions, toggles, baseline rescan
  - Account — change username/password, session management
- **Systemd integration** — auto-start on boot, `journalctl` logging
- **Debounced events** — prevents alert storms on rapidly-written files
- **SQLite storage** — zero external dependencies for persistence
 
---

### Classification
- Four severity levels: **Critical** (SUID / ownership changes), **High** (file deletion, content modification), **Medium** (new files, size changes), **Low** (timestamp changes, renames)
- Event types: `modified`, `permission_change`, `ownership_change`, `suid_change`, `size_change`, `timestamp_change`, `created`, `deleted`, `moved`

---
 
## Tech Stack
 
| Component | Technology |
|---|---|
| Language | Python 3 |
| File monitoring | pyinotify |
| Hashing | SHA-256 |
| Web UI | Flask + Jinja2 |
| Storage | SQLite |
| Styling | Custom CSS (dark theme) |
| Charts | Chart.js |
| OS | Linux (tested on Kali Linux) |
 
---
 
## Installation
 
```bash
# Clone the repo
git clone https://github.com/HusnainZargar/IntegrityEye.git
cd IntegrityEye
 
# Install dependencies
pip install flask pyinotify werkzeug
```
 
---
 
## Running
 
### First run — installs and starts the systemd service
 
```bash
# Without a path (add paths later from the web UI Settings page)
sudo python3 main.py
 
# With an initial path to monitor
sudo python3 main.py /etc/ssh
```
 
> ⚠️ Must be run with `sudo` — required to install the systemd unit file.
 
On first run the script will:
1. Write `/etc/systemd/system/fim.service`
2. Run `systemctl daemon-reload && systemctl enable fim && systemctl start fim`
3. Print dashboard URL and default credentials, then exit
 
The service takes over from there.
 
### Accessing the dashboard
 
```
http://localhost:5000
```
 
Default credentials: `admin` / `admin` — **change these immediately from the Account page.**
 
### Managing the service
 
```bash
systemctl status fim        # check status
systemctl stop fim          # stop
systemctl restart fim       # restart
journalctl -u fim -f        # live logs
```
 
---
 
## Project Structure
 
```
.
├── main.py                  # Entry point — systemd setup + service runner
├── components/
│   ├── monitor.py           # pyinotify event handler, baseline management
│   └── utils.py             # SQLite helpers, DB schema, file history
├── web/
│   ├── app.py               # Flask app factory
│   ├── auth.py              # Authentication (PBKDF2 hashing)
│   ├── routes.py            # All Flask routes
│   └── templates/
│       ├── base.html
│       ├── dashboard.html
│       ├── alerts.html
│       ├── logs.html
│       ├── change_password.html
│       ├── file_analysis.html
│       ├── statistics.html
│       ├── settings.html
│       ├── account.html
│       └── login.html

```
 
---

## Scope
 
### What it does
- Linux-only, single-host monitoring
- Systemd service with auto-start on boot
- Immutable baseline — original attributes locked at capture
- Per-file change history — append-only forensic log
- Alert deduplication across restarts
- Full web dashboard with live metrics
- Paginated logs, alerts, and file browser with search
- File Analysis — baseline diff and change timeline per file
- Statistics — drift percentage, most-changed files, hourly heatmap
- Secure PBKDF2 password hashing
- Event debouncing
- Exclusion list, hidden file filtering, recursive monitoring toggle
### What it doesn't do (yet)
- Email or push notifications
- Encrypted baseline storage
- Multi-host / distributed agents
- Role-based access control
- Windows or macOS support
---
 
## Use Cases
 
- **HIDS learning** — understand how host-based intrusion detection systems work at the kernel level
- **Home lab security** — monitor sensitive directories on a personal Linux server
- **Academic projects** — cybersecurity FYP or coursework demonstration
- **Security tooling demos** — showcase real-time file monitoring with a polished UI
- **CTF infrastructure** — detect unexpected file changes on competition servers

---
 
## Author
 
**Muhammad Husnain**  
🎓 BS Cybersecurity &nbsp;|&nbsp; 🛡️ Junior Penetration Tester  
✍️ [hackwithhusnain.com](https://hackwithhusnain.com)
 
---
 
## License
 
MIT — see `LICENSE` for details.
