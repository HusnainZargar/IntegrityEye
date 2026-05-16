import argparse
import threading
import subprocess
import os
import sys



RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"
DIM    = "\033[2m"


def c(color, text):
    """Wrap text in an ANSI color + reset."""
    return f"{color}{text}{RESET}"



def banner():
    print()
    print(c(CYAN,   "  ██╗███╗   ██╗████████╗███████╗ ██████╗ ██████╗ ██╗████████╗██╗   ██╗███████╗██╗   ██╗███████╗"))
    print(c(CYAN,   "  ██║████╗  ██║╚══██╔══╝██╔════╝██╔════╝ ██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝"))
    print(c(BLUE,   "  ██║██╔██╗ ██║   ██║   █████╗  ██║  ███╗██████╔╝██║   ██║    ╚████╔╝ █████╗   ╚████╔╝ █████╗  "))
    print(c(BLUE,   "  ██║██║╚██╗██║   ██║   ██╔══╝  ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  ██╔══╝    ╚██╔╝  ██╔══╝  "))
    print(c(MAGENTA,"  ██║██║ ╚████║   ██║   ███████╗╚██████╔╝██║  ██║██║   ██║      ██║   ███████╗   ██║   ███████╗"))
    print(c(MAGENTA,"  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   ╚══════╝   ╚═╝   ╚══════╝"))
    print()
    print(c(WHITE,  "  " + BOLD + "IntegrityEye" + RESET + c(DIM, "  —  Real-time file integrity and metadata monitoring")))
    print(c(WHITE,    "  v1.0.0"))
    print(c(WHITE,  "  " + BOLD + "Author: " + RESET + "Muhammad Husnain Zargar"))
    print()


def step(n, msg):
    print(f"  {c(CYAN, f'[STEP {n}]')}  {msg}")


def info(msg):
    print(f"  {c(CYAN, '[INFO] ')}  {msg}")


def ok(msg):
    print(f"  {c(GREEN, '[ OK ] ')}  {msg}")


def warn(msg):
    print(f"  {c(YELLOW, '[WARN] ')}  {msg}")


def err(msg):
    print(f"  {c(RED, '[ERR ] ')}  {msg}")


def separator():
    print("  " + c(DIM, "─" * 60))



def setup_systemd_service(directory=None):
    separator()
    step(1, "Writing systemd unit file…")

    service_file = '/etc/systemd/system/integrityeye.service'
    project_dir  = os.path.dirname(os.path.abspath(__file__))
    main_py_path = os.path.join(project_dir, 'main.py')
    exec_start = f"/usr/bin/python3 {main_py_path}"
    if directory:
        exec_start += f" {directory}"

    service_content = f"""[Unit]
Description=IntegrityEye — File Integrity Monitoring System
After=network.target

[Service]
User=root
WorkingDirectory={project_dir}
ExecStart={exec_start}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

    tmp = os.path.join(project_dir, 'integrityeye.service')
    with open(tmp, 'w') as f:
        f.write(service_content)

    subprocess.run(['mv', tmp, service_file], check=True)
    ok(f"Unit file written  →  {service_file}")

    separator()
    step(2, "Reloading systemd daemon…")
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    ok("Daemon reloaded.")

    step(3, "Enabling service (auto-start on boot)…")
    subprocess.run(['systemctl', 'enable', 'integrityeye'], check=True)
    ok("Service enabled.")

    step(4, "Starting service now…")
    subprocess.run(['systemctl', 'start', 'integrityeye'], check=True)
    ok("Service started.")

    separator()
    print()
    print("  " + c(GREEN, "┌─────────────────────────────────────────────────────┐"))
    print("  " + c(GREEN, "│                                                     │"))
    print("  " + c(GREEN, "│") + c(WHITE, "   IntegrityEye is running as a systemd service.     ") + c(GREEN, "│"))
    print("  " + c(GREEN, "│                                                     │"))
    print("  " + c(GREEN, "│") + c(CYAN,  "   Dashboard  →  http://localhost:5000               ") + c(GREEN, "│"))
    print("  " + c(GREEN, "│") + c(DIM,   "   Credentials:  admin / admin                       ") + c(GREEN, "│"))
    print("  " + c(GREEN, "│                                                     │"))
    print("  " + c(GREEN, "│") + c(WHITE, "   Useful commands:                                  ") + c(GREEN, "│"))
    print("  " + c(GREEN, "│") + c(DIM,   "     systemctl status integrityeye                   ") + c(GREEN, "│"))
    print("  " + c(GREEN, "│") + c(DIM,   "     journalctl -u integrityeye -f                   ") + c(GREEN, "│"))
    print("  " + c(GREEN, "│") + c(DIM,   "     systemctl stop integrityeye                     ") + c(GREEN, "│"))
    print("  " + c(GREEN, "│") + c(DIM,   "     systemctl restart integrityeye                  ") + c(GREEN, "│"))
    print("  " + c(GREEN, "│                                                     │"))
    print("  " + c(GREEN, "└─────────────────────────────────────────────────────┘"))
    print()
    sys.exit(0)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='integrityeye',
        description=(
            "IntegrityEye — Real-time file integrity and metadata monitoring.\n\n"
            "USAGE\n"
            "  sudo python3 main.py [/path/to/monitor]\n\n"
            "FIRST RUN\n"
            "  Run as root to install and start the systemd service.\n"
            "  Add more paths to monitor from the web UI Settings page.\n\n"
            "USEFUL COMMANDS (after install)\n"
            "  systemctl status integrityeye\n"
            "  journalctl -u integrityeye -f\n"
            "  systemctl restart integrityeye\n"
            "  systemctl stop integrityeye\n\n"
            "DASHBOARD\n"
            "  http://localhost:5000   (default credentials: admin / admin)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'directory', type=str, nargs='?', default=None,
        help="Optional path to monitor on first start (can also add from the web UI)"
    )
    args = parser.parse_args()
    running_under_systemd = os.getenv('INVOCATION_ID') is not None

    if not running_under_systemd:

        banner()
        separator()

        # Require root
        if os.geteuid() != 0:
            warn("This script must run as root to install the systemd service.")
            warn("Re-run with:  " + c(CYAN, "sudo python3 main.py") +
                 (c(CYAN, f" {args.directory}") if args.directory else ""))
            print()
            sys.exit(1)

        if args.directory:
            path = os.path.abspath(args.directory)
            if not os.path.exists(path):
                err(f"Path does not exist: {path}")
                sys.exit(1)
            info(f"Path to monitor on first start: {c(CYAN, path)}")
        else:
            info("No path supplied — add monitored paths from the " +
                 c(CYAN, "web UI → Settings") + " page.")

        separator()
        print()

        setup_systemd_service(args.directory)

    else:

        import logging
        from components.utils import get_config, set_config, add_settings_audit, init_db
        init_db()
        if args.directory:
            path = os.path.abspath(args.directory)
            paths = get_config('monitored_paths') or []
            if path not in paths:
                paths = list(paths) + [path]
                set_config('monitored_paths', paths)
                add_settings_audit(f"Systemd service added monitored path: {path}")

        set_config('monitoring_active', 1)
        from components.monitor import run_monitor_loop
        monitor_thread = threading.Thread(target=run_monitor_loop, daemon=True)
        monitor_thread.start()
        log = logging.getLogger('werkzeug')
        log.disabled = True

        from web.app import app
        app.run(host='127.0.0.1', port=5000, debug=False,
                use_reloader=False, threaded=True)
