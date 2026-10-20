#!/usr/bin/env python3
"""
Standalone headless runner for VX-LB Telemetry Watchdog & DNS Failover Daemon.
Supports foreground execution (systemd), background daemonizing with PID tracking,
and single-cycle test execution.
"""
import os
import sys
import time
import signal
import argparse
import json
from core.storage import DATA_DIR, LOG_FILE, atomic_update, rotated_log
from core.watchdog import TelemetryWatchdog
from core.dns_scheduler import run_due_rotations

PID_FILE = os.path.join(DATA_DIR, "watchdog.pid")

def log(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] [daemon] {msg}"
    print(formatted, flush=True)
    rotated_log(LOG_FILE, formatted)

def run_loop(interval: int = 30):
    watchdog = TelemetryWatchdog(check_interval=interval)
    log(f"Starting VX-LB Watchdog in foreground (interval: {interval}s)...")

    # Save PID
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    running = True

    def _sig_handler(signum, frame):
        nonlocal running
        log(f"Received signal {signum}, stopping gracefully...")
        running = False

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    try:
        while running:
            try:
                report = watchdog.run_check_cycle(callback=log)
                def save_summary(data):
                    data["watchdog_status"] = {
                        "last_check": report.get("timestamp"),
                        "healthy_ips": report.get("healthy_ips", []),
                        "filtered_ips": report.get("filtered_ips", []),
                        "pool_reports": report.get("pool_reports", {})
                    }
                atomic_update(save_summary)
                run_due_rotations(callback=log)
            except Exception as e:
                log(f"Watchdog cycle error: {str(e)}")

            for _ in range(interval):
                if not running:
                    break
                time.sleep(1)
    finally:
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except Exception:
                pass
        log("Watchdog daemon stopped.")

def get_pid() -> int:
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            # Check if alive
            os.kill(pid, 0)
            return pid
        except (ValueError, OSError):
            return 0
    return 0

def start_background(interval: int = 30):
    pid = get_pid()
    if pid > 0:
        print(f"Watchdog daemon is already running (PID: {pid}).")
        return

    import subprocess
    cmd = [sys.executable, os.path.abspath(__file__), "--foreground", "--interval", str(interval)]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True
    )
    print(f"Watchdog daemon started in background with PID {proc.pid}.")

def stop_background():
    pid = get_pid()
    if pid == 0:
        print("Watchdog daemon is not running.")
        return
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Sent SIGTERM to Watchdog daemon (PID: {pid}). Waiting for termination...")
        for _ in range(10):
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
            except OSError:
                print("Watchdog daemon stopped successfully.")
                return
        os.kill(pid, signal.SIGKILL)
        print("Watchdog daemon force-killed.")
    except Exception as e:
        print(f"Error stopping daemon: {e}")

def check_status():
    pid = get_pid()
    if pid > 0:
        print(f"Watchdog daemon is ACTIVE (PID: {pid}).")
    else:
        print("Watchdog daemon is INACTIVE.")

def run_once():
    watchdog = TelemetryWatchdog()
    print("Running single watchdog check cycle...")
    rep = watchdog.run_check_cycle(callback=lambda m: print(f"  {m}"))
    print("\n--- Summary Report ---")
    print(json.dumps(rep, indent=2, ensure_ascii=False))

def main():
    parser = argparse.ArgumentParser(description="VX-LB Watchdog Daemon Manager")
    parser.add_argument("--foreground", action="store_true", help="Run daemon in foreground (for systemd)")
    parser.add_argument("--start", action="store_true", help="Start daemon in background")
    parser.add_argument("--stop", action="store_true", help="Stop running background daemon")
    parser.add_argument("--status", action="store_true", help="Check daemon running status")
    parser.add_argument("--once", action="store_true", help="Execute a single check cycle and output report")
    parser.add_argument("--interval", type=int, default=30, help="Check interval in seconds (default: 30)")

    args = parser.parse_args()

    if args.foreground:
        run_loop(args.interval)
    elif args.start:
        start_background(args.interval)
    elif args.stop:
        stop_background()
    elif args.status:
        check_status()
    elif args.once:
        run_once()
    else:
        run_loop(args.interval)

if __name__ == "__main__":
    main()
