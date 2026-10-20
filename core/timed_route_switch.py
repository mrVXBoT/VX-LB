"""Timed Default Route Switcher with Watchdog Rollback.

Enables safe default route switching across a tunnel interface or gateway.
Captures a structured snapshot of the original default route, applies the
new gateway, and starts an independent watchdog timer. If the switch is not
explicitly confirmed within timeout_seconds (e.g. if connectivity is lost),
the watchdog automatically restores the original default route.
"""
import ipaddress
import json
import logging
import re
import shlex
import time
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("ldbp.timed_route_switch")

SNAPSHOT_FILE = "/etc/ldbp/route-watchdog-snapshot.json"
CONFIRM_FILE = "/etc/ldbp/route-watchdog.confirm"
WATCHDOG_SCRIPT = "/usr/local/bin/ldbp-route-watchdog.py"
WATCHDOG_SERVICE = "ldbp-route-watchdog.service"
WATCHDOG_UNIT_PATH = f"/etc/systemd/system/{WATCHDOG_SERVICE}"


def validate_gateway_and_timeout(gateway_ip: str, timeout_seconds: int) -> Tuple[str, int]:
    try:
        ip = str(ipaddress.IPv4Address(gateway_ip))
    except Exception as e:
        raise ValueError(f"Invalid gateway IPv4 address: {e}")
    timeout = int(timeout_seconds)
    if not 5 <= timeout <= 600:
        raise ValueError("Timeout must be between 5 and 600 seconds")
    return ip, timeout


def get_current_default_route_snapshot(ssh: Any) -> dict:
    code, out, err = ssh.execute("ip -4 -j route show default")
    if code != 0 or not out.strip():
        # Fallback to plain ip route show default
        code2, out2, _ = ssh.execute("ip route show default")
        if code2 != 0 or not out2.strip():
            raise RuntimeError("Failed to detect existing default route on remote host")
        # Parse text e.g. "default via 192.168.1.1 dev eth0 metric 100"
        parts = out2.strip().split()
        via = parts[parts.index("via") + 1] if "via" in parts else None
        dev = parts[parts.index("dev") + 1] if "dev" in parts else None
        metric = parts[parts.index("metric") + 1] if "metric" in parts else None
        return {
            "dst": "default",
            "gateway": via,
            "dev": dev,
            "metric": int(metric) if metric and metric.isdigit() else None,
            "raw": out2.strip()
        }

    try:
        data = json.loads(out)
        if isinstance(data, list) and data:
            row = data[0]
            return {
                "dst": row.get("dst", "default"),
                "gateway": row.get("gateway"),
                "dev": row.get("dev"),
                "metric": row.get("metric"),
                "protocol": row.get("protocol"),
                "raw": out.strip()
            }
        raise RuntimeError("No default route entry returned by iproute2")
    except Exception as e:
        raise RuntimeError(f"Failed to parse route snapshot: {e}")


def render_watchdog_program() -> str:
    return '''#!/usr/bin/env python3
"""LD-BP standalone route switch watchdog."""
import json, os, subprocess, sys, time

SNAPSHOT_FILE = "/etc/ldbp/route-watchdog-snapshot.json"
CONFIRM_FILE = "/etc/ldbp/route-watchdog.confirm"

def restore():
    if not os.path.isfile(SNAPSHOT_FILE):
        return False
    try:
        with open(SNAPSHOT_FILE, "r") as f:
            snap = json.load(f)
        cmd = ["ip", "-4", "route", "replace", "default"]
        if snap.get("gateway"):
            cmd.extend(["via", str(snap["gateway"])])
        if snap.get("dev"):
            cmd.extend(["dev", str(snap["dev"])])
        if snap.get("metric") is not None:
            cmd.extend(["metric", str(snap["metric"])])
        subprocess.run(cmd, check=True)
        return True
    except Exception:
        return False

def run_watchdog(gateway_ip, timeout_seconds, dev=None):
    timeout = int(timeout_seconds)
    # Apply new default route
    cmd = ["ip", "-4", "route", "replace", "default", "via", gateway_ip]
    if dev:
        cmd.extend(["dev", dev])
    subprocess.run(cmd, check=True)

    # Monitor confirmation flag
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if os.path.exists(CONFIRM_FILE):
            sys.exit(0)
        time.sleep(1)

    # Expired without confirmation: trigger rollback
    restore()
    sys.exit(1)

if __name__ == "__main__":
    action = sys.argv[1]
    if action == "run":
        gw = sys.argv[2]
        to = sys.argv[3]
        d = sys.argv[4] if len(sys.argv) > 4 else None
        run_watchdog(gw, to, d)
    elif action == "restore":
        restore()
'''


def render_watchdog_unit(gateway_ip: str, timeout_seconds: int, dev: Optional[str] = None) -> str:
    dev_arg = f" {shlex.quote(dev)}" if dev else ""
    return f"""[Unit]
Description=LD-BP Timed Default Route Watchdog Rollback
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {WATCHDOG_SCRIPT} run {shlex.quote(gateway_ip)} {int(timeout_seconds)}{dev_arg}
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
"""


def execute_timed_route_switch(
    ssh: Any,
    gateway_ip: str,
    timeout_seconds: int = 60,
    dev: Optional[str] = None
) -> dict:
    """Executes default route modification with active watchdog rollback."""
    gw, timeout = validate_gateway_and_timeout(gateway_ip, timeout_seconds)
    snapshot = get_current_default_route_snapshot(ssh)

    # Prepare directories and files
    ssh.execute("mkdir -p /etc/ldbp")
    ssh.write_file(SNAPSHOT_FILE, json.dumps(snapshot, indent=2))
    ssh.execute(f"rm -f {CONFIRM_FILE}")

    # Write watchdog script
    watchdog_py = render_watchdog_program()
    ssh.write_file(WATCHDOG_SCRIPT, watchdog_py)
    ssh.execute(f"chmod 0755 {WATCHDOG_SCRIPT}")

    # Write systemd unit
    unit_str = render_watchdog_unit(gw, timeout, dev)
    ssh.write_file(WATCHDOG_UNIT_PATH, unit_str)
    ssh.execute(f"chmod 0644 {WATCHDOG_UNIT_PATH}")

    # Start the watchdog service
    code, _, err = ssh.execute(f"systemctl daemon-reload && systemctl restart {WATCHDOG_SERVICE}")
    if code != 0:
        # Fallback restore immediately if watchdog failed to start
        restore_cmd = f"/usr/bin/python3 {WATCHDOG_SCRIPT} restore"
        ssh.execute(restore_cmd)
        raise RuntimeError(f"Failed to start route watchdog service: {err}")

    return {
        "status": "active",
        "executed": True,
        "gateway_ip": gw,
        "dev": dev,
        "timeout_seconds": timeout,
        "original_snapshot": snapshot,
        "service": WATCHDOG_SERVICE,
        "snapshot_path": SNAPSHOT_FILE,
        "confirm_path": CONFIRM_FILE
    }


def confirm_route_switch(ssh: Any) -> Tuple[bool, str]:
    """Confirms default route switch, cancels timer, and stops the watchdog."""
    code, _, _ = ssh.execute(f"touch {CONFIRM_FILE}")
    if code != 0:
        return False, "Failed to write confirmation flag on remote host"

    # Stop watchdog service
    ssh.execute(f"systemctl stop {WATCHDOG_SERVICE} 2>/dev/null; systemctl disable {WATCHDOG_SERVICE} 2>/dev/null")
    # Clean temporary files
    ssh.execute(f"rm -f {WATCHDOG_UNIT_PATH} {CONFIRM_FILE} && systemctl daemon-reload")
    return True, "Default route switch confirmed successfully; watchdog timer stopped"


def rollback_route_switch(ssh: Any) -> Tuple[bool, str]:
    """Triggers immediate route restoration and halts the watchdog."""
    code, _, err = ssh.execute(f"/usr/bin/python3 {WATCHDOG_SCRIPT} restore")
    ssh.execute(f"systemctl stop {WATCHDOG_SERVICE} 2>/dev/null; rm -f {WATCHDOG_UNIT_PATH} {CONFIRM_FILE} {SNAPSHOT_FILE} && systemctl daemon-reload")
    if code != 0:
        return False, f"Failed to restore original default route: {err}"
    return True, "Original default route restored successfully"
