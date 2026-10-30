#!/usr/bin/env python3
"""
BackPack User Connection Telemetry Logger
Monitors inbound user traffic across all forwarded service ports.
Extracts kernel TCP socket metrics (Send-Q, bytes_received, bytes_acked, retransmissions)
to detect transport stalls, DPI drops, and active data-flowing sessions per port.
"""
import subprocess
import time
import os
import glob
import re

LOG_PATH = "/var/log/vxlb-user-connections.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB

def _rotate_log_if_needed():
    try:
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > MAX_LOG_SIZE:
            backup_path = f"{LOG_PATH}.1"
            if os.path.exists(backup_path):
                try:
                    os.remove(backup_path)
                except Exception:
                    pass
            os.rename(LOG_PATH, backup_path)
    except Exception:
        pass

def log_event(event: str, peer: str, port: str, details: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {event} | port={port} | client={peer} | {details}\n"
    _rotate_log_if_needed()
    try:
        with open(LOG_PATH, "a") as f:
            f.write(line)
            f.flush()
    except Exception:
        pass

_cached_ports = None
_last_ports_check = 0.0

def ports_from_wattunnel_yaml(text):
    """Listen ports from a WatTunnel client config. `8443:443` publishes 8443."""
    found = set()
    in_ports = False
    for raw in str(text or '').splitlines():
        line = raw.split('#', 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if not line[:1].isspace() and not stripped.startswith('-'):
            in_ports = stripped == 'ports:'
            continue
        if not in_ports or not stripped.startswith('-'):
            continue
        item = stripped[1:].strip().strip('"').strip("'")
        item = item.split('/', 1)[0]
        if ':' in item:
            item = item.split(':', 1)[0]
        if item.isdigit():
            found.add(item)
    return found


def get_monitored_ports():
    global _cached_ports, _last_ports_check
    now = time.time()
    if _cached_ports is not None and (now - _last_ports_check) < 15.0:
        return _cached_ports

    ports = set()
    for f in glob.glob("/etc/backpack/*.toml"):
        try:
            with open(f) as fp:
                for line in fp:
                    if line.strip().startswith("ports"):
                        found = re.findall(r'"(\d+)"', line)
                        ports.update(found)
        except Exception:
            pass
    for f in glob.glob("/etc/vxlb/wattunnel/client-*.yml"):
        try:
            with open(f) as fp:
                ports.update(ports_from_wattunnel_yaml(fp.read()))
        except Exception:
            pass
    _cached_ports = sorted(list(ports)) if ports else ["2222"]
    _last_ports_check = now
    return _cached_ports

def get_sockets():
    ports = get_monitored_ports()
    filter_expr = " or ".join([f"sport = :{p}" for p in ports])
    try:
        return subprocess.check_output(
            f"ss -tan -i {filter_expr}",
            shell=True, text=True, stderr=subprocess.DEVNULL
        )
    except Exception:
        return ""

def parse_sockets(ss_output):
    lines = ss_output.strip().split("\n")
    sockets = {}
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("State") or "LISTEN" in line:
            continue
        parts = line.split()
        if len(parts) >= 5:
            state = parts[0]
            recv_q = int(parts[1]) if parts[1].isdigit() else 0
            send_q = int(parts[2]) if parts[2].isdigit() else 0
            local_addr = parts[3]
            peer = parts[4]
            port = local_addr.rsplit(":", 1)[-1] if ":" in local_addr else "unknown"

            tcp_info = ""
            if i < len(lines) and not any(lines[i].strip().startswith(s) for s in ("ESTAB", "SYN-", "FIN-", "CLOSE-", "TIME-", "LAST-", "LISTEN")):
                tcp_info = lines[i].strip()
                i += 1
            sockets[(local_addr, peer)] = {
                "peer": peer,
                "port": port,
                "state": state,
                "recv_q": recv_q,
                "send_q": send_q,
                "tcp_info": tcp_info
            }
    return sockets

def extract_metric(info_str: str, key: str) -> int:
    m = re.search(r'\b' + key + r':(\d+)', info_str)
    return int(m.group(1)) if m else 0

def monitor_loop():
    active = {}
    while True:
        try:
            ss_out = get_sockets()
            current = parse_sockets(ss_out)
            now = time.time()

            # Process active connections
            for connection, info in current.items():
                peer = info["peer"]
                port = info["port"]
                state = info["state"]
                send_q = info["send_q"]
                recv_q = info["recv_q"]
                tcp_info = info["tcp_info"]

                bytes_rx = extract_metric(tcp_info, "bytes_received")
                bytes_ack = extract_metric(tcp_info, "bytes_acked")
                retrans = extract_metric(tcp_info, "retrans")

                if connection not in active:
                    active[connection] = {
                        "peer": peer,
                        "port": port,
                        "start": now,
                        "last_rx": bytes_rx,
                        "last_ack": bytes_ack,
                        "last_ack_time": now,
                        "ack_advances": 0,
                        "last_rx_time": now,
                        "stuck_start": now if (send_q > 0 or state == "FIN-WAIT-1") else None,
                        "verdict": "CONNECTING",
                        "max_rx": bytes_rx,
                        "max_ack": bytes_ack,
                        "max_retrans": retrans,
                        "logged_fail": False,
                        "logged_success": False
                    }
                    log_event("USER_CONNECT", peer, port, f"state={state} send_q={send_q} bytes_rx={bytes_rx} bytes_ack={bytes_ack}")
                else:
                    c = active[connection]
                    dur = now - c["start"]

                    if bytes_rx > c["max_rx"]:
                        c["max_rx"] = bytes_rx
                        c["last_rx_time"] = now
                    if bytes_ack > c["max_ack"]:
                        c["ack_advances"] += 1
                        c["max_ack"] = bytes_ack
                        c["last_ack_time"] = now
                    if retrans > c["max_retrans"]:
                        c["max_retrans"] = retrans

                    # Track Send-Q queue stall duration accurately
                    if send_q > 0 or state == "FIN-WAIT-1":
                        if c["stuck_start"] is None:
                            c["stuck_start"] = now
                        send_stuck_duration = now - c["stuck_start"]
                    else:
                        c["stuck_start"] = None
                        send_stuck_duration = 0

                    ack_stall_duration = now - c.get("last_ack_time", now)

                    # 1. Verified bidirectional active data transfer:
                    is_bidirectional = (state == "ESTAB" and c["max_rx"] >= 5000 and c["max_ack"] >= 5000 and c["ack_advances"] >= 2 and send_q < 30000)

                    # 2. Genuine transport stall / packet drop:
                    # Return data unacknowledged: Send-Q continuously backlogged for >= 4s AND ACK progress stalled >= 4s
                    is_stalled = (send_q > 0 or state == "FIN-WAIT-1") and (send_stuck_duration >= 4 and ack_stall_duration >= 4)

                    if is_bidirectional and not c["logged_success"]:
                        c["verdict"] = "ACTIVE_TRAFFIC"
                        c["logged_success"] = True
                        c["logged_fail"] = False
                        log_event("USER_SESSION_ACTIVE", peer, port, f"state={state} bytes_rx={c['max_rx']} bytes_ack={c['max_ack']} ack_advances={c['ack_advances']} (bidirectional flow verified)")

                    elif is_stalled and not c["logged_fail"]:
                        c["verdict"] = "TRANSPORT_STALL"
                        c["logged_fail"] = True
                        # A recovery needs fresh ACK progress after this stall.
                        c["logged_success"] = False
                        c["ack_advances"] = 0
                        log_event("TRANSPORT_STALL_DETECTED", peer, port, f"unacked_send_q={send_q} state={state} retrans={c['max_retrans']} queue_stuck={round(send_stuck_duration, 1)}s (possible packet drop / return block)")

            # Clean up closed connections
            for connection in list(active.keys()):
                if connection not in current:
                    c = active.pop(connection)
                    peer = c["peer"]
                    port = c.get("port", "unknown")
                    dur = round(now - c["start"], 1)
                    max_rx = c.get("max_rx", 0)
                    max_ack = c.get("max_ack", 0)

                    if c["verdict"] == "TRANSPORT_STALL" or c["logged_fail"]:
                        log_event("SESSION_CLOSED_STALLED", peer, port, f"dur={dur}s bytes_rx={max_rx} bytes_ack={max_ack} verdict=STALL_OR_DROP")
                    elif c["verdict"] == "ACTIVE_TRAFFIC":
                        log_event("SESSION_CLOSED_NORMAL", peer, port, f"dur={dur}s bytes_rx={max_rx} bytes_ack={max_ack} verdict=CLEAN_FLOW")
                    else:
                        # Short-lived, idle, or incomplete connection
                        log_event("SESSION_CLOSED_INCOMPLETE", peer, port, f"dur={dur}s bytes_rx={max_rx} bytes_ack={max_ack} verdict=INCOMPLETE_OR_IDLE")

        except Exception:
            pass
        time.sleep(1)

if __name__ == "__main__":
    monitor_loop()
