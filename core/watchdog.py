import os
import sys
import time
import re
import threading
import shlex
from typing import Dict, List, Tuple, Callable, Optional
from core.storage import load_data, save_data, atomic_update, LOG_FILE, DATA_DIR, rotated_log
from core.ssh_client import SSHManager
from core.tunnel_readiness import control_connected
from core.validation import validate_port
from core.cloudflare import CloudflareManager
from core.dns_routing import routing_lock, route_key, effective_config
from core.transport_change import ACTIVE as TRANSPORT_ACTIVE

class TelemetryWatchdog:
    def __init__(self, check_interval: int = 30):
        self.check_interval = check_interval
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def get_cloudflare_config() -> Optional[dict]:
        data = load_data()
        return data.get("cloudflare")

    @staticmethod
    def set_cloudflare_config(api_token: str, zone_id: str, subdomain: str, enabled: bool = True):
        def _up(data: dict):
            data["cloudflare"] = {
                "api_token": api_token.strip(),
                "zone_id": zone_id.strip(),
                "subdomain": subdomain.strip().lower(),
                "enabled": enabled
            }
        atomic_update(_up)

    @staticmethod
    def get_node_telemetry(pool_name: str, ip: str) -> dict:
        data = load_data()
        telem = data.get("node_telemetry", {})
        key = f"{pool_name}:{ip}"
        return telem.get(key, {})

    @staticmethod
    def save_node_telemetry(pool_name: str, ip: str, status: str, reason: str, logs: Optional[List[str]] = None, port_details: Optional[dict] = None):
        key = f"{pool_name}:{ip}"
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        def _updater(data: dict):
            if "node_telemetry" not in data:
                data["node_telemetry"] = {}
            prev = data["node_telemetry"].get(key, {})
            # Preserve status_since if status has not changed
            if prev.get("status") == status and prev.get("status_since"):
                status_since = prev["status_since"]
            else:
                status_since = now_str

            data["node_telemetry"][key] = {
                "pool": pool_name,
                "ip": ip,
                "status": status,
                "reason": reason,
                "status_since": status_since,
                "filter_confirmed": status == "FILTERED",
                "port_details": port_details or {},
                "logs": logs or [],
                "updated_at": now_str
            }

        atomic_update(_updater)

    def analyze_node_health(self, pool_name: str, node: dict, client_ports: Optional[List[str]] = None) -> Tuple[str, str, List[str], Dict[str, dict]]:
        """
        Inspects user connection telemetry (/var/log/bp-user-connections.log)
        and live sockets strictly across client ports belonging to this specific pool.
        Requires multi-client consensus for filtering, avoids marking idle nodes as filtered,
        and provides canary recovery after cooldown.
        """
        if node.get('engine') == 'spoof' and node.get('spoof'):
            from core.spoof_transport import health
            status, reason, details = health(pool_name,node,client_ports or [])
            self.save_node_telemetry(pool_name,node['ip'],status,reason,[],details)
            return status,reason,[],details
        if node.get('engine') in ('http', 'https'):
            from core.http_transport import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') == 'slipstream':
            from core.slipstream_adapter import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') == 'waterwall':
            from core.waterwall import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') == 'paqet':
            from core.paqet_adapter import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') == 'xray':
            from core.https_tunnel import health
            status, reason, details = health(pool_name,node,client_ports or [])
            self.save_node_telemetry(pool_name,node['ip'],status,reason,[],details)
            return status,reason,[],details
        if node.get('engine') == 'gre' or node.get('transport') == 'gre':
            from core.gre import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') in ('geneve', 'geneve_ipsec') or node.get('transport') in ('geneve', 'geneve_ipsec'):
            from core.geneve import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') == 'gre6' or node.get('transport') == 'gre6':
            from core.gre6 import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') == 'ip6ip6' or node.get('transport') == 'ip6ip6':
            from core.ip6ip6 import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') == 'dc6' or node.get('transport') == 'dc6':
            from core.dc6_runtime import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') == 'tun' or node.get('transport') == 'tun':
            from core.tun_runtime import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') == 'vxlan' or node.get('transport') == 'vxlan':
            from core.vxlan_adapter import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details
        if node.get('engine') == 'wireguard' or node.get('transport') == 'wireguard':
            from core.wireguard_adapter import health
            status, reason, details = health(pool_name, node, client_ports or [])
            self.save_node_telemetry(pool_name, node['ip'], status, reason, [], details)
            return status, reason, [], details

        ip = node["ip"]
        # Security: ports flow into a shell filter expression below -- accept
        # digits only so a poisoned pool record cannot inject shell commands.
        raw_ports = [str(p).strip() for p in (client_ports or ["2222"]) if str(p).strip()]
        ports = []
        for rp in raw_ports:
            try:
                ports.append(validate_port(rp))
            except ValueError:
                continue
        if not ports:
            ports = ["2222"]
        ssh = SSHManager(
            ip,
            int(node.get("port") or 22),
            node.get("username", "root"),
            node.get("password"),
            key_path=node.get("key_path"),
            private_key=node.get("private_key"),
            timeout=8,
        )
        ok, msg = ssh.connect()
        if not ok:
            reason = f"SSH unreachable; current health cannot be verified ({msg})"
            self.save_node_telemetry(pool_name, ip, "DOWN", reason, [], {})
            return "DOWN", reason, [], {}

        if node.get('node_name'):
            if not control_connected(ssh, 'backpack-'+node['node_name']+'.service'):
                ssh.close()
                reason = 'Tunnel control channel is disconnected; service active does not mean traffic can pass'
                self.save_node_telemetry(pool_name, ip, 'DOWN', reason, [], {})
                return 'DOWN', reason, [], {}

        # Read the time window, including the rotated file; busy ports must not
        # push successful sessions out of an arbitrary tail-of-lines sample.
        reader = """import time, os
now=time.time()
for path in ['/var/log/bp-user-connections.log.1','/var/log/bp-user-connections.log']:
    if not os.path.exists(path): continue
    with open(path, errors='replace') as source:
        for line in source:
            try: age=now-time.mktime(time.strptime(line[1:20],'%Y-%m-%d %H:%M:%S'))
            except ValueError: continue
            if -5 <= age <= 900: print(line.rstrip())
print(time.strftime('BP_CLOCK '+str(int(now))+' %Y-%m-%d %H:%M:%S'))
"""
        log_rc, log_content, log_error = ssh.execute('python3 -c ' + shlex.quote(reader))
        clock_offset = 0
        clock = re.search(r"BP_CLOCK (\d+) (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", log_content)
        if clock:
            clock_offset = int(clock.group(1)) - time.mktime(time.strptime(clock.group(2), "%Y-%m-%d %H:%M:%S"))
        recent_log_lines = [l.strip() for l in log_content.strip().split("\n") if l.strip() and not l.startswith("BP_CLOCK ")]

        # 2. Check live sockets strictly across ports of this pool
        filter_expr = " or ".join([f"sport = :{p}" for p in ports])
        _, ss_out, _ = ssh.execute(f"ss -tan -i {filter_expr}")
        ssh.close()
        if log_rc != 0:
            reason = 'Telemetry window unavailable; filtering cannot be confirmed'
            self.save_node_telemetry(pool_name, ip, 'DOWN', reason, [], {})
            return 'DOWN', reason, [], {}
        previous = self.get_node_telemetry(pool_name, ip).get('port_details', {})
        socket_samples = {p: {} for p in ports}
        stuck_clients = {p: set() for p in ports}

        # Parse live sockets per port: count both active data-flowing sockets and genuinely stuck sockets
        live_stalls_by_port = {p: 0 for p in ports}
        live_actives_by_port = {p: 0 for p in ports}
        lines = ss_out.strip().split("\n")
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            i += 1
            if not line or line.startswith("State") or "LISTEN" in line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                state = parts[0]
                send_q = int(parts[2]) if parts[2].isdigit() else 0
                local_addr = parts[3]
                sock_port = local_addr.rsplit(":", 1)[-1] if ":" in local_addr else ""

                tcp_info = ""
                if i < len(lines) and not any(lines[i].strip().startswith(s) for s in ("ESTAB", "SYN-", "FIN-", "CLOSE-", "TIME-", "LAST-", "LISTEN")):
                    tcp_info = lines[i].strip()
                    i += 1

                # Parse active throughput metrics
                m_ack = re.search(r'bytes_acked:(\d+)', tcp_info)
                m_rx = re.search(r'bytes_received:(\d+)', tcp_info)
                bytes_ack = int(m_ack.group(1)) if m_ack else 0
                bytes_rx = int(m_rx.group(1)) if m_rx else 0

                # Active live session in kernel: ESTAB with bidirectional data flow and normal queue
                if state == "ESTAB" and bytes_ack > 2000 and bytes_rx > 2000 and send_q < 30000 and "backoff:" not in tcp_info:
                    if sock_port in live_actives_by_port:
                        peer = parts[4] if len(parts) > 4 else ''
                        old = previous.get(sock_port, {}).get('socket_samples', {}).get(peer, {})
                        if 0 < time.time() - previous.get(sock_port, {}).get('checked_epoch', 0) <= 90 and bytes_ack > old.get('ack', bytes_ack) and bytes_rx > old.get('rx', bytes_rx):
                            live_actives_by_port[sock_port] += 1

                if sock_port in socket_samples and len(parts) > 4:
                    socket_samples[sock_port][parts[4]] = {'ack': bytes_ack, 'rx': bytes_rx}
                # Genuine stuck live session: persistent backlog with RTO backoff
                is_rto_backoff = "backoff:" in tcp_info or ("rto:120000" in tcp_info and send_q > 5000)
                if (state == "FIN-WAIT-1" and send_q > 5000) or (send_q > 10000 and is_rto_backoff):
                    if sock_port in live_stalls_by_port:
                        live_stalls_by_port[sock_port] += 1
                        if len(parts) > 4: stuck_clients[sock_port].add(parts[4].rsplit(':', 1)[0])

        # 3. Parse log lines with timestamp freshness window (15 minutes = 900s)
        now_ts = time.time()
        parsed_logs = []
        for l in recent_log_lines:
            m = re.match(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+([A-Z_]+)\s+\|\s+port=(\d+)\s+\|\s+(.*)', l)
            if m:
                ts_str, evt, p_str, rest = m.groups()
                try:
                    ev_time = time.mktime(time.strptime(ts_str, "%Y-%m-%d %H:%M:%S")) + clock_offset
                    age = now_ts - ev_time
                except Exception:
                    age = 999999
                parsed_logs.append({
                    "raw": l,
                    "time": ts_str,
                    "age": age,
                    "event": evt,
                    "port": p_str,
                    "rest": rest
                })

        # Evaluate each port of this pool independently
        port_results = {}
        for p in ports:
            live_active = live_actives_by_port.get(p, 0)
            live_stuck = live_stalls_by_port.get(p, 0)

            # Filter fresh logs for this specific port (<= 900s)
            p_logs = [pl for pl in parsed_logs if pl["port"] == p and -5 <= pl["age"] <= 900]
            # The newest verdict for each endpoint wins; stall + close is one
            # failed connection, and a recovery supersedes its earlier failure.
            verdicts = {}
            for event in p_logs:
                match = re.search(r'client=([^ |]+)', event['raw'])
                if match and event['event'] in ('TRANSPORT_STALL_DETECTED', 'SESSION_CLOSED_STALLED', 'DPI_DROP_DETECTED', 'USER_SESSION_ACTIVE', 'SESSION_CLOSED_NORMAL'):
                    peer = match.group(1)
                    if peer not in verdicts or event['age'] <= verdicts[peer]['age']:
                        verdicts[peer] = event
            stalls = [e for e in verdicts.values() if e['event'] in ('TRANSPORT_STALL_DETECTED','SESSION_CLOSED_STALLED','DPI_DROP_DETECTED') and e['age'] <= 120]
            actives = []
            for e in verdicts.values():
                if e['event'] not in ('USER_SESSION_ACTIVE','SESSION_CLOSED_NORMAL') or e['age'] > 120: continue
                rx = re.search(r'bytes_rx=(\d+)', e['raw'])
                ack = re.search(r'bytes_ack=(\d+)', e['raw'])
                if rx and ack and int(rx.group(1)) >= 5000 and int(ack.group(1)) >= 5000: actives.append(e)
            clients = {re.search(r'client=([^ |]+)',e['raw']).group(1).rsplit(':',1)[0] for e in stalls} | stuck_clients[p]
            total_active = live_active + len(actives)
            old = previous.get(p, {})
            last_check = old.get('checked_epoch', 0)
            latest_failure = max((now_ts-e['age'] for e in stalls), default=0)
            consensus = len(clients) >= 3 and total_active == 0
            # Re-reading the same closed failures cannot advance confirmation.
            fresh_round = len(stuck_clients[p]) >= 3 or latest_failure > old.get('failure_epoch', 0)
            streak = old.get('failure_checks', 0) if consensus and now_ts-last_check <= 90 else 0
            if consensus and fresh_round and now_ts-last_check >= 15:
                streak = streak + 1 if now_ts-last_check <= 90 else 1
            if total_active:
                is_degraded = bool(clients) and (total_active < 3 or (len(clients) >= 3 and len(clients) > total_active * 0.15))
                status = 'DEGRADED' if is_degraded else 'HEALTHY'
                if is_degraded:
                    reason = f'Fresh bidirectional flow ({total_active} session(s)); significant stalls ({len(clients)} client(s))'
                elif clients:
                    reason = f'Fresh bidirectional flow ({total_active} session(s)); {len(clients)} isolated client disconnect(s)'
                else:
                    reason = f'Fresh bidirectional flow ({total_active} session(s)); 0 client(s) stalled'
            elif consensus and streak >= 3:
                status = 'FILTERED'
                reason = f'Transport impairment confirmed across {len(clients)} independent clients and {streak} checks; cause unverified'
            elif clients:
                status = 'DEGRADED'
                reason = f'Suspected transport stalls: {len(stalls)} unique connection(s), {len(clients)} independent client(s); confirmation {streak}/3'
            else:
                status = 'IDLE'
                reason = 'No fresh bidirectional flow or failure evidence; health unverified'
            last_success = now_ts if total_active else old.get('last_success_epoch')
            port_results[p] = {'status':status, 'reason':reason,
                'checked_epoch':now_ts, 'failure_epoch':latest_failure,
                'failure_checks':streak, 'last_success_epoch':last_success,
                'socket_samples':socket_samples[p], 'independent_clients':len(clients)}

        # Determine node status specifically for this pool
        filtered_ports = [p for p, res in port_results.items() if res["status"] == "FILTERED"]
        degraded_ports = [p for p, res in port_results.items() if res["status"] == "DEGRADED"]
        healthy_ports = [p for p, res in port_results.items() if res["status"] == "HEALTHY"]
        idle_ports = [p for p, res in port_results.items() if res["status"] == "IDLE"]

        if filtered_ports and len(filtered_ports) == len(ports):
            status = "FILTERED"
            reason = f"Impaired on port(s) {', '.join(filtered_ports)}: {port_results[filtered_ports[0]]['reason']}"
        elif filtered_ports:
            status = 'DEGRADED'
            reason = f"Partial impairment on port(s) {', '.join(filtered_ports + degraded_ports)}; whole-node filtering unverified"
        elif healthy_ports:
            if degraded_ports and len(degraded_ports) >= len(healthy_ports):
                status = 'DEGRADED'
                reason = f"Partial impairment on port(s) {', '.join(degraded_ports)}; {len(healthy_ports)} port(s) healthy"
            else:
                status = "HEALTHY"
                reason = f"Verified healthy on port(s) {', '.join(healthy_ports)}" + (f" (Port(s) {', '.join(degraded_ports + idle_ports)} idle/monitoring)" if (degraded_ports or idle_ports) else "")
        elif degraded_ports:
            status = 'DEGRADED'
            reason = f"Partial or unconfirmed impairment on port(s) {', '.join(degraded_ports)}; whole-node filtering unverified"
        else:
            status = "IDLE"
            # All ports are IDLE in the last 15 minutes
            prev = self.get_node_telemetry(pool_name, ip)
            prev_status = prev.get("status")
            if prev_status == "FILTERED" and prev.get("filter_confirmed"):
                # Check cooldown: if 15 minutes (900s) have passed since filtering was marked,
                # give the node a Canary / Probationary trial to test recovery!
                status_since = prev.get("status_since") or prev.get("updated_at")
                try:
                    cooldown_age = now_ts - time.mktime(time.strptime(status_since, "%Y-%m-%d %H:%M:%S"))
                except Exception:
                    cooldown_age = 0

                if cooldown_age >= 900:
                    status = "CANARY"
                    reason = "Probationary recovery trial (15m cooldown elapsed; testing traffic)"
                else:
                    status = "FILTERED"
                    reason = f"Retaining filtered state (cooldown remaining: {int(900 - cooldown_age)}s)"
            elif prev_status in ("HEALTHY", "CANARY"):
                status = "IDLE"
                reason = "Previous health expired: no fresh bidirectional flow evidence; current health unverified"
            else:
                # Untested node: NOT FILTERED! It is IDLE and eligible for traffic
                status = "IDLE"
                reason = f"No recent traffic across pool ports {', '.join(ports)} (Awaiting connections)"

        self.save_node_telemetry(pool_name, ip, status, reason, recent_log_lines[-5:], port_results)
        return status, reason, recent_log_lines[-5:], port_results

    def run_check_cycle(self, callback: Optional[Callable[[str], None]] = None) -> Dict:
        def log(msg: str):
            if callback:
                callback(msg)

        from core.private_link_monitor import schedule_cycle as check_private_links
        check_private_links()
        data = load_data()
        pools = data.get("pools", {})
        global_cf = data.get("cloudflare")

        if not pools:
            log("No active load balancer pools configured.")
            return {}

        pool_reports = {}
        all_healthy_ips = set()
        all_filtered_ips = set()
        aggregated_nodes = {}

        for pool_name, pool in pools.items():
            log(f"\n[Pool: {pool_name}] Checking nodes...")
            client_ports = pool.get("client_ports", ["2222"])
            nodes = pool.get("nodes", [])
            current = load_data()
            pool_operation_active = any(current.get(key, {}).get(pool_name, {}).get('status') in ('queued','running') for key in ('pool_tasks','pool_creations'))
            if pool_operation_active or pool.get("gre_update", {}).get("status") in ("running", "rollback_failed"):
                log("GRE settings are in maintenance; retaining the previous DNS state")
                previous=load_data().get("watchdog_status",{}).get("pool_reports",{}).get(pool_name)
                if previous: pool_reports[pool_name]=previous
                continue
            if not nodes:
                log(f"  No nodes registered in pool '{pool_name}'. Skipping.")
                continue
            pool_cf = pool.get("cloudflare") or global_cf

            node_results = {}

            # Concurrently inspect all nodes of this pool in parallel
            import concurrent.futures
            max_workers = max(1, min(len(nodes), 8))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_node = [
                    (n, executor.submit(self.analyze_node_health, pool_name, n, client_ports))
                    for n in nodes
                ]
                for n, fut in future_to_node:
                    ip = n["ip"]
                    status, reason, logs, port_details = fut.result()
                    node_results[ip] = {
                        "pool": pool_name,
                        "status": status,
                        "reason": reason,
                        "logs": logs,
                        "ports": client_ports,
                        "port_details": port_details
                    }
                    aggregated_nodes[f"{pool_name}:{ip}"] = node_results[ip]

                    if status in ("HEALTHY", "CANARY"):
                        all_healthy_ips.add(ip)
                        log(f"  ✅ [{status}] {ip}: {reason}")
                    elif status == "DEGRADED":
                        log(f"  ⚠️ [DEGRADED] {ip}: {reason}")
                    elif status == "IDLE":
                        log(f"  ⚪ [IDLE] {ip}: {reason}")
                    else:
                        all_filtered_ips.add(ip)
                        log(f"  ❌ [{status}] {ip}: {reason}")

                    for p, p_res in port_details.items():
                        log(f"     ↳ Port {p}: [{p_res['status']}] {p_res['reason']}")

            # Categorize nodes for DNS routing in this pool:
            # 1. HEALTHY nodes: confirmed clean bidirectional traffic.
            # 2. CANARY nodes: probationary test nodes after cooldown.
            # 3. DEGRADED nodes: only 1 isolated drop (not filtered).
            # 4. IDLE nodes: untested nodes without failure proof (must be in DNS to receive initial traffic).
            # 5. FILTERED nodes: confirmed multi-client stalls (excluded from DNS).
            healthy_ips = [ip for ip, r in node_results.items() if r["status"] == "HEALTHY"]
            canary_ips = [ip for ip, r in node_results.items() if r["status"] == "CANARY"]
            degraded_ips = [ip for ip, r in node_results.items() if r["status"] == "DEGRADED"]
            idle_ips = [ip for ip, r in node_results.items() if r["status"] == "IDLE"]
            filtered_ips = [ip for ip, r in node_results.items() if r["status"] == "FILTERED"]

            # failover DNS only after confirming full path health to destination service.
            # Configurable via pool's 'dns_policy': 'strict' (strictly requires verified full path HEALTHY)
            # or explicitly configured 'permissive' for legacy trial routing.
            dns_policy = pool.get("dns_policy", "strict")
            if dns_policy == "strict":
                active_dns_ips = sorted(list(set(healthy_ips)))
                if not active_dns_ips:
                    log(f"  ⚠️ [Strict 6.10 Policy] No node in pool '{pool_name}' has confirmed complete path health; DNS failover suspended to prevent unverified routing.")
            else:
                if healthy_ips:
                    active_dns_ips = sorted(list(set(healthy_ips + canary_ips + degraded_ips)))
                elif idle_ips or degraded_ips or canary_ips:
                    active_dns_ips = sorted(list(set(idle_ips + degraded_ips + canary_ips)))
                else:
                    fallback_ip = nodes[0]["ip"] if nodes else ""
                    if not fallback_ip:
                        continue
                    active_dns_ips = [fallback_ip]
                    log(f"  ⚠️ All nodes for pool '{pool_name}' impaired! Retaining fallback {fallback_ip} in DNS.")

            # Independent Cloudflare sync for this specific pool
            sync_report = {}
            dns_snapshot = None
            route_source = "auto"
            override_version = None
            from core.dns_scheduler import sync_target_for_watchdog
            active_dns_ips, rotation_pinned = sync_target_for_watchdog(load_data(), pool_name, active_dns_ips)
            if rotation_pinned:
                route_source = "rotation"
            with routing_lock():
                latest = load_data()
                pool_cf = effective_config(latest, pool_name)
                maintenance = any((p.get("transport_change", {}).get("status") in TRANSPORT_ACTIVE or p.get("gre_update",{}).get("status") in ("running","rollback_failed")) and route_key(effective_config(latest, name)) == route_key(pool_cf) for name, p in latest.get("pools", {}).items())
                maintenance = maintenance or any(
                    job.get('status') in ('queued','running') and route_key(effective_config(latest, name)) == route_key(pool_cf)
                    for key in ('pool_tasks','pool_creations') for name,job in latest.get(key,{}).items()
                )
                if not maintenance and pool_cf and pool_cf.get("enabled") and pool_cf.get("api_token") and pool_cf.get("subdomain"):
                    subdomain = pool_cf.get("subdomain")
                    override = latest.get("dns_overrides", {}).get(route_key(pool_cf))
                    if override:
                        active_dns_ips = [override["ip"]]
                        route_source = "manual"
                        override_version = override.get("version")
                    elif not active_dns_ips and dns_policy == "strict":
                        log(f"  ⚠️ DNS sync skipped for '{subdomain}': 0 verified healthy nodes under strict 6.10 policy.")
                        pool_reports[pool_name] = {
                            "source": route_source,
                            "override_version": override_version,
                            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "dns_snapshot": None,
                            "subdomain": subdomain,
                            "scope": pool_cf.get("scope", "single"),
                            "nodes": node_results,
                            "healthy_ips": [],
                            "filtered_ips": filtered_ips,
                            "dns_policy": dns_policy,
                            "cloudflare_sync": {"status": "SUSPENDED_NO_HEALTHY_NODES", "warning": "هیچ نود سالمی با تأیید مسیر کامل موجود نیست"}
                        }
                        continue
                    log(f"  Syncing Cloudflare '{subdomain}' for pool '{pool_name}' (DNS IPs: {active_dns_ips})...")
                    cf = CloudflareManager(pool_cf["api_token"], pool_cf["zone_id"])
                    cf.scope = pool_cf.get('scope','single')
                    sync_report = cf.sync_subdomain(subdomain, active_dns_ips, proxied=False, ttl=60)
                    dns_snapshot = cf.record_snapshot(subdomain)
                    if rotation_pinned:
                        from core.dns_scheduler import record_watchdog_target
                        record_watchdog_target(pool_name, active_dns_ips[0], time.strftime("%Y-%m-%d %H:%M:%S"))
                    if sync_report.get("deleted"):
                        log(f"  🚨 [{subdomain}] Removed filtered IP(s): {sync_report['deleted']}")
                    if sync_report.get("added"):
                        log(f"  ✅ [{subdomain}] Added healthy/canary IP(s): {sync_report['added']}")
                    if sync_report.get("kept"):
                        log(f"  🔒 [{subdomain}] Preserved active IP(s): {sync_report['kept']}")
                    if sync_report.get("warning"):
                        log(f"  ⚠️ [{subdomain}] Cloudflare warning: {sync_report['warning']}")
                    if sync_report.get("failed_adds"):
                        log(f"  ❌ [{subdomain}] Failed to add record(s) to DNS: {sync_report['failed_adds']}")

            pool_reports[pool_name] = {
                "source": route_source,
                "override_version": override_version,
                "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "dns_snapshot": dns_snapshot,
                "subdomain": pool_cf.get("subdomain") if pool_cf else None,
                "scope": pool_cf.get("scope", "single") if pool_cf else "single",
                "nodes": node_results,
                "healthy_ips": active_dns_ips,
                "filtered_ips": filtered_ips,
                "cloudflare_sync": sync_report
            }

        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "pools": list(pools.keys()),
            "pool_reports": pool_reports,
            "nodes": aggregated_nodes,
            "healthy_ips": sorted(list(all_healthy_ips)),
            "filtered_ips": sorted(list(all_filtered_ips))
        }

    @classmethod
    def get_daemon_pid(cls) -> int:
        pid_file = os.path.join(DATA_DIR, "watchdog.pid")
        if os.path.exists(pid_file):
            try:
                with open(pid_file, "r") as f:
                    pid = int(f.read().strip())
                os.kill(pid, 0)
                return pid
            except (ValueError, OSError):
                return 0
        return 0

    @classmethod
    def is_daemon_running(cls) -> bool:
        return cls.get_daemon_pid() > 0

    def start_background_daemon(self, callback: Optional[Callable[[str], None]] = None):
        pid = self.get_daemon_pid()
        if pid > 0:
            return

        daemon_py = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "daemon.py")
        if os.path.exists(daemon_py):
            import subprocess
            cmd = [sys.executable, daemon_py, "--foreground", "--interval", str(self.check_interval)]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True
            )
            return

        # Fallback in-process thread if daemon.py not found
        if self._running:
            return

        self._running = True

        def _log_to_file(msg: str):
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            rotated_log(LOG_FILE, f"[{ts}] {msg}")
            if callback:
                try:
                    callback(msg)
                except Exception:
                    pass

        def _loop():
            while self._running:
                try:
                    rep = self.run_check_cycle(_log_to_file)
                    def _save_summary(data: dict):
                        data["watchdog_status"] = {
                            "last_check": rep.get("timestamp"),
                            "healthy_ips": rep.get("healthy_ips", []),
                            "filtered_ips": rep.get("filtered_ips", []),
                            "pool_reports": rep.get("pool_reports", {})
                        }
                    atomic_update(_save_summary)
                except Exception as e:
                    _log_to_file(f"Watchdog error: {str(e)}")
                
                for _ in range(self.check_interval):
                    if not self._running:
                        break
                    time.sleep(1)

        self._thread = threading.Thread(target=_loop, daemon=True)
        self._thread.start()

    def stop_background_daemon(self):
        pid = self.get_daemon_pid()
        if pid > 0:
            import signal
            try:
                os.kill(pid, signal.SIGTERM)
                for _ in range(10):
                    time.sleep(0.3)
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        break
                else:
                    os.kill(pid, signal.SIGKILL)
            except Exception:
                pass

        self._running = False
        if self._thread:
            try:
                self._thread.join(timeout=1.5)
            except Exception:
                pass
            self._thread = None

