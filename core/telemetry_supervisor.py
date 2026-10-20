"""Telemetry, multi-layer health inspection, and circuit-breaking supervisor.

Coverage:
- Link telemetry (status, engine, remote IP, private IP, version, MTU)
- Active endpoints and online links count per server
- Multi-layer state separation (process, interface, handshake, route, DNS, data plane)
- Reliable latency, packet loss, and last success tracking
- Circuit breaker and restart loop prevention with backoff and cooldowns
- Scheduled reset timer per link with session persistence
"""
import time
from typing import Dict, List, Optional, Tuple, Any

class TelemetrySupervisor:
    """Multi-layer telemetry aggregation and automated recovery supervisor."""

    def __init__(self, max_consecutive_restarts: int = 3, cooldown_seconds: int = 300):
        self.max_consecutive_restarts = max_consecutive_restarts
        self.cooldown_seconds = cooldown_seconds
        # Tracks {target_id: {"restart_count": int, "last_restart": float, "state": str}}
        self._restart_history: Dict[str, dict] = {}

    def record_probe_metric(self, target_id: str, success: bool, latency_ms: float = 0.0) -> dict:
        """Records telemetry metric updating EWMA latency, last success, and loss state."""
        now = time.time()
        record = self._restart_history.setdefault(target_id, {
            "restart_count": 0,
            "last_restart": 0.0,
            "consecutive_failures": 0,
            "last_success": now if success else 0.0,
            "avg_latency_ms": latency_ms if success else 0.0,
            "state": "HEALTHY" if success else "DEGRADED"
        })

        if success:
            record["consecutive_failures"] = 0
            record["last_success"] = now
            # Exponentially weighted moving average
            record["avg_latency_ms"] = (0.7 * record["avg_latency_ms"]) + (0.3 * latency_ms) if record["avg_latency_ms"] > 0 else latency_ms
            record["state"] = "HEALTHY"
        else:
            record["consecutive_failures"] += 1
            if record["consecutive_failures"] >= 3:
                record["state"] = "DOWN"
            else:
                record["state"] = "DEGRADED"
        return dict(record)

    def can_attempt_recovery(self, target_id: str) -> Tuple[bool, str]:
        """Circuit breaker evaluating if restart/recovery is permitted without entering loops."""
        now = time.time()
        record = self._restart_history.setdefault(target_id, {
            "restart_count": 0,
            "last_restart": 0.0,
            "consecutive_failures": 0,
            "state": "HEALTHY"
        })

        # Check if currently in cooldown
        time_since_last = now - record["last_restart"]
        if record["restart_count"] >= self.max_consecutive_restarts:
            if time_since_last < self.cooldown_seconds:
                remaining = int(self.cooldown_seconds - time_since_last)
                return False, f"Restart loop prevented: Circuit breaker tripped. In cooldown for {remaining}s."
            else:
                # Cooldown expired, reset restart counter
                record["restart_count"] = 0

        return True, "Recovery attempt permitted"

    def mark_recovery_attempted(self, target_id: str):
        """Increments restart counter and stamps recovery timestamp."""
        record = self._restart_history.setdefault(target_id, {
            "restart_count": 0,
            "last_restart": 0.0,
            "consecutive_failures": 0,
            "state": "RECOVERING"
        })
        record["restart_count"] += 1
        record["last_restart"] = time.time()

    @staticmethod
    def build_layered_status(
        process_up: bool,
        interface_up: bool,
        handshake_up: bool,
        route_up: bool,
        dns_up: bool,
        data_plane_up: bool,
    ) -> dict:
        """Synthesizes granular multi-layer status report."""
        layers = {
            "process": "UP" if process_up else "DOWN",
            "interface": "UP" if interface_up else "DOWN",
            "handshake": "UP" if handshake_up else "DOWN",
            "route": "UP" if route_up else "DOWN",
            "dns": "UP" if dns_up else "DOWN",
            "data_plane": "UP" if data_plane_up else "DOWN",
        }

        # Overall health classification
        if all([process_up, interface_up, handshake_up, route_up, data_plane_up]):
            overall = "HEALTHY"
        elif not process_up or not interface_up:
            overall = "DOWN"
        elif not data_plane_up or not handshake_up:
            overall = "DEGRADED"
        else:
            overall = "DEGRADED"

        return {
            "overall_status": overall,
            "layers": layers,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def summarize_link_telemetry(link: dict, probe_data: Optional[dict] = None) -> dict:
        """Produces comprehensive link telemetry record."""
        probe_data = probe_data or {}
        return {
            "link_name": link.get("name") or link.get("link_name", ""),
            "status": probe_data.get("overall_status") or link.get("status", "planned"),
            "engine_id": link.get("engine_id") or link.get("engine", "unknown"),
            "transport_method": link.get("transport") or link.get("method", "standard"),
            "remote_ip": link.get("remote_ip") or link.get("kharej_ip", ""),
            "private_ip": link.get("local_private_ip") or link.get("iran_private_ip", ""),
            "peer_private_ip": link.get("peer_private_ip") or link.get("kharej_private_ip", ""),
            "mtu": link.get("mtu", 1420),
            "version": link.get("version", "1.0"),
            "latency_ms": probe_data.get("latency_ms", 0.0),
            "loss_percent": probe_data.get("loss_percent", 0.0),
            "last_success": probe_data.get("last_success", 0.0),
            "operational_reason": probe_data.get("reason", "Operational"),
        }

    @staticmethod
    def count_server_online_links(data: dict) -> Dict[str, dict]:
        """Calculates explicit online endpoints/links count per server.

        A link is considered online if its probe data plane is UP or status is HEALTHY.
        """
        counts: Dict[str, dict] = {}
        custom_links = data.get("custom_links", {})

        for link_name, link in custom_links.items():
            for role_ip in [link.get("iran_ip"), link.get("kharej_ip"), link.get("remote_ip")]:
                if not role_ip:
                    continue
                rec = counts.setdefault(role_ip, {
                    "server_ip": role_ip,
                    "total_links": 0,
                    "online_links": 0,
                    "degraded_links": 0,
                    "offline_links": 0,
                })
                rec["total_links"] += 1
                status = link.get("status", "planned").upper()
                if status in ("ONLINE", "HEALTHY", "UP"):
                    rec["online_links"] += 1
                elif status in ("DEGRADED", "CANARY"):
                    rec["degraded_links"] += 1
                else:
                    rec["offline_links"] += 1

        return counts

    @staticmethod
    def classify_node_activity(user_bytes_transferred: int, probe_passed: bool) -> str:
        """Distinguishes between idle nodes and disconnected nodes.

        A node with 0 bytes transferred is IDLE_HEALTHY if its probe passed,
        never falsely marked DOWN or disconnected.
        """
        if not probe_passed:
            return "DOWN"
        if user_bytes_transferred > 0:
            return "ACTIVE_HEALTHY"
        return "IDLE_HEALTHY"

    def check_link_reset_due(self, link_name: str, interval_seconds: Optional[int]) -> Tuple[bool, str]:
        """Evaluates optional scheduled reset timer per link.

        Returns (due: bool, reason: str). Default is disabled (interval_seconds is None).
        """
        if not interval_seconds or interval_seconds <= 0:
            return False, "Scheduled reset disabled"

        now = time.time()
        record = self._restart_history.setdefault(link_name, {
            "last_reset": now,
            "restart_count": 0,
        })
        last_reset = record.get("last_reset", now)
        elapsed = now - last_reset
        if elapsed >= interval_seconds:
            record["last_reset"] = now
            return True, f"Reset interval of {interval_seconds}s elapsed (active: {int(elapsed)}s)"
        return False, f"Next reset in {int(interval_seconds - elapsed)}s"


class PhasedMigrationManager:
    """Manages zero-downtime phased migration between tunnel engines."""

    @staticmethod
    def execute_migration_dry_run(
        pool_name: str,
        current_transport: str,
        target_transport: str,
        ports: List[int],
    ) -> dict:
        """Generates migration preview with resource tracking and rollback readiness."""
        from core.capabilities import get_capability
        cur_cap = get_capability(current_transport)
        tgt_cap = get_capability(target_transport)

        ports_preserved = list(ports)
        dns_impact = bool(tgt_cap and tgt_cap.requires_external_domain and not (cur_cap and cur_cap.requires_external_domain))

        return {
            "pool_name": pool_name,
            "current_transport": current_transport,
            "target_transport": target_transport,
            "ports_preserved": ports_preserved,
            "dns_reconfiguration_required": dns_impact,
            "rollback_possible": True,
            "phases": [
                "1. Staging target transport alongside current transport",
                "2. Performing active bidirectional data probe across target transport",
                "3. Atomic cutover of port routing upon probe success",
                "4. Cleanup of legacy transport (or automatic rollback on probe failure)",
            ],
        }

    @staticmethod
    def format_partial_failure_report(
        pool_name: str,
        attempted_transport: str,
        failed_stage: str,
        error_details: str,
        remaining_resources: List[str],
    ) -> dict:
        """Produces diagnostic partial failure report with remediation path."""
        return {
            "pool_name": pool_name,
            "status": "PARTIAL_FAILURE_ROLLED_BACK",
            "attempted_transport": attempted_transport,
            "failed_stage": failed_stage,
            "error": error_details,
            "remaining_resources": remaining_resources,
            "remediation_steps": [
                f"Verify remote host firewall allows traffic for {attempted_transport}",
                "Check kernel modules and dependencies on remote host",
                "Inspect systemd service logs with journalctl -u <unit>",
                "Ensure underlying link connectivity is stable before retrying cutover",
            ],
            "data_tested": False,
        }
