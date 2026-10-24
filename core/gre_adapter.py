"""GRE IPv4 tunnel adapter implementing BaseTunnelAdapter.

Standardizes GRE IPv4 adapter into the universal registry.
"""
from typing import Dict, List, Tuple, Optional
from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.ssh_client import SSHManager

class GreIpv4Adapter(BaseTunnelAdapter):
    def __init__(self):
        super().__init__("gre_ipv4")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        # Preflight kernel modules for GRE and IPsec
        cmd = "modprobe gre && modprobe ip_gre && modprobe xfrm_user 2>/dev/null; which iptables ip"
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"GRE preflight kernel check failed: {err or out}"
        return True, "GRE kernel prerequisites verified"

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.gre import build_systemd_unit, generate_psk
        psk = pool_config.get("ipsec_psk") or generate_psk()
        return {
            "psk": psk,
            "engine": "gre_ipv4",
            "transport": "gre",
            "mtu": pool_config.get("mtu", 1280)
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {svc} && systemctl restart {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre-{identifier}.service"
        cmd = f"systemctl stop {svc} && systemctl disable {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre-{identifier}.service"
        ok, out, _ = ssh.execute(f"systemctl is-active {svc}")
        is_active = (ok == 0 and out.strip() == "active")
        return {
            "engine": "gre_ipv4",
            "service": svc,
            "status": "UP" if is_active else "DOWN"
        }

    def probe(self, endpoint_ir: dict, endpoint_kh: dict, ports: List[int]) -> dict:
        from core.gre import verify_gre_tunnel
        ok, latency = verify_gre_tunnel(endpoint_ir, endpoint_kh, ports)
        return {
            "passed": ok,
            "latency_ms": latency,
        }

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.gre import change_mtu, change_ports
        if "mtu" in updates:
            ok, msg = change_mtu(pool_name, int(updates["mtu"]))
            return ok, msg
        if "ports" in updates:
            ok, msg = change_ports(pool_name, updates["ports"])
            return ok, msg
        return True, "No supported modification"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.gre import rollback_mtu
        if "mtu" in previous_state:
            ok, msg = rollback_mtu(pool_name, int(previous_state["mtu"]))
            return ok, msg
        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        from core.gre import cleanup_gre_node
        # Call cleanup ensuring fail-closed removal
        return cleanup_gre_node(ssh, identifier)

register_adapter(GreIpv4Adapter())

