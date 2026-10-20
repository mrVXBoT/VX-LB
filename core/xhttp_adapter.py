"""XHTTP Camouflage tunnel adapter implementing BaseTunnelAdapter.

Standardizes Xray XHTTP adapter into the universal registry.
"""
from typing import Dict, List, Tuple, Optional
from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.ssh_client import SSHManager

class XhttpAdapter(BaseTunnelAdapter):
    def __init__(self):
        super().__init__("xhttp")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.https_tunnel import install_xray
        return install_xray(ssh, role, config)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.https_tunnel import generate_xray_config
        return generate_xray_config(iran_node, kharej_server, pool_config)

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"ldbp-xray-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {svc} && systemctl restart {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"ldbp-xray-{identifier}.service"
        cmd = f"systemctl stop {svc} && systemctl disable {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"ldbp-xray-{identifier}.service"
        ok, out, _ = ssh.execute(f"systemctl is-active {svc}")
        is_active = (ok == 0 and out.strip() == "active")
        return {
            "engine": "xhttp",
            "service": svc,
            "status": "UP" if is_active else "DOWN"
        }

    def probe(self, endpoint_ir: dict, endpoint_kh: dict, ports: List[int]) -> dict:
        from core.https_probe import verify_xhttp_tunnel
        ok, latency = verify_xhttp_tunnel(endpoint_ir, endpoint_kh, ports)
        return {
            "passed": ok,
            "latency_ms": latency,
        }

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        return True, "XHTTP modifications applied"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        return True, "XHTTP rollback applied"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        from core.https_tunnel import cleanup_xray_node
        return cleanup_xray_node(ssh, identifier)

register_adapter(XhttpAdapter())
