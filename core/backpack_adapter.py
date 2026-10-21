"""BackPack tunnel adapter implementing the unified BaseTunnelAdapter interface.

Full isolation of BackPack install, configuration, service management,
telemetry, modification, and cleanup into its own dedicated adapter.
"""
import shlex
import time
from typing import Dict, List, Tuple, Optional
from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.ssh_client import SSHManager
from core.tunnel import (
    build_iran_config,
    build_kharej_config,
    build_systemd_unit,
    generate_token,
    stop_and_remove_tunnel,
)
from core.validation import validate_tunnel_name, validate_port

class BackPackAdapter(BaseTunnelAdapter):
    def __init__(self):
        super().__init__("backpack")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        """Use the same verified local-only installer as legacy pools and TUNs."""
        return SSHManager.ensure_backpack_installed(ssh)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        """Generates configuration files and systemd service specifications."""
        tunnel_port = int(pool_config.get("tunnel_port", 443))
        transport = pool_config.get("transport", "pck")
        token = pool_config.get("token") or generate_token()
        client_ports = [str(p) for p in pool_config.get("client_ports", ["2222"])]
        node_name = iran_node.get("node_name") or f"bp_{iran_node['ip'].replace('.', '_')}"
        
        ir_cfg = build_iran_config(tunnel_port, transport, token, client_ports)
        kh_cfg = build_kharej_config(iran_node["ip"], tunnel_port, transport, token)
        unit = build_systemd_unit(node_name)

        return {
            "token": token,
            "transport": transport,
            "tunnel_port": tunnel_port,
            "iran_config": ir_cfg,
            "kharej_config": kh_cfg,
            "systemd_unit": unit,
            "service_name": f"backpack-{node_name}.service",
            "config_path": f"/etc/backpack/{node_name}.toml",
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = f"backpack-{identifier}.service" if not identifier.endswith(".service") else identifier
        cmd = f"systemctl daemon-reload && systemctl enable {svc} && systemctl restart {svc}"
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Failed to start {svc}: {err or out}"
        return True, f"Service {svc} started"

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = f"backpack-{identifier}.service" if not identifier.endswith(".service") else identifier
        cmd = f"systemctl stop {svc} && systemctl disable {svc}"
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Failed to stop {svc}: {err or out}"
        return True, f"Service {svc} stopped"

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = f"backpack-{identifier}.service" if not identifier.endswith(".service") else identifier
        ok, out, _ = ssh.execute(f"systemctl is-active {svc}")
        is_active = (ok == 0 and out.strip() == "active")
        return {
            "engine": "backpack",
            "service": svc,
            "is_active": is_active,
            "status": "UP" if is_active else "DOWN"
        }

    def probe(self, endpoint_ir: dict, endpoint_kh: dict, ports: List[int]) -> dict:
        from core.tunnel_probe import TunnelProbe
        # Use existing TunnelProbe for end-to-end verification
        probe_runner = TunnelProbe(endpoint_ir.get("ip", ""), ports)
        result = probe_runner.probe_tcp()
        return {
            "passed": result.get("all_passed", False),
            "details": result,
            "latency_ms": result.get("latency_ms", 0.0),
        }

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.transport_change import run_change
        # Delegates to transactional rolling transport change
        try:
            run_change(pool_name)
            return True, "Transport change completed"
        except Exception as e:
            return False, str(e)

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        return True, "Rollback handled by transport change state machine"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = f"backpack-{identifier}.service" if not identifier.endswith(".service") else identifier
        name = identifier.replace("backpack-", "").replace(".service", "")
        cfg = f"/etc/backpack/{name}.toml"
        unit = f"/etc/systemd/system/{svc}"
        
        cmd = f"systemctl stop {svc} 2>/dev/null; systemctl disable {svc} 2>/dev/null; rm -f {unit} {cfg}; systemctl daemon-reload"
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Failed cleaning backpack service {svc}: {err or out}"
        return True, f"Cleaned backpack resources for {identifier}"

# Automatically register BackPack adapter
register_adapter(BackPackAdapter())
