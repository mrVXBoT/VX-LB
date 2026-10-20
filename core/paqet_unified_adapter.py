"""Paqet tunnel adapter implementing BaseTunnelAdapter.

Standardizes Paqet adapter into the universal registry with
complete operational lifecycle management, fail-closed semantics, and integration
with core/paqet_adapter.py.
"""
import shlex
from typing import Dict, List, Tuple, Optional, Any
from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.ssh_client import SSHManager


class PaqetUnifiedAdapter(BaseTunnelAdapter):
    def __init__(self):
        super().__init__("paqet")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        """Installs Paqet binary and verifies prerequisites."""
        if not ssh or not hasattr(ssh, "execute"):
            return False, "SSH connection required for Paqet installation"
        from core.paqet_adapter import install_paqet
        return install_paqet(ssh, role, config)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        """Generates configuration files and systemd specifications for Paqet."""
        if not iran_node or not kharej_server or not isinstance(iran_node, dict) or not isinstance(kharej_server, dict):
            raise NotImplementedError("Paqet unified configuration requires valid node and server definitions")
        if "ip" not in iran_node or "ip" not in kharej_server:
            raise NotImplementedError("Paqet unified configuration requires node and server IP addresses")

        from core.paqet_adapter import PaqetAdapter, generate_paqet_secret, DEFAULT_PAQET_BIN
        adapter = PaqetAdapter(paqet_bin=pool_config.get("binary") or DEFAULT_PAQET_BIN)
        tunnel_port = int(pool_config.get("tunnel_port") or pool_config.get("port") or 9999)
        secret = pool_config.get("secret_key") or generate_paqet_secret()
        node_name = iran_node.get("node_name") or f"paq_{iran_node['ip'].replace('.', '_')}"
        cipher = pool_config.get("cipher", "aes-128-gcm")
        kcp_mode = pool_config.get("kcp_mode", "fast")
        client_ports = pool_config.get("client_ports", ["2222"])
        forwards = [{"listen": f"0.0.0.0:{p}", "target": f"{kharej_server['ip']}:{p}", "protocol": protocol} for p in client_ports for protocol in ("tcp", "udp")]

        srv_cfg, srv_yaml = adapter.build_server_config(
            listen_port=tunnel_port,
            interface=kharej_server.get("interface", "eth0"),
            server_ip=kharej_server["ip"],
            router_mac=kharej_server.get("router_mac", "00:00:00:00:00:00"),
            secret_key=secret,
            cipher=cipher,
            kcp_mode=kcp_mode,
        )
        clt_cfg, clt_yaml = adapter.build_client_config(
            server_ip=kharej_server["ip"],
            server_port=tunnel_port,
            interface=iran_node.get("interface", "eth0"),
            client_ip=iran_node["ip"],
            router_mac=iran_node.get("router_mac", "00:00:00:00:00:00"),
            secret_key=secret,
            forward_rules=forwards,
            cipher=cipher,
            kcp_mode=kcp_mode,
        )
        unit = adapter.build_systemd_unit(node_name)
        return {
            "engine": "paqet",
            "node_name": node_name,
            "tunnel_port": tunnel_port,
            "secret_key": secret,
            "service_name": f"paqet-{node_name}.service",
            "systemd_unit": unit,
            "server_config": srv_cfg,
            "server_yaml": srv_yaml,
            "client_config": clt_cfg,
            "client_yaml": clt_yaml,
            "config_path": f"/etc/paqet/{node_name}.yaml",
            "forward_rules": forwards,
        }

    def start(self, ssh: SSHManager, identifier: Any) -> Tuple[bool, str]:
        """Starts Paqet systemd service."""
        if not ssh or not hasattr(ssh, "execute"):
            return False, "SSH connection required"
        svc = str(identifier) if str(identifier).endswith(".service") else f"paqet-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: Any) -> Tuple[bool, str]:
        """Stops and disables Paqet systemd service."""
        if not ssh or not hasattr(ssh, "execute"):
            return False, "SSH connection required"
        svc = str(identifier) if str(identifier).endswith(".service") else f"paqet-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: Any) -> dict:
        """Queries Paqet service status."""
        if not ssh or not hasattr(ssh, "execute"):
            return {"engine": "paqet", "service": str(identifier), "status": "DOWN", "error": "SSH connection required"}
        svc = str(identifier) if str(identifier).endswith(".service") else f"paqet-{identifier}.service"
        ok, out, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok == 0 and out.strip() == "active")
        return {
            "engine": "paqet",
            "service": svc,
            "status": "UP" if is_active else "DOWN"
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        """Verifies active status and data plane connectivity."""
        from core.paqet_adapter import verify
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh
        node = kwargs.get("node") or (endpoint_ir if isinstance(endpoint_ir, dict) and "node_name" in endpoint_ir else {})
        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute") or not node.get("node_name"):
            return {"passed": False, "reason": "Paqet probe requires connected SSH endpoints and valid node configuration"}
        try:
            result = verify(iran_ssh, kharej_ssh, node, ports)
            return {"passed": True, "latency_ms": result["latency_ms"], "reason": "TCP/UDP challenge crossed the Paqet forward mapping"}
        except Exception as e:
            return {"passed": False, "reason": str(e)}

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        """Modifies forwarded ports with transactional update."""
        from core.paqet_adapter import change_ports
        if not updates or "ports" not in updates:
            return False, "Paqet unified modification requires 'ports' parameter"
        return change_ports(pool_name, updates["ports"])

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        """Rolls back forwarded ports upon failure."""
        from core.paqet_adapter import change_ports
        if not previous_state or "ports" not in previous_state:
            return False, "Paqet unified rollback requires previous 'ports' state"
        return change_ports(pool_name, previous_state["ports"], recovery=True)

    def clean(self, ssh: SSHManager, identifier: Any) -> Tuple[bool, str]:
        """Tears down Paqet tunnel resources."""
        if not ssh or not hasattr(ssh, "execute"):
            return False, "SSH connection required for cleanup"
        from core.paqet_adapter import clean
        return clean(ssh, identifier, iran=True)


register_adapter(PaqetUnifiedAdapter())
