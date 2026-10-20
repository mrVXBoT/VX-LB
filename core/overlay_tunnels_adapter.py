"""Overlay Network Tunnel Adapters (VXLAN and Geneve) for LD-BP.

Coverage:
- VXLAN Single-Server & Multi-Server
- Geneve (RFC 8926) Single-Server & Multi-Server
- Geneve + IPsec
- Geneve + GRE6 Native IPv6 & IPv4 Carrier
"""
from typing import Dict, List, Tuple, Optional, Any
from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.ssh_client import SSHManager
from core.validation import validate_tunnel_name

class OverlayBaseAdapter(BaseTunnelAdapter):
    def __init__(self, engine_id: str, overlay_type: str, kernel_module: str, default_port: int):
        super().__init__(engine_id)
        self.overlay_type = overlay_type
        self.kernel_module = kernel_module
        self.default_port = default_port

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        cmd = f"modprobe {self.kernel_module} 2>/dev/null; modprobe bridge 2>/dev/null; which ip bridge"
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Prerequisites missing for {self.engine_id}: {err or out}"
        return True, f"Prerequisites for {self.engine_id} verified"

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        node_name = iran_node.get("node_name", f"{self.engine_id}_node")
        clean_name = validate_tunnel_name(node_name[:12])
        iface = f"{self.engine_id[:5]}-{clean_name}"
        vni = pool_config.get("vni", 1000)
        port = pool_config.get("dst_port", self.default_port)
        mtu = pool_config.get("mtu", self.capabilities.default_mtu)

        ir_ip = iran_node.get("ip")
        kh_ip = kharej_server.get("ip")
        peers = pool_config.get("peers", [kh_ip])

        return {
            "engine": self.engine_id,
            "type": self.overlay_type,
            "interface": iface,
            "vni": vni,
            "dst_port": port,
            "mtu": mtu,
            "local_ip": ir_ip,
            "remote_ip": kh_ip,
            "peers": peers,
            "service_name": f"ldbp-{iface}.service",
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"ldbp-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {svc} && systemctl restart {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"ldbp-{identifier}.service"
        cmd = f"systemctl stop {svc} && systemctl disable {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"ldbp-{identifier}.service"
        ok, out, _ = ssh.execute(f"systemctl is-active {svc}")
        is_active = (ok == 0 and out.strip() == "active")
        return {
            "engine": self.engine_id,
            "service": svc,
            "status": "UP" if is_active else "DOWN",
        }

    def probe(self, endpoint_ir: dict, endpoint_kh: dict, ports: List[int]) -> dict:
        return {
            "passed": False,
            "error": f"Active overlay data probe is unsupported/unimplemented for tunnel '{self.engine_id}'",
            "latency_ms": None
        }

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        return False, f"Dynamic modify is unsupported for overlay tunnel '{self.engine_id}'"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        return False, f"Rollback is unsupported for overlay tunnel '{self.engine_id}'"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("ldbp-", "").replace(".service", "")
        svc = f"ldbp-{iface}.service"
        cmd = f"systemctl stop {svc} 2>/dev/null; ip link del {iface} 2>/dev/null; rm -f /etc/systemd/system/{svc}; systemctl daemon-reload"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class VxlanAdapter(OverlayBaseAdapter):
    def __init__(self):
        super().__init__("vxlan", "vxlan", "vxlan", 4789)

class GeneveAdapter(OverlayBaseAdapter):
    def __init__(self):
        super().__init__("geneve", "geneve", "geneve", 6081)

class GeneveIpsecAdapter(BaseTunnelAdapter):
    def __init__(self):
        super().__init__("geneve_ipsec")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.geneve import install_agent
        try:
            install_agent(ssh)
            return True, "Geneve + IPsec prerequisites and agent verified"
        except Exception as err:
            return False, f"Geneve + IPsec install failed: {err}"

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.geneve import allocate
        node = allocate(
            iran_node,
            kharej_server,
            pool_config.get("client_ports", [443]),
            mtu=pool_config.get("mtu", self.capabilities.default_mtu),
            vni=pool_config.get("vni"),
        )
        conf = node["geneve"]["configs"][0]
        return {
            "engine": "geneve_ipsec",
            "type": "geneve",
            "interface": conf["interface"],
            "vni": conf["vni"],
            "dst_port": conf.get("dst_port", 6081),
            "mtu": conf["mtu"],
            "local_ip": conf["local"],
            "remote_ip": conf["remote"],
            "private_ip": conf["private"],
            "peer_private_ip": conf["peer"],
            "security": conf["security"],
            "service_name": f"ldbp-geneve-{conf['interface']}.service",
            "node": node,
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"ldbp-geneve-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {svc} && systemctl restart {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"ldbp-geneve-{identifier}.service"
        cmd = f"systemctl stop {svc} && systemctl disable {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"ldbp-geneve-{identifier}.service"
        iface = identifier.replace("ldbp-geneve-", "").replace(".service", "").replace("-relay", "")
        ok, out, _ = ssh.execute(f"systemctl is-active {svc}")
        is_active = (ok == 0 and out.strip() == "active")
        return {
            "engine": "geneve_ipsec",
            "service": svc,
            "interface": iface,
            "status": "UP" if is_active else "DOWN",
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.geneve import verify_geneve_tunnel
        ok, latency = verify_geneve_tunnel(endpoint_ir, endpoint_kh, ports)
        return {
            "passed": ok,
            "latency_ms": latency,
            "error": "" if ok else "Geneve + IPsec probe failed",
        }

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.geneve import change_mtu, change_ports
        if "mtu" in updates:
            return change_mtu(pool_name, int(updates["mtu"]))
        if "ports" in updates:
            return change_ports(pool_name, updates["ports"])
        return True, "No modifications required"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.geneve import rollback_mtu
        if "mtu" in previous_state:
            return rollback_mtu(pool_name, int(previous_state["mtu"]))
        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        from core.geneve import cleanup_geneve_node
        return cleanup_geneve_node(ssh, identifier)


class GeneveGre6Adapter(OverlayBaseAdapter):
    def __init__(self):
        super().__init__("geneve_gre6", "geneve", "geneve", 6081)

for cls in [VxlanAdapter, GeneveAdapter, GeneveIpsecAdapter, GeneveGre6Adapter]:
    register_adapter(cls())
