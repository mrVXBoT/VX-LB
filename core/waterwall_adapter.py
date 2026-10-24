"""WaterWall tunnel adapter implementing BaseTunnelAdapter.

Standardizes WaterWall adapter into the universal registry.
Integrates with core/waterwall.py for chain generation, service units,
active probe verification, port modification, and rollback.
"""
import copy
import re
import secrets
import uuid
from typing import Dict, List, Tuple, Optional, Any
from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.ssh_client import SSHManager

class WaterWallAdapter(BaseTunnelAdapter):
    def __init__(self):
        super().__init__("waterwall")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.waterwall import install_waterwall
        return install_waterwall(ssh, role, config)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.waterwall import chain_configs, core_config, service, path, unit, DIRECTORY, profile as waterwall_profile
        from core.waterwall_modes import default_settings

        node = copy.deepcopy(iran_node)
        node_name = node.get("node_name")
        if not node_name or not re.fullmatch(r"ldw[0-9a-f]{16}", str(node_name)):
            node["node_name"] = "ldw" + secrets.token_hex(8)
        if "ip" not in node:
            node["ip"] = "127.0.0.1"

        raw_profile = dict(pool_config.get("camouflage") or pool_config.get("profile") or {})
        mode = str(raw_profile.get("mode") or pool_config.get("waterwall_mode") or "trojan")
        merged = default_settings(mode)
        merged.update({k: v for k, v in raw_profile.items() if v is not None})
        prof = waterwall_profile(mode, merged)

        ports = pool_config.get("client_ports", ["2222"])
        outer_port = pool_config.get("tunnel_port", prof.get("port", 443))

        # Independent probe ingress port (strictly loopback-only on Iran) separate from client_ports
        client_ports_set = set(int(p) for p in ports)
        probe_ingress_port = pool_config.get("probe_port") or (iran_node.get("waterwall") or {}).get("probe_port")
        if not probe_ingress_port or int(probe_ingress_port) in client_ports_set:
            probe_candidate = 31000
            while probe_candidate in client_ports_set or probe_candidate == int(outer_port):
                probe_candidate += 1
            probe_ingress_port = probe_candidate
        probe_ingress_port = int(probe_ingress_port)

        # Independent probe backend port (destination on Kharej where echo responder listens)
        probe_backend_port = pool_config.get("probe_backend_port") or (iran_node.get("waterwall") or {}).get("probe_backend_port")
        if not probe_backend_port:
            probe_candidate = 32000
            while probe_candidate in client_ports_set or probe_candidate == int(outer_port) or probe_candidate == probe_ingress_port:
                probe_candidate += 1
            probe_backend_port = probe_candidate
        probe_backend_port = int(probe_backend_port)

        backend_port = int(pool_config.get("backend_port") or (ports[0] if ports else 2222))

        if "waterwall" not in node:
            node["waterwall"] = {
                "profile": copy.deepcopy(prof),
                "outer_port": int(outer_port),
                "probe_port": probe_ingress_port,
                "probe_ingress_port": probe_ingress_port,
                "probe_backend_port": probe_backend_port,
                "backend_port": backend_port
            }
        else:
            node["waterwall"].setdefault("outer_port", int(outer_port))
            node["waterwall"]["probe_port"] = probe_ingress_port
            node["waterwall"]["probe_ingress_port"] = probe_ingress_port
            node["waterwall"]["probe_backend_port"] = probe_backend_port
            node["waterwall"].setdefault("backend_port", backend_port)
            node["waterwall"].setdefault("profile", copy.deepcopy(prof))

        kharej_ip = kharej_server.get("ip", "127.0.0.1")
        iran_chain, kharej_chain = chain_configs(node, kharej_ip, ports)
        chain_file = f"{DIRECTORY}/chain-{node['node_name']}.json"

        iran_core = core_config(chain_file)
        kharej_core = core_config(chain_file)

        return {
            "engine": "waterwall",
            "node": node,
            "node_name": node["node_name"],
            "service_name": unit(node),
            "config_path": path(node),
            "systemd_unit": service(node),
            "iran_chain": iran_chain,
            "kharej_chain": kharej_chain,
            "iran_core_config": iran_core,
            "kharej_core_config": kharej_core,
            "core_config": iran_core,
            "probe_port": probe_ingress_port,
            "probe_ingress_port": probe_ingress_port,
            "probe_backend_port": probe_backend_port,
            "backend_port": backend_port,
            "client_ports": ports
        }

    @staticmethod
    def _resolve_service_name(identifier: Any) -> str:
        if isinstance(identifier, dict):
            if "service_name" in identifier:
                return identifier["service_name"]
            if "node_name" in identifier:
                return f"{identifier['node_name']}.service"
            if "node" in identifier and isinstance(identifier["node"], dict):
                node_name = identifier["node"].get("node_name", "")
                if node_name:
                    return f"{node_name}.service"
        svc = str(identifier)
        if not svc.endswith(".service"):
            svc = f"{svc}.service"
        return svc

    def start(self, ssh: SSHManager, identifier: Any) -> Tuple[bool, str]:
        svc = self._resolve_service_name(identifier)
        cmd = f"systemctl daemon-reload && systemctl enable {svc} && systemctl restart {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: Any) -> Tuple[bool, str]:
        svc = self._resolve_service_name(identifier)
        cmd = f"systemctl stop {svc} && systemctl disable {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: Any) -> dict:
        svc = self._resolve_service_name(identifier)
        ok, out, _ = ssh.execute(f"systemctl is-active {svc}")
        is_active = (ok == 0 and out.strip() == "active")
        return {
            "engine": "waterwall",
            "service": svc,
            "status": "UP" if is_active else "DOWN"
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, node: Optional[dict] = None, **kwargs) -> dict:
        from core.waterwall import verify
        try:
            # Resolve SSH connection handles
            iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
            kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

            # Resolve target node
            target_node = node
            if target_node is None and isinstance(endpoint_ir, dict):
                if "node" in endpoint_ir:
                    target_node = endpoint_ir["node"]
                elif "waterwall" in endpoint_ir:
                    target_node = endpoint_ir

            # Auto-resolve ports from configured node if not explicitly provided
            if ports is None and target_node and "waterwall" in target_node:
                bp = target_node["waterwall"].get("backend_port") or target_node["waterwall"].get("probe_port")
                if bp is not None:
                    ports = [int(bp)]

            if hasattr(iran_ssh, "execute") and hasattr(kharej_ssh, "execute") and target_node and "waterwall" in target_node:
                verify(iran_ssh, kharej_ssh, target_node, ports)
                return {"passed": True, "latency_ms": 1.0, "error": None}
            return {
                "passed": False,
                "error": "WaterWall probe requires Iran SSH, Kharej SSH, and target node configuration with 'waterwall' profile",
                "latency_ms": None
            }
        except Exception as e:
            return {"passed": False, "error": str(e), "latency_ms": None}

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.waterwall import change_ports
        if "ports" in updates:
            return change_ports(pool_name, updates["ports"])
        return False, "Unsupported modification for WaterWall (only 'ports' supported)"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.waterwall import change_ports
        if "ports" in previous_state:
            return change_ports(pool_name, previous_state["ports"], recovery=True)
        return False, "Rollback failed: previous ports not provided"

    def clean(self, ssh: SSHManager, identifier: Any) -> Tuple[bool, str]:
        from core.waterwall import clean
        if isinstance(identifier, dict):
            node = identifier.get("node", identifier)
        else:
            name = str(identifier).replace(".service", "").replace("vxlb-waterwall-", "")
            node = {"node_name": name}
        try:
            clean(ssh, node, iran=True)
            return True, f"Cleaned WaterWall node {node['node_name']}"
        except Exception as e:
            return False, f"Failed to clean WaterWall node: {e}"

register_adapter(WaterWallAdapter())
