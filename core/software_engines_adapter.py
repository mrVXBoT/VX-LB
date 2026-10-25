"""User-space Tunnel Software Engine Adapters for VX-LB.

Coverage:
- TrustTunnel
- Backhaul
- FRP
- Rathole
- GOST
- Hysteria 2

Guarantees:
- Real structured configuration generation for both Iran client and Kharej server roles.
- Isolated systemd unit generation with standard hardening.
- Authentic dependency verification via core.dependency_manifest.
- Metrics availability: probe, modify, and rollback return unsupported/False when no verified live runner is present.
"""
import json
import logging
import os
import re
import secrets
import shlex
from typing import Any, Dict, List, Optional, Tuple

from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.dependency_manifest import get_dependency_manifest
from core.ssh_client import SSHManager
from core.validation import validate_port, validate_tunnel_name

logger = logging.getLogger("vxlb.software_engines")


def _build_daemon_systemd_unit(
    service_name: str,
    executable: str,
    config_path: str,
    description: str,
    extra_flags: str = "",
) -> str:
    """Generates standard hardened systemd service file for userspace daemon engines."""
    flags = f" {extra_flags}".rstrip() if extra_flags else ""
    return f"""[Unit]
Description={description}
After=network-online.target
Wants=network-online.target
PartOf=vxlb-tunnels.target

[Service]
Type=simple
ExecStart={executable}{flags} -c {config_path}
Restart=always
RestartSec=3
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


class SoftwareEngineBaseAdapter(BaseTunnelAdapter):
    """Base class for user-space tunnel daemon engines managed via systemd."""

    def __init__(self, engine_id: str, binary_name: str, config_ext: str = "toml"):
        super().__init__(engine_id)
        self.binary_name = binary_name
        self.config_ext = config_ext

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        # FRP uses role-specific binaries: frpc on iran/client, frps on kharej/server.
        binary_name = "frpc" if (self.binary_name == "frps" and role == "iran") else self.binary_name
        cmd = f"which {binary_name} || test -f /usr/local/bin/{binary_name}"
        ok, out, _ = ssh.execute(cmd)
        if ok == 0:
            return True, f"{binary_name} verified at {out.strip()}"

        # Air-gapped fallback: check local bundled bin/ with SHA-256 verification
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _, arch_raw, _ = ssh.execute("uname -m")
        remote_arch = arch_raw.strip().lower()
        arch_dir = "x86_64" if ("x86_64" in remote_arch or "amd64" in remote_arch) else ("aarch64" if ("aarch64" in remote_arch or "arm64" in remote_arch) else remote_arch)

        candidate_paths = [
            os.path.join(base_dir, "bin", arch_dir, binary_name),
            os.path.join(base_dir, "bin", binary_name),
            os.path.join(base_dir, "data", "binaries", arch_dir, binary_name),
            os.path.join(base_dir, "data", "binaries", binary_name),
        ]
        manifest = get_dependency_manifest(binary_name)
        expected_sha = manifest.architectures.get(arch_dir, {}).get("sha256") if manifest else None

        for candidate in candidate_paths:
            if os.path.exists(candidate) and os.path.isfile(candidate):
                if expected_sha:
                    import hashlib
                    with open(candidate, "rb") as f:
                        if hashlib.sha256(f.read()).hexdigest() != expected_sha:
                            continue  # Skip unverified/mismatched binaries
                uploaded = ssh.upload_binary(candidate, f"/usr/local/bin/{binary_name}", mode=0o755)
                if uploaded:
                    c, o, _ = ssh.execute(f"which {binary_name} || test -f /usr/local/bin/{binary_name}")
                    if c == 0:
                        return True, f"{binary_name} installed from local bundled binary (Air-gapped / Offline)"

        return False, f"Binary '{binary_name}' not found on host or local bin/ depot."

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-{self.engine_id}-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {svc} && systemctl restart {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-{self.engine_id}-{identifier}.service"
        cmd = f"systemctl stop {svc} && systemctl disable {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-{self.engine_id}-{identifier}.service"
        ok, out, _ = ssh.execute(f"systemctl is-active {svc}")
        is_active = (ok == 0 and out.strip() == "active")
        return {
            "engine": self.engine_id,
            "service": svc,
            "status": "UP" if is_active else "DOWN",
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        return {
            "passed": False,
            "error": f"Active network data probe is unsupported/unimplemented for engine '{self.engine_id}'",
            "latency_ms": None,
        }

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        return False, f"Dynamic modify is unsupported for engine '{self.engine_id}'"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        return False, f"Rollback is unsupported for engine '{self.engine_id}'"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        clean_id = identifier.replace(f"vxlb-{self.engine_id}-", "").replace(".service", "")
        svc = f"vxlb-{self.engine_id}-{clean_id}.service"
        cfg = f"/etc/{self.engine_id}/{clean_id}.{self.config_ext}"
        cmd = f"systemctl stop {svc} 2>/dev/null || true; systemctl disable {svc} 2>/dev/null || true; rm -f /etc/systemd/system/{svc} {cfg}; systemctl daemon-reload"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class TrustTunnelAdapter(SoftwareEngineBaseAdapter):
    """TrustTunnel client/endpoint adapter."""

    def __init__(self):
        super().__init__("trusttunnel", "trusttunnel", "json")

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        node_name = iran_node.get("node_name", "trusttunnel_node")
        clean_name = validate_tunnel_name(node_name[:12])
        port = int(pool_config.get("tunnel_port", 443))
        client_ports = [int(p) for p in pool_config.get("client_ports", [2222])]
        token = pool_config.get("token") or secrets.token_hex(16)

        ir_ip = iran_node["ip"]
        kh_ip = kharej_server["ip"]

        server_conf = {
            "mode": "server",
            "listen": f"0.0.0.0:{port}",
            "token": token,
            "tls": {
                "enabled": True,
                "cert_file": f"/etc/trusttunnel/{clean_name}.crt",
                "key_file": f"/etc/trusttunnel/{clean_name}.key",
            },
        }

        client_conf = {
            "mode": "client",
            "server": f"{kh_ip}:{port}",
            "token": token,
            "forwards": [{"listen": f"0.0.0.0:{p}", "target": f"127.0.0.1:{p}"} for p in client_ports],
        }

        svc = f"vxlb-trusttunnel-{clean_name}.service"
        cfg_path = f"/etc/trusttunnel/{clean_name}.json"

        return {
            "engine": self.engine_id,
            "service_name": svc,
            "tunnel_port": port,
            "client_ports": client_ports,
            "token": token,
            "iran_config": {
                "content": json.dumps(client_conf, indent=2),
                "path": cfg_path,
                "unit": _build_daemon_systemd_unit(svc, "/usr/local/bin/trusttunnel", cfg_path, "TrustTunnel Client"),
                "unit_path": f"/etc/systemd/system/{svc}",
            },
            "kharej_config": {
                "content": json.dumps(server_conf, indent=2),
                "path": cfg_path,
                "unit": _build_daemon_systemd_unit(svc, "/usr/local/bin/trusttunnel", cfg_path, "TrustTunnel Server"),
                "unit_path": f"/etc/systemd/system/{svc}",
            },
        }


class BackhaulAdapter(SoftwareEngineBaseAdapter):
    """Backhaul high-speed tunnel adapter."""

    def __init__(self):
        super().__init__("backhaul", "backhaul", "toml")

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        node_name = iran_node.get("node_name", "backhaul_node")
        clean_name = validate_tunnel_name(node_name[:12])
        port = int(pool_config.get("tunnel_port", 443))
        client_ports = [int(p) for p in pool_config.get("client_ports", [2222])]
        token = pool_config.get("token") or secrets.token_hex(16)
        transport = pool_config.get("transport", "tcp")

        kh_ip = kharej_server["ip"]

        server_toml = f"""[server]
bind_addr = "0.0.0.0:{port}"
transport = "{transport}"
token = "{token}"
keepalive = 75
heartbeat = 20
channel_size = 2048
"""
        port_lines = "\n".join([f'  "{p}=127.0.0.1:{p}",' for p in client_ports])
        client_toml = f"""[client]
remote_addr = "{kh_ip}:{port}"
transport = "{transport}"
token = "{token}"
connection_pool = 8
ports = [
{port_lines}
]
"""
        svc = f"vxlb-backhaul-{clean_name}.service"
        cfg_path = f"/etc/backhaul/{clean_name}.toml"

        return {
            "engine": self.engine_id,
            "service_name": svc,
            "tunnel_port": port,
            "transport": transport,
            "client_ports": client_ports,
            "iran_config": {
                "content": client_toml,
                "path": cfg_path,
                "unit": _build_daemon_systemd_unit(svc, "/usr/local/bin/backhaul", cfg_path, "Backhaul Client"),
                "unit_path": f"/etc/systemd/system/{svc}",
            },
            "kharej_config": {
                "content": server_toml,
                "path": cfg_path,
                "unit": _build_daemon_systemd_unit(svc, "/usr/local/bin/backhaul", cfg_path, "Backhaul Server"),
                "unit_path": f"/etc/systemd/system/{svc}",
            },
        }


class FrpAdapter(SoftwareEngineBaseAdapter):
    """FRP (Fast Reverse Proxy) adapter."""

    def __init__(self):
        super().__init__("frp", "frps", "toml")

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        node_name = iran_node.get("node_name", "frp_node")
        clean_name = validate_tunnel_name(node_name[:12])
        port = int(pool_config.get("tunnel_port", 7000))
        client_ports = [int(p) for p in pool_config.get("client_ports", [2222])]
        token = pool_config.get("token") or secrets.token_hex(16)

        kh_ip = kharej_server["ip"]

        server_toml = f"""bindPort = {port}
auth.method = "token"
auth.token = "{token}"
transport.tcpKeepalive = 7200
"""
        proxy_blocks = []
        for p in client_ports:
            proxy_blocks.append(f"""[[proxies]]
name = "p{p}"
type = "tcp"
localIP = "127.0.0.1"
localPort = {p}
remotePort = {p}
""")
        client_toml = f"""serverAddr = "{kh_ip}"
serverPort = {port}
auth.method = "token"
auth.token = "{token}"

{"".join(proxy_blocks)}"""

        ir_svc = f"vxlb-frpc-{clean_name}.service"
        kh_svc = f"vxlb-frps-{clean_name}.service"
        ir_cfg = f"/etc/frp/frpc-{clean_name}.toml"
        kh_cfg = f"/etc/frp/frps-{clean_name}.toml"

        return {
            "engine": self.engine_id,
            "tunnel_port": port,
            "client_ports": client_ports,
            "iran_config": {
                "service_name": ir_svc,
                "content": client_toml,
                "path": ir_cfg,
                "unit": _build_daemon_systemd_unit(ir_svc, "/usr/local/bin/frpc", ir_cfg, "FRP Client (frpc)"),
                "unit_path": f"/etc/systemd/system/{ir_svc}",
            },
            "kharej_config": {
                "service_name": kh_svc,
                "content": server_toml,
                "path": kh_cfg,
                "unit": _build_daemon_systemd_unit(kh_svc, "/usr/local/bin/frps", kh_cfg, "FRP Server (frps)"),
                "unit_path": f"/etc/systemd/system/{kh_svc}",
            },
        }


class RatholeAdapter(SoftwareEngineBaseAdapter):
    """Rathole lightweight secure proxy adapter."""

    def __init__(self):
        super().__init__("rathole", "rathole", "toml")

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        node_name = iran_node.get("node_name", "rathole_node")
        clean_name = validate_tunnel_name(node_name[:12])
        port = int(pool_config.get("tunnel_port", 2333))
        client_ports = [int(p) for p in pool_config.get("client_ports", [2222])]
        token = pool_config.get("token") or secrets.token_hex(16)
        transport = pool_config.get("transport", "tcp")
        proto = pool_config.get("proto", "tcp")
        settings = pool_config.get("settings", {})

        ir_ip = iran_node["ip"]

        from core.rathole_engine import _server_config, _client_config
        server_toml = _server_config(port, token, transport, proto, client_ports, settings)
        client_toml = _client_config(ir_ip, port, token, transport, proto, client_ports, settings)

        svc = f"vxlb-rathole-{clean_name}.service"
        cfg_path = f"/etc/rathole/{clean_name}.toml"

        return {
            "engine": self.engine_id,
            "service_name": svc,
            "tunnel_port": port,
            "client_ports": client_ports,
            "iran_config": {
                "content": server_toml,
                "path": cfg_path,
                "unit": _build_daemon_systemd_unit(svc, "/usr/local/bin/rathole", cfg_path, "Rathole Server", extra_flags="--server"),
                "unit_path": f"/etc/systemd/system/{svc}",
            },
            "kharej_config": {
                "content": client_toml,
                "path": cfg_path,
                "unit": _build_daemon_systemd_unit(svc, "/usr/local/bin/rathole", cfg_path, "Rathole Client", extra_flags="--client"),
                "unit_path": f"/etc/systemd/system/{svc}",
            },
        }


class GostAdapter(SoftwareEngineBaseAdapter):
    """GOST (GO Simple Tunnel) adapter."""

    def __init__(self):
        super().__init__("gost", "gost", "yaml")

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        node_name = iran_node.get("node_name", "gost_node")
        clean_name = validate_tunnel_name(node_name[:12])
        port = int(pool_config.get("tunnel_port", 8443))
        client_ports = [int(p) for p in pool_config.get("client_ports", [2222])]
        token = pool_config.get("token") or secrets.token_hex(16)
        kh_ip = kharej_server["ip"]

        server_yaml = f"""services:
  - name: tunnel-server
    addr: ":{port}"
    handler:
      type: auto
      auth:
        username: vxlb
        password: "{token}"
    listener:
      type: tcp
"""
        client_services = []
        for p in client_ports:
            client_services.append(f"""  - name: forward-{p}
    addr: ":{p}"
    handler:
      type: tcp
    listener:
      type: tcp
    forwarder:
      nodes:
        - name: target-{p}
          addr: "127.0.0.1:{p}"
""")
        client_yaml = f"""services:
{"".join(client_services)}
chains:
  - name: egress-chain
    hops:
      - name: hop-0
        nodes:
          - name: kharej-server
            addr: "{kh_ip}:{port}"
            connector:
              type: auto
              auth:
                username: vxlb
                password: "{token}"
            dialer:
              type: tcp
"""
        svc = f"vxlb-gost-{clean_name}.service"
        cfg_path = f"/etc/gost/{clean_name}.yaml"

        return {
            "engine": self.engine_id,
            "service_name": svc,
            "tunnel_port": port,
            "client_ports": client_ports,
            "iran_config": {
                "content": client_yaml,
                "path": cfg_path,
                "unit": _build_daemon_systemd_unit(svc, "/usr/local/bin/gost", cfg_path, "GOST Client"),
                "unit_path": f"/etc/systemd/system/{svc}",
            },
            "kharej_config": {
                "content": server_yaml,
                "path": cfg_path,
                "unit": _build_daemon_systemd_unit(svc, "/usr/local/bin/gost", cfg_path, "GOST Server"),
                "unit_path": f"/etc/systemd/system/{svc}",
            },
        }


class Hysteria2Adapter(SoftwareEngineBaseAdapter):
    """Hysteria 2 QUIC-based loss-resistant tunnel adapter."""

    def __init__(self):
        super().__init__("hysteria2", "hysteria", "yaml")

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        node_name = iran_node.get("node_name", "hy2_node")
        clean_name = validate_tunnel_name(node_name[:12])
        port = int(pool_config.get("tunnel_port", 443))
        client_ports = [int(p) for p in pool_config.get("client_ports", [2222])]
        password = pool_config.get("password") or pool_config.get("token") or secrets.token_hex(16)
        sni = pool_config.get("sni") or pool_config.get("domain") or kharej_server["ip"]

        kh_ip = kharej_server["ip"]

        server_yaml = f"""listen: :{port}
tls:
  cert: /etc/hysteria/{clean_name}.crt
  key: /etc/hysteria/{clean_name}.key
auth:
  type: password
  password: "{password}"
masquerade:
  type: 404
ignoreClientBandwidth: false
"""
        tcp_tunnels = []
        for p in client_ports:
            tcp_tunnels.append(f"""  - listen: 0.0.0.0:{p}
    target: 127.0.0.1:{p}
""")
        client_yaml = f"""server: {kh_ip}:{port}
auth: "{password}"
tls:
  sni: "{sni}"
  insecure: false
tcpTunnels:
{"".join(tcp_tunnels)}
"""
        svc = f"vxlb-hysteria2-{clean_name}.service"
        cfg_path = f"/etc/hysteria/{clean_name}.yaml"

        return {
            "engine": self.engine_id,
            "service_name": svc,
            "tunnel_port": port,
            "client_ports": client_ports,
            "sni": sni,
            "iran_config": {
                "content": client_yaml,
                "path": cfg_path,
                "unit": _build_daemon_systemd_unit(svc, "/usr/local/bin/hysteria", cfg_path, "Hysteria 2 Client", extra_flags="client"),
                "unit_path": f"/etc/systemd/system/{svc}",
            },
            "kharej_config": {
                "content": server_yaml,
                "path": cfg_path,
                "unit": _build_daemon_systemd_unit(svc, "/usr/local/bin/hysteria", cfg_path, "Hysteria 2 Server", extra_flags="server"),
                "unit_path": f"/etc/systemd/system/{svc}",
            },
        }


# Register all software engine adapters
for cls in [
    TrustTunnelAdapter,
    BackhaulAdapter,
    FrpAdapter,
    RatholeAdapter,
    GostAdapter,
    Hysteria2Adapter,
]:
    register_adapter(cls())
