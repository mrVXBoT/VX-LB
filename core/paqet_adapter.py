"""
Paqet Adapter for VX-LB.

Provides configuration generation, firewall rule synthesis, systemd unit definitions,
and deployment lifecycle management for the Paqet raw-packet KCP proxy.

Upstream reference: https://github.com/hanselime/paqet
Target version: v1.0.0-alpha.21+
"""

import copy
import json
import os
import re
import secrets
import shlex
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import yaml

from core.ssh_client import SSHManager
from core.storage import get_pools, save_pool, delete_pool, atomic_update
from core.validation import (
    shquote,
    validate_port,
    validate_ports,
    validate_tunnel_name,
    validate_pool_name,
)

# Supported block ciphers for transport.kcp.block
SUPPORTED_CIPHERS = {
    "aes",
    "aes-128",
    "aes-128-gcm",
    "aes-192",
    "salsa20",
    "blowfish",
    "twofish",
    "cast5",
    "3des",
    "tea",
    "xtea",
    "xor",
    "sm4",
    "none",
    "null",
}

# Supported KCP operational modes
SUPPORTED_KCP_MODES = {"normal", "fast", "fast2", "fast3", "manual"}

# Valid TCP flag patterns for raw packet crafting
VALID_TCP_FLAGS = {"S", "A", "PA", "F", "R", "FA", "SA", "RA"}

_INTERFACE_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,32}$")
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$")


def validate_interface(iface: str) -> str:
    """Validates Linux network interface name (e.g. eth0, ens3, enx...)."""
    clean = str(iface).strip()
    if not _INTERFACE_RE.fullmatch(clean):
        raise ValueError(f"Invalid interface name {iface!r}")
    return clean


def validate_mac(mac: str) -> str:
    """Validates IEEE 802 MAC address format (e.g. aa:bb:cc:dd:ee:ff)."""
    clean = str(mac).strip().lower().replace("-", ":")
    if not _MAC_RE.fullmatch(clean):
        raise ValueError(f"Invalid MAC address {mac!r}")
    return clean


def validate_cipher(cipher: str) -> str:
    """Validates KCP block encryption cipher."""
    clean = str(cipher).strip().lower()
    if clean not in SUPPORTED_CIPHERS:
        raise ValueError(
            f"Unsupported cipher {cipher!r}. Supported: {sorted(SUPPORTED_CIPHERS)}"
        )
    return clean


def validate_kcp_mode(mode: str) -> str:
    """Validates KCP acceleration mode."""
    clean = str(mode).strip().lower()
    if clean not in SUPPORTED_KCP_MODES:
        raise ValueError(
            f"Unsupported KCP mode {mode!r}. Supported: {sorted(SUPPORTED_KCP_MODES)}"
        )
    return clean


def validate_tcp_flags(flags: List[str]) -> List[str]:
    """Validates list of TCP flags for cycling."""
    if not flags:
        return ["PA"]
    cleaned = []
    for f in flags:
        f_clean = str(f).strip().upper()
        if f_clean not in VALID_TCP_FLAGS:
            raise ValueError(
                f"Invalid TCP flag {f!r}. Allowed: {sorted(VALID_TCP_FLAGS)}"
            )
        cleaned.append(f_clean)
    return cleaned


def generate_paqet_secret(length: int = 64) -> str:
    """
    Generates a cryptographically secure hex secret key (default 32 bytes = 64 hex chars),
    matching `paqet secret` output format.
    """
    return secrets.token_hex(length // 2)


def parse_gateway_route(route_output: str, neigh_output: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Parses `ip route show default` and `ip neigh show` output.
    Returns (interface, gateway_ip, gateway_mac).
    """
    # Example: default via 192.168.8.1 dev enx0c5b8f279a64 proto dhcp src 192.168.8.100 metric 100
    iface = None
    gateway_ip = None
    mac = None

    match_route = re.search(r"default via (\d+\.\d+\.\d+\.\d+) dev ([a-zA-Z0-9_\-\.]+)", route_output)
    if match_route:
        gateway_ip = match_route.group(1)
        iface = match_route.group(2)

    if gateway_ip:
        # Look for gateway IP in neighbor table: 192.168.8.1 dev enx0c5b8f279a64 lladdr ac:bd:70:b5:b4:90 REACHABLE
        match_neigh = re.search(
            r"(?:^|\n)\s*" + re.escape(gateway_ip) + r"\s+.*?lladdr\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})",
            neigh_output,
        )
        if match_neigh:
            mac = match_neigh.group(1).lower()

    return iface, gateway_ip, mac


def build_forward_rule(listen: str, target: str, protocol: str = "tcp") -> Dict[str, str]:
    """
    Builds and validates a port forwarding rule supporting TCP and UDP.
    """
    proto = str(protocol).strip().lower()
    if proto not in ("tcp", "udp"):
        raise ValueError(f"Invalid forward protocol {protocol!r}, must be 'tcp' or 'udp'")

    # Validate listen
    listen_clean = str(listen).strip()
    if ":" in listen_clean:
        l_host, l_port = listen_clean.rsplit(":", 1)
        validate_port(l_port)
    else:
        validate_port(listen_clean)
        listen_clean = f"0.0.0.0:{listen_clean}"

    # Validate target
    target_clean = str(target).strip()
    if ":" not in target_clean:
        raise ValueError(f"Target must be in host:port format: {target!r}")
    t_host, t_port = target_clean.rsplit(":", 1)
    validate_port(t_port)

    return {
        "listen": listen_clean,
        "target": target_clean,
        "protocol": proto,
    }


class PaqetAdapter:
    """
    Adapter for configuring, deploying, and managing Paqet tunnels.
    Supports raw-packet TCP transport, encrypted KCP, and TCP/UDP port forwarding.
    """

    def __init__(
        self,
        paqet_bin: str = "/usr/local/bin/paqet",
        config_dir: str = "/etc/paqet",
    ):
        self.paqet_bin = paqet_bin
        self.config_dir = config_dir

    def build_server_config(
        self,
        listen_port: int,
        interface: str,
        server_ip: str,
        router_mac: str,
        secret_key: str,
        cipher: str = "aes-128-gcm",
        kcp_mode: str = "fast",
        local_flags: Optional[List[str]] = None,
        conn: int = 1,
        log_level: str = "info",
        ipv6_addr: Optional[str] = None,
        ipv6_router_mac: Optional[str] = None,
        kcp_tuning: Optional[dict] = None,
    ) -> Tuple[Dict[str, Any], str]:
        """
        Builds the server-side YAML configuration for Paqet.
        """
        port_str = validate_port(listen_port)
        iface = validate_interface(interface)
        mac = validate_mac(router_mac)
        ciph = validate_cipher(cipher)
        mode = validate_kcp_mode(kcp_mode)
        flags = validate_tcp_flags(local_flags or ["PA"])

        if not secret_key or len(secret_key.strip()) < 16:
            raise ValueError("Secret key must be at least 16 characters long")

        config: Dict[str, Any] = {
            "role": "server",
            "log": {
                "level": log_level,
            },
            "listen": {
                "addr": f":{port_str}",
            },
            "network": {
                "interface": iface,
                "ipv4": {
                    "addr": f"{server_ip.strip()}:{port_str}",
                    "router_mac": mac,
                },
                "tcp": {
                    "local_flag": flags,
                },
            },
            "transport": {
                "protocol": "kcp",
                "conn": max(1, min(int(conn), 256)),
                "kcp": {
                    "mode": mode,
                    "block": ciph,
                    "key": secret_key.strip(),
                },
            },
        }

        if ipv6_addr and ipv6_router_mac:
            config["network"]["ipv6"] = {
                "addr": ipv6_addr.strip(),
                "router_mac": validate_mac(ipv6_router_mac),
            }

        if kcp_tuning:
            allowed = {'dshard', 'pshard', 'nodelay', 'interval', 'resend', 'nocongestion', 'wdelay', 'acknodelay'}
            if set(kcp_tuning) - allowed:
                raise ValueError('Unsupported KCP tuning option')
            config['transport']['kcp'].update(kcp_tuning)
        yaml_content = yaml.dump(config, sort_keys=False, default_flow_style=False)
        return config, yaml_content

    def build_client_config(
        self,
        server_ip: str,
        server_port: int,
        interface: str,
        client_ip: str,
        router_mac: str,
        secret_key: str,
        forward_rules: Optional[List[Dict[str, str]]] = None,
        socks5_rules: Optional[List[Dict[str, Any]]] = None,
        cipher: str = "aes-128-gcm",
        kcp_mode: str = "fast",
        local_flags: Optional[List[str]] = None,
        remote_flags: Optional[List[str]] = None,
        conn: int = 1,
        log_level: str = "info",
        kcp_tuning: Optional[dict] = None,
    ) -> Tuple[Dict[str, Any], str]:
        """
        Builds the client-side YAML configuration for Paqet with TCP/UDP forward rules.
        """
        s_port = validate_port(server_port)
        iface = validate_interface(interface)
        mac = validate_mac(router_mac)
        ciph = validate_cipher(cipher)
        mode = validate_kcp_mode(kcp_mode)
        l_flags = validate_tcp_flags(local_flags or ["PA"])
        r_flags = validate_tcp_flags(remote_flags or ["PA"])

        if not secret_key or len(secret_key.strip()) < 16:
            raise ValueError("Secret key must be at least 16 characters long")

        config: Dict[str, Any] = {
            "role": "client",
            "log": {
                "level": log_level,
            },
            "network": {
                "interface": iface,
                "ipv4": {
                    "addr": f"{client_ip.strip()}:0",  # port 0 for random source port
                    "router_mac": mac,
                },
                "tcp": {
                    "local_flag": l_flags,
                    "remote_flag": r_flags,
                },
            },
            "server": {
                "addr": f"{server_ip.strip()}:{s_port}",
            },
            "transport": {
                "protocol": "kcp",
                "conn": max(1, min(int(conn), 256)),
                "kcp": {
                    "mode": mode,
                    "block": ciph,
                    "key": secret_key.strip(),
                },
            },
        }

        # Port forwarding mappings (supports TCP and UDP)
        if forward_rules:
            validated_forwards = []
            for rule in forward_rules:
                validated_forwards.append(
                    build_forward_rule(
                        listen=rule["listen"],
                        target=rule["target"],
                        protocol=rule.get("protocol", "tcp"),
                    )
                )
            config["forward"] = validated_forwards

        # SOCKS5 proxy listeners
        if socks5_rules:
            config["socks5"] = socks5_rules

        if kcp_tuning:
            allowed = {'dshard', 'pshard', 'nodelay', 'interval', 'resend', 'nocongestion', 'wdelay', 'acknodelay'}
            if set(kcp_tuning) - allowed:
                raise ValueError('Unsupported KCP tuning option')
            config['transport']['kcp'].update(kcp_tuning)
        yaml_content = yaml.dump(config, sort_keys=False, default_flow_style=False)
        return config, yaml_content

    def build_iptables_setup_commands(self, tunnel_port: int) -> List[str]:
        """
        Generates mandatory iptables commands to prevent kernel RST injection
        and conntrack interference on the raw Paqet port.
        """
        p = validate_port(tunnel_port)
        return [
            # 1. NOTRACK PREROUTING
            f"iptables -t raw -C PREROUTING -p tcp --dport {p} -j NOTRACK 2>/dev/null || "
            f"iptables -t raw -A PREROUTING -p tcp --dport {p} -j NOTRACK",
            # 2. NOTRACK OUTPUT
            f"iptables -t raw -C OUTPUT -p tcp --sport {p} -j NOTRACK 2>/dev/null || "
            f"iptables -t raw -A OUTPUT -p tcp --sport {p} -j NOTRACK",
            # 3. Suppress kernel TCP RST in mangle OUTPUT
            f"iptables -t mangle -C OUTPUT -p tcp --sport {p} --tcp-flags RST RST -j DROP 2>/dev/null || "
            f"iptables -t mangle -A OUTPUT -p tcp --sport {p} --tcp-flags RST RST -j DROP",
        ]

    def build_iptables_teardown_commands(self, tunnel_port: int) -> List[str]:
        """
        Generates teardown commands to cleanly remove Paqet iptables rules upon teardown.
        """
        p = validate_port(tunnel_port)
        return [
            f"iptables -t raw -D PREROUTING -p tcp --dport {p} -j NOTRACK 2>/dev/null || true",
            f"iptables -t raw -D OUTPUT -p tcp --sport {p} -j NOTRACK 2>/dev/null || true",
            f"iptables -t mangle -D OUTPUT -p tcp --sport {p} --tcp-flags RST RST -j DROP 2>/dev/null || true",
        ]

    def build_systemd_unit(self, tunnel_name: str) -> str:
        """
        Creates hardened systemd service unit for Paqet with required capabilities.
        """
        t_name = validate_tunnel_name(tunnel_name)
        cfg_path = f"{self.config_dir}/{t_name}.yaml"
        return f"""[Unit]
Description=Paqet Raw-Packet Tunnel ({t_name})
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={self.paqet_bin} run -c {cfg_path}
Restart=always
RestartSec=3
LimitNOFILE=1048576

# Security Hardening & Capabilities
# Raw socket capture requires CAP_NET_RAW and CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""

    def detect_remote_network(self, ssh: SSHManager) -> Tuple[str, str, str]:
        """
        Detects primary default route interface, local IP, and default router MAC on remote host.
        Returns (interface, local_ip, router_mac).
        """
        # Get default route
        code, route_out, err = ssh.execute("ip route show default")
        if code != 0 or not route_out.strip():
            raise RuntimeError(f"Failed to detect default route on {ssh.ip}: {err}")

        # Get neighbor table
        code, neigh_out, _ = ssh.execute("ip neigh show")
        iface, gateway_ip, mac = parse_gateway_route(route_out, neigh_out)

        if not iface:
            raise RuntimeError(f"Could not determine default interface from route: {route_out}")

        # If MAC was not found in neighbor table, ping gateway once to populate ARP cache
        if not mac and gateway_ip:
            ssh.execute(f"ping -c 1 -W 1 {shquote(gateway_ip)} >/dev/null 2>&1 || true")
            _, neigh_out2, _ = ssh.execute(f"ip neigh show {shquote(gateway_ip)}")
            _, _, mac = parse_gateway_route(route_out, neigh_out2)

        if not mac:
            raise RuntimeError(
                f"Could not resolve gateway MAC address for {gateway_ip} on {ssh.ip}"
            )

        # Get local IP on that interface
        code, ip_out, _ = ssh.execute(f"ip -4 addr show dev {shquote(iface)}")
        ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_out)
        local_ip = ip_match.group(1) if ip_match else ssh.ip

        return iface, local_ip, mac

    def deploy_server_node(
        self,
        ssh: SSHManager,
        tunnel_name: str,
        tunnel_port: int,
        secret_key: str,
        cipher: str = "aes-128-gcm",
        kcp_mode: str = "fast",
        interface: Optional[str] = None,
        router_mac: Optional[str] = None,
        server_ip: Optional[str] = None,
        kcp_tuning: Optional[dict] = None,
    ) -> Tuple[bool, str]:
        """
        Provisions and starts Paqet server on a remote server node.
        """
        t_name = validate_tunnel_name(tunnel_name)
        p = int(validate_port(tunnel_port))

        # Detect interface and MAC if not explicitly supplied
        if not interface or not router_mac or not server_ip:
            det_iface, det_ip, det_mac = self.detect_remote_network(ssh)
            interface = interface or det_iface
            server_ip = server_ip or det_ip
            router_mac = router_mac or det_mac

        _, yaml_cfg = self.build_server_config(
            listen_port=p,
            interface=interface,
            server_ip=server_ip,
            router_mac=router_mac,
            secret_key=secret_key,
            cipher=cipher,
            kcp_mode=kcp_mode,
            kcp_tuning=kcp_tuning,
        )
        unit = self.build_systemd_unit(t_name)
        iptables_cmds = self.build_iptables_setup_commands(p)

        # Execute remote setup commands
        cfg_path = f"{self.config_dir}/{t_name}.yaml"
        unit_path = f"/etc/systemd/system/paqet-{t_name}.service"

        commands = [
            f"mkdir -p {self.config_dir}",
            f"cat << 'EOF' > {cfg_path}\n{yaml_cfg}\nEOF",
            f"chmod 600 {cfg_path}",
            f"cat << 'EOF' > {unit_path}\n{unit}\nEOF",
            *iptables_cmds,
            "systemctl daemon-reload",
            f"systemctl enable --now paqet-{t_name}.service",
            f"systemctl restart paqet-{t_name}.service",
        ]

        # Heredoc terminators must occupy a line by themselves. Joining them
        # with && writes the remaining deployment commands into the config.
        batch_cmd = "set -e\n" + "\n".join(commands)
        code, out, err = ssh.execute(batch_cmd, timeout=90)
        if code != 0:
            return False, f"Server deployment failed (exit {code}): {err or out}"

        return True, f"Paqet server node {t_name} deployed successfully on port {p}"

    def deploy_client_node(
        self,
        ssh: SSHManager,
        tunnel_name: str,
        server_ip: str,
        tunnel_port: int,
        secret_key: str,
        forward_rules: List[Dict[str, str]],
        cipher: str = "aes-128-gcm",
        kcp_mode: str = "fast",
        interface: Optional[str] = None,
        router_mac: Optional[str] = None,
        client_ip: Optional[str] = None,
        kcp_tuning: Optional[dict] = None,
    ) -> Tuple[bool, str]:
        """
        Provisions and starts Paqet client on a remote client node.
        """
        t_name = validate_tunnel_name(tunnel_name)
        p = int(validate_port(tunnel_port))

        if not interface or not router_mac or not client_ip:
            det_iface, det_ip, det_mac = self.detect_remote_network(ssh)
            interface = interface or det_iface
            client_ip = client_ip or det_ip
            router_mac = router_mac or det_mac

        _, yaml_cfg = self.build_client_config(
            server_ip=server_ip,
            server_port=p,
            interface=interface,
            client_ip=client_ip,
            router_mac=router_mac,
            secret_key=secret_key,
            forward_rules=forward_rules,
            cipher=cipher,
            kcp_mode=kcp_mode,
            kcp_tuning=kcp_tuning,
        )
        unit = self.build_systemd_unit(t_name)

        cfg_path = f"{self.config_dir}/{t_name}.yaml"
        unit_path = f"/etc/systemd/system/paqet-{t_name}.service"

        commands = [
            f"mkdir -p {self.config_dir}",
            f"cat << 'EOF' > {cfg_path}\n{yaml_cfg}\nEOF",
            f"chmod 600 {cfg_path}",
            f"cat << 'EOF' > {unit_path}\n{unit}\nEOF",
            "systemctl daemon-reload",
            f"systemctl enable --now paqet-{t_name}.service",
            f"systemctl restart paqet-{t_name}.service",
        ]

        batch_cmd = "set -e\n" + "\n".join(commands)
        code, out, err = ssh.execute(batch_cmd, timeout=90)
        if code != 0:
            return False, f"Client deployment failed (exit {code}): {err or out}"

        return True, f"Paqet client node {t_name} deployed successfully connecting to {server_ip}:{p}"

    def teardown_node(
        self,
        ssh: SSHManager,
        tunnel_name: str,
        tunnel_port: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Stops, disables, and removes service, configs, and firewall rules for a Paqet tunnel.
        """
        t_name = validate_tunnel_name(tunnel_name)
        cfg_path = f"{self.config_dir}/{t_name}.yaml"
        unit_name = f"paqet-{t_name}.service"
        unit_path = f"/etc/systemd/system/{unit_name}"

        cleanup_cmds = [
            f"systemctl stop {unit_name} 2>/dev/null || true",
            f"systemctl disable {unit_name} 2>/dev/null || true",
            f"rm -f {unit_path} {cfg_path}",
            "systemctl daemon-reload",
        ]

        if tunnel_port:
            cleanup_cmds.extend(self.build_iptables_teardown_commands(tunnel_port))

        batch_cmd = " && ".join(cleanup_cmds)
        code, out, err = ssh.execute(batch_cmd, timeout=60)
        if code != 0:
            return False, f"Teardown failed (exit {code}): {err or out}"

        return True, f"Paqet tunnel {t_name} torn down cleanly"


DEFAULT_PAQET_BIN = os.environ.get("VX_LB_PAQET_BINARY") or (
    "/tmp/paqet_test/paqet_linux_amd64"
    if os.path.exists("/tmp/paqet_test/paqet_linux_amd64")
    else "/usr/local/bin/paqet"
)


def connect(server: dict) -> SSHManager:
    """Creates connected SSHManager resolving local addresses."""
    address = server["ip"]
    try:
        interfaces = json.loads(subprocess.check_output(["ip", "-j", "addr"], timeout=5))
        local_addresses = {entry["local"] for interface in interfaces for entry in interface.get("addr_info", [])}
        if address in local_addresses:
            address = "127.0.0.1" if ":" not in address else "::1"
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    ssh = SSHManager(address, server.get("port", 22), server.get("username", "root"), server.get("password"), timeout=10)
    ok, error = ssh.connect()
    if not ok:
        raise RuntimeError(f"Failed to connect to {server['ip']}: {error}")
    return ssh


def install_paqet(ssh: SSHManager, role: str, config: Optional[dict] = None) -> Tuple[bool, str]:
    """Verifies binary existence and system prerequisites for Paqet."""
    if ssh is None or not hasattr(ssh, "execute"):
        return False, "SSH connection required for Paqet installation"
    cfg = config or {}
    binary = cfg.get("binary") or DEFAULT_PAQET_BIN
    cmd = f'test "$(id -u)" = 0 && test -x {shlex.quote(binary)} && command -v iptables && command -v systemctl'
    code, out, err = ssh.execute(cmd)
    if code == 0:
        return True, f"Paqet binary and prerequisites verified on {role} host"

    # Air-gapped fallback: check local bundled bin/
    import os
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _, arch_raw, _ = ssh.execute("uname -m")
    remote_arch = arch_raw.strip().lower()
    arch_dir = "x86_64" if ("x86_64" in remote_arch or "amd64" in remote_arch) else ("aarch64" if ("aarch64" in remote_arch or "arm64" in remote_arch) else remote_arch)

    candidate_paths = [
        os.path.join(base_dir, "bin", arch_dir, "paqet"),
        os.path.join(base_dir, "bin", "paqet"),
    ]
    for candidate in candidate_paths:
        if os.path.exists(candidate) and os.path.isfile(candidate):
            if hasattr(ssh, "upload_binary"):
                uploaded = ssh.upload_binary(candidate, binary, mode=0o755)
                if uploaded:
                    c, _, _ = ssh.execute(f"test -x {shlex.quote(binary)}")
                    if c == 0:
                        return True, f"Paqet binary installed from local bundled binary ({arch_dir})"

    return False, f"Paqet prerequisite check failed on {role}: {err or out}"


def verify(iran: SSHManager, kharej: SSHManager, node: dict, ports: Optional[List[int]] = None):
    """Require services and a real TCP/UDP round trip through the reserved Paqet mapping."""
    node_name = node.get("node_name", "")
    unit = f"paqet-{node_name}.service"
    for ssh, side in [(iran, "Iran"), (kharej, "Kharej")]:
        code, out, err = ssh.execute(f"systemctl is-active {shlex.quote(unit)}")
        if code != 0 or out.strip() != "active":
            raise RuntimeError(f"Paqet service {unit} is not active on {side}: {err or out}")
        code, out, _ = ssh.execute(f"journalctl -u {shlex.quote(unit)} -n 25 --no-pager 2>/dev/null | grep -iE 'fatal|panic' || true")
        if out.strip():
            raise RuntimeError(f"Paqet errors on {side}: {out.strip()}")

    from core.paqet_probe import verify_data
    return verify_data(iran, kharej, node)


def health(name: str, node: dict, ports: List[str]) -> Tuple[str, str, dict]:
    """Check the Paqet data mapping plus relay sockets and TCP destinations."""
    if node.get('provisioning'):
        return 'DOWN', 'راه‌اندازی نود کامل نشده است', {}
    if not node.get('paqet', {}).get('probe_port'):
        return 'IDLE', 'این نود مسیر آزمون داده ندارد؛ نیازمند راه‌اندازی با پیکربندی جدید است', {str(p): {'status':'IDLE','reason':'مسیر داده تأیید نشده','path_verified':False} for p in ports}
    sessions=[]
    try:
        pool=get_pools()[name]
        ports=validate_ports(ports)
        iran=connect(node);sessions.append(iran)
        kharej=connect(pool['kharej_server']);sessions.append(kharej)
        result=verify(iran,kharej,node,list(map(int,ports)))
        from core.kernel_relay_ports import verify_listeners
        verify_listeners(iran, 'paqet-'+node['node_name']+'.service', ports)
        program="""import socket,sys,json
results={}
for port in json.loads(sys.argv[2]):
 try:
  with socket.create_connection((sys.argv[1],int(port)),timeout=2):pass
  results[str(port)]=True
 except OSError:results[str(port)]=False
print(json.dumps(results))
"""
        code,out,_=kharej.execute('python3 -c '+shlex.quote(program)+' '+shlex.quote(pool['kharej_server']['ip'])+' '+shlex.quote(json.dumps(ports)),timeout=max(15,len(ports)*3))
        if code:raise RuntimeError('Destination check failed')
        availability=json.loads(out)
        details={p:{'status':'HEALTHY' if availability.get(p) is True else 'DOWN', 'reason':'مسیر واقعی Paqet TCP/UDP و دسترسی TCP مقصد تأیید شد؛ برنامهٔ UDP بررسی نشده' if availability.get(p) is True else 'مسیر Paqet سالم است؛ سرویس TCP مقصد آماده نیست','process_verified':True,'path_verified':True,'udp_application':'UNVERIFIED','latency_ms':result['latency_ms'],'last_success_epoch':time.time() if availability.get(p) is True else None} for p in ports}
        count=sum(d['status']=='HEALTHY' for d in details.values())
        return ('HEALTHY' if count==len(ports) else 'DEGRADED' if count else 'DOWN'), f'{count}/{len(ports)} TCP destinations ready; Paqet TCP/UDP challenge passed', details
    except Exception:
        return 'DOWN','مسیر واقعی Paqet، شنونده‌ها یا سرویس مقصد تأیید نشد',{}
    finally:
        for ssh in sessions:ssh.close()


def clean(ssh: SSHManager, node: Union[dict, str], iran: bool = True) -> Tuple[bool, str]:
    """Tears down Paqet tunnel, service, firewall rules, and configs."""
    if ssh is None or not hasattr(ssh, "execute"):
        return False, "SSH connection required for cleanup"
    if isinstance(node, dict):
        node_name = node.get("node_name", "")
        tunnel_port = (node.get("paqet", {}) or {}).get("tunnel_port") or node.get("tunnel_port")
    else:
        node_name = str(node).replace(".service", "").replace("paqet-", "")
        tunnel_port = None
    adapter = PaqetAdapter(paqet_bin=DEFAULT_PAQET_BIN)
    return adapter.teardown_node(ssh, node_name, tunnel_port=int(tunnel_port) if tunnel_port else None)


def add(name: str, server: dict, callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
    """Adds a new Iran node to an existing Paqet pool."""
    pool = get_pools().get(name)
    if not pool:
        return False, "استخر یافت نشد"
    if any(n["ip"] == server["ip"] for n in pool.get("nodes", [])):
        return False, "این سرور قبلاً عضو استخر است"

    def progress(message, status="running", error=""):
        def update_job(data):
            data["pools"][name].setdefault("node_additions", {}).setdefault(server["ip"], {}).update({
                "ip": server["ip"], "name": server.get("name", server["ip"]), "status": status, "message": message, "error": error, "updated_at": time.time()
            })
        atomic_update(update_job)
        if callback:
            callback(message)

    node_name = f"paq_{secrets.token_hex(6)}"
    node = dict(server, node_name=node_name, engine="paqet", transport="paqet", provisioning=True)
    sessions = []

    try:
        progress("اتصال به سرورها و بررسی پیش‌نیازهای Paqet")
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool["kharej_server"])
        sessions.append(kharej)

        adapter = PaqetAdapter(paqet_bin=(pool.get("camouflage") or {}).get("binary", DEFAULT_PAQET_BIN))

        # Check binary on both hosts
        for ssh, role in [(iran, "iran"), (kharej, "kharej")]:
            ok, msg = install_paqet(ssh, role, pool.get("camouflage"))
            if not ok:
                raise RuntimeError(msg)

        preferred_port = int((pool.get("camouflage") or {}).get("port") or 9999)
        from core.paqet_probe import reserve_probe_port
        used_ports = list(pool.get('client_ports', []))
        for other in get_pools().values():
            if other.get('kharej_server', {}).get('ip') == pool['kharej_server']['ip']:
                used_ports.extend(other.get('client_ports', []))
                for member in other.get('nodes', []):
                    value = member.get('tunnel_port') or member.get('paqet', {}).get('tunnel_port')
                    if value:
                        used_ports.append(value)
        tunnel_port = reserve_probe_port(kharej, used_ports, preferred=preferred_port, bind_host='0.0.0.0')
        secret_key = (pool.get("camouflage") or {}).get("secret_key") or generate_paqet_secret()
        cipher = (pool.get("camouflage") or {}).get("cipher", "aes-128-gcm")
        kcp_mode = (pool.get("camouflage") or {}).get("kcp_mode", "fast")

        kcp_tuning = {}
        if pool.get('transport') == 'quantum+':
            profile = pool.get('camouflage') or {}
            data, parity = int(profile.get('fec_datashard', 10)), int(profile.get('fec_parityshard', 3))
            if data < 1 or parity < 1 or data + parity > 32:
                raise ValueError('Invalid FEC shard counts')
            kcp_tuning.update(dshard=data, pshard=parity)
        elif pool.get('transport') == 'quantum-gaming':
            kcp_mode = 'manual'
            kcp_tuning.update(nodelay=1, interval=10, resend=2, nocongestion=1,
                              wdelay=False, acknodelay=True)

        node["paqet"] = {
            "tunnel_port": tunnel_port,
            "secret_key": secret_key,
            "cipher": cipher,
            "kcp_mode": kcp_mode,
            "kcp_tuning": kcp_tuning,
        }
        from core.paqet_probe import reserve_probe_port
        excluded = [*pool.get('client_ports', []), tunnel_port]
        node['paqet']['probe_port'] = reserve_probe_port(iran, excluded)
        node['paqet']['probe_backend_port'] = reserve_probe_port(kharej, excluded)
        node["tunnel_port"] = tunnel_port

        # Reserve node in storage
        def reserve(data):
            data["pools"][name]["nodes"].append(node)
        atomic_update(reserve)

        # Deploy server on Kharej
        progress("پیکربندی گره سرور Paqet روی سرور خارج")
        ok_kh, msg_kh = adapter.deploy_server_node(
            ssh=kharej,
            tunnel_name=node_name,
            tunnel_port=tunnel_port,
            secret_key=secret_key,
            cipher=cipher,
            kcp_mode=kcp_mode,
            kcp_tuning=kcp_tuning,
        )
        if not ok_kh:
            raise RuntimeError(msg_kh)

        # Deploy client on Iran
        progress("پیکربندی گره کلاینت Paqet روی سرور ایران")
        from core.paqet_probe import forward_rules
        forwards = forward_rules(node, pool['kharej_server']['ip'], pool.get('client_ports', ['2222']))
        ok_ir, msg_ir = adapter.deploy_client_node(
            ssh=iran,
            tunnel_name=node_name,
            server_ip=pool["kharej_server"]["ip"],
            tunnel_port=tunnel_port,
            secret_key=secret_key,
            forward_rules=forwards,
            cipher=cipher,
            kcp_mode=kcp_mode,
            kcp_tuning=kcp_tuning,
        )
        if not ok_ir:
            raise RuntimeError(msg_ir)

        progress("بررسی وضعیت و تأیید سرویس")
        verify(iran, kharej, node, [int(p) for p in pool.get("client_ports", [])])

        def finish(data):
            member = next(n for n in data["pools"][name]["nodes"] if n["node_name"] == node["node_name"])
            member.update(provisioning=False, status="active")
        atomic_update(finish)
        progress("نود Paqet با موفقیت به استخر اضافه شد", "succeeded")
        return True, "نود Paqet با موفقیت فعال شد"

    except Exception as failure:
        errors = []
        try:
            for ssh, is_ir in zip(sessions, (True, False)):
                ok, err = clean(ssh, node, iran=is_ir)
                if not ok:
                    errors.append(err)
            if not errors:
                def discard(data):
                    data["pools"][name]["nodes"] = [n for n in data["pools"][name]["nodes"] if n["node_name"] != node["node_name"]]
                atomic_update(discard)
        except Exception:
            pass

        err_msg = str(failure) + ("; پاک‌سازی ناقص: " + "; ".join(errors) if errors else "")
        progress("راه‌اندازی نود Paqet ناموفق بود", "failed", err_msg)
        return False, err_msg

    finally:
        for ssh in sessions:
            ssh.close()


def create(name: str, kharej: dict, servers: List[dict], ports: List[str], settings: Optional[dict] = None, callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str, dict]:
    """Creates a new Paqet pool."""
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        if not ports or not servers or name in get_pools():
            raise ValueError("نام تکراری یا فهرست سرورها/پورت‌ها خالی است")
        if len({s["ip"] for s in servers}) != len(servers):
            raise ValueError("سرورهای ایران نمی‌توانند تکراری باشند")
        if any(s["ip"] == kharej["ip"] for s in servers):
            raise ValueError("سرور ایران و سرور خارج نمی‌توانند یکسان باشند")
    except ValueError as e:
        return False, str(e), {}

    from core.load_balancer import LoadBalancerManager
    ok_conflict, err_conflict = LoadBalancerManager.check_port_conflicts(ports, [s["ip"] for s in servers])
    if not ok_conflict:
        return False, err_conflict, {}

    cfg = settings or {}
    tr_name = cfg.get("transport") or "paqet"
    pool_data = {
        "name": name,
        "transport": tr_name,
        "engine": "paqet",
        "camouflage": {
            "mode": tr_name,
            "server_name": cfg.get("server_name", "paqet.tunnel"),
            "port": int(validate_port(cfg.get("tunnel_port") or cfg.get("port") or 9999)),
            "cipher": cfg.get("cipher", "aes-128-gcm"),
            "kcp_mode": cfg.get("kcp_mode", "fast3" if tr_name.startswith("quantum") else "fast"),
            "binary": cfg.get("binary", DEFAULT_PAQET_BIN),
            "fec_datashard": int(cfg.get("fec_datashard", 10)),
            "fec_parityshard": int(cfg.get("fec_parityshard", 3)),
        },
        "kharej_server": kharej,
        "client_ports": ports,
        "nodes": [],
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_pool(name, pool_data)

    results = [add(name, s, callback) for s in servers]
    updated_pool = get_pools().get(name, pool_data)
    any_success = any(ok for ok, _ in results)
    return any_success, "نتیجهٔ نصب هر نود Paqet در کارت استخر ثبت شد" if any_success else "راه‌اندازی استخر Paqet ناموفق بود", updated_pool


def remove(name: str, ip: str, callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
    """Removes a single node from a Paqet pool."""
    pool = get_pools().get(name, {})
    node = next((n for n in pool.get("nodes", []) if n["ip"] == ip), None)
    if not node:
        return False, "نود در این استخر یافت نشد"

    sessions = []
    try:
        if callback:
            callback("اتصال به سرورهای ایران و خارج...")
        for s in (node, pool["kharej_server"]):
            sessions.append(connect(s))

        if callback:
            callback("Tearing down tunnel from Iran server...")
        clean(sessions[0], node, iran=True)

        if callback:
            callback("Tearing down tunnel from Kharej server...")
        clean(sessions[1], node, iran=False)

        def discard(data):
            data["pools"][name]["nodes"] = [n for n in data["pools"][name]["nodes"] if n["node_name"] != node["node_name"]]
        atomic_update(discard)
        return True, "نود Paqet و منابع آن حذف شدند"
    except Exception as e:
        return False, str(e)
    finally:
        for s in sessions:
            s.close()


def remove_pool(name: str, callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
    """Removes an entire Paqet pool."""
    pool = get_pools().get(name, {})
    for node in list(pool.get("nodes", [])):
        ok, err = remove(name, node["ip"], callback)
        if not ok:
            return False, err
    delete_pool(name)
    return True, "استخر Paqet و تمام سرویس‌های مرتبط با موفقیت حذف شدند"


def change_ports(name: str, ports: List[str], recovery: bool = False) -> Tuple[bool, str]:
    """Updates forwarded client ports for the entire Paqet pool with rollback."""
    pool = get_pools().get(name)
    if not pool:
        return False, "استخر یافت نشد"
    from core.load_balancer import LoadBalancerManager
    try:
        ports = validate_ports(ports)
        if not ports:
            raise ValueError("حداقل یک پورت باید باقی بماند")
        from core.paqet_probe import forward_rules
        for member in pool.get('nodes', []):
            forward_rules(member, pool['kharej_server']['ip'], ports)
        ok, err = LoadBalancerManager.check_port_conflicts(ports, [n["ip"] for n in pool["nodes"]], exclude_pool_name=name)
        if not ok:
            return False, err
    except ValueError as e:
        return False, str(e)

    def set_job(**fields):
        def update_data(data):
            data["pools"][name].setdefault("transport_change", {}).update(fields, updated_at=time.strftime("%Y-%m-%d %H:%M:%S"))
        atomic_update(update_data)

    set_job(status="changing", target="paqet", kind="paqet_ports", **{"from": ",".join(pool["client_ports"]), "to": ",".join(ports), "total": len(pool["nodes"]), "completed": 0}, message="به‌روزرسانی پورت‌های Paqet")

    sessions = []
    changed = []
    try:
        adapter = PaqetAdapter(paqet_bin=(pool.get("camouflage") or {}).get("binary", DEFAULT_PAQET_BIN))
        for node in pool["nodes"]:
            ir = connect(node)
            kh = connect(pool["kharej_server"])
            sessions.extend([ir, kh])
            changed.append((node, ir, kh))

            from core.paqet_probe import forward_rules
            forwards = forward_rules(node, pool['kharej_server']['ip'], ports)
            ok, msg = adapter.deploy_client_node(
                ssh=ir,
                tunnel_name=node["node_name"],
                server_ip=pool["kharej_server"]["ip"],
                tunnel_port=node.get("tunnel_port") or (node.get("paqet", {}) or {}).get("tunnel_port", 9999),
                secret_key=(node.get("paqet", {}) or {}).get("secret_key", ""),
                forward_rules=forwards,
                cipher=(node.get("paqet", {}) or {}).get("cipher", "aes-128-gcm"),
                kcp_mode=(node.get("paqet", {}) or {}).get("kcp_mode", "fast"),
            )
            if not ok:
                raise RuntimeError(msg)
            verify(ir, kh, node, list(map(int, ports)))
            set_job(completed=len(changed))

        def commit(data):
            data["pools"][name]["client_ports"] = ports
        atomic_update(commit)
        set_job(status="succeeded", message="پورت‌های Paqet به‌روزرسانی شدند")
        return True, "پورت‌های Paqet به‌روزرسانی شدند"

    except Exception as failure:
        # Rollback old ports
        errors = []
        for node, ir, kh in reversed(changed):
            try:
                from core.paqet_probe import forward_rules
                old_forwards = forward_rules(node, pool['kharej_server']['ip'], pool['client_ports'])
                restored, restore_message = adapter.deploy_client_node(
                    ssh=ir,
                    tunnel_name=node["node_name"],
                    server_ip=pool["kharej_server"]["ip"],
                    tunnel_port=node.get("tunnel_port") or (node.get("paqet", {}) or {}).get("tunnel_port", 9999),
                    secret_key=(node.get("paqet", {}) or {}).get("secret_key", ""),
                    forward_rules=old_forwards,
                    cipher=(node.get("paqet", {}) or {}).get("cipher", "aes-128-gcm"),
                    kcp_mode=(node.get("paqet", {}) or {}).get("kcp_mode", "fast"),
                )
                if not restored:
                    raise RuntimeError(restore_message)
                verify(ir, kh, node, list(map(int, pool['client_ports'])))
            except Exception as e:
                errors.append(str(e))
        err_msg = str(failure) + ("; بازگردانی ناقص: " + "; ".join(errors) if errors else "")
        set_job(status="rollback_failed" if errors or recovery else "rolled_back", message="تغییر پورت Paqet ناموفق بود", error=err_msg)
        return False, err_msg
    finally:
        for s in sessions:
            s.close()
