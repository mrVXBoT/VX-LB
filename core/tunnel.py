import secrets
from typing import List, Tuple
from core.ssh_client import SSHManager
from core.validation import (
    validate_port,
    validate_ports,
    validate_transport,
    validate_tunnel_name,
    shquote,
    toml_basic_string,
)

SUPPORTED_TRANSPORTS = {
    # Original BackPack Keys (100% Backwards Compatibility with CLI and tests)
    "1": ("tcp", "Standard TCP (Minimal CPU and packet overhead)"),
    "2": ("stealth", "TCP + Stealth (Noise protocol, zero fingerprint, anti-DPI) [Recommended]"),
    "3": ("pck", "TCP + PCK (Raw TCP packets, immune to kernel resets & TCP RST injection) [High Resilience]"),
    "4": ("kcp", "UDP + KCP + FEC (Forward error correction, repairs loss, great for gaming)"),
    "5": ("wss", "WebSocket Secure TLS 1.3 (Browser fingerprint simulation and CDN traversal)"),
    "6": ("quic", "UDP + QUIC (Standard session with TLS 1.3 encryption)"),
    # Additional Web & Advanced Stream Transports
    "7": ("ws", "Plaintext WebSocket RFC 6455 (Reverse-proxy and CDN traversal)"),
    "8": ("http", "HTTP/1.1 CONNECT (mTLS verified transport)"),
    "9": ("https", "HTTPS CONNECT (TLS 1.3 mTLS verified transport)"),
    # Kernel L3 Carriers
    "13": ("tun", "Linux Kernel Virtual L3 TUN (Full Layer 3 routing without TCP-over-TCP penalty)"),
    "14": ("dc6", "Direct Connect IPv6 Carrier (Fast unpolluted IPv6 transport)"),
    # Specialized / Tunnel Engines
    "18": ("gre", "GRE IPv4 + IPsec AES-GCM + TCP/UDP forwarding"),
    "20": ("waterwall", "WaterWall (Official Engine: HalfDuplex, Reverse, Trojan, Bgp4, Reality)"),
    "21": ("gost", "GOST (Shadowsocks/obfs4/gRPC/SSH multi-protocol engine)"),
    "42": ("frp", "FRP (معکوس‌پروکسی سریع — TCP/UDP/Dual)"),
    "43": ("hedioum", "Hedioum Pool Tunnel (SOCKS5/TUN/Gateway — استتار ۱۶‌گانه)"),
    "22": ("geneve_ipsec", "Geneve + IPsec (Experimental kernel tunnel)"),
    "23": ("vxlan", "VXLAN (L2 encapsulation: Point-to-Point / Bridge / FDB — بدون رمزنگاری)"),
    "24": ("wireguard", "WireGuard (Curve25519 + ChaCha20 kernel interface)"),
    "25": ("gre6", "GRE6 (Native IPv6 GRE encapsulation)"),
    "26": ("ip6ip6", "IP6IP6 (Native IPv6 in IPv6 encapsulation)"),
    "27": ("slipstream", "Slipstream (Emergency DNS tunnel over port 53)"),
    # Spoof Tunnel & DPI Desync Suite
    "28": ("fake-sni", "Fake SNI Injection (Auto-TTL / BadSum / MD5Sig)"),
    "29": ("split-tls", "TLS Record & TCP MultiSplit (Disorder ClientHello)"),
    "30": ("hop-ttl-injection", "Hop-Count Windowing (Short-lived TTL injection)"),
    "31": ("tcp-state-desync", "TCP State Desync (RST + OOB DPI desync)"),
    "32": ("l3-ip-spoof", "L3 Source-IP Spoofing (Raw socket IP spoofing)"),
    "33": ("l7-header-mutation", "HTTP/WS Header Mutation (Host header mutation)"),
    "34": ("udp-raw-spoof", "Raw UDP / QUIC Spoofing (UDP obfuscation)"),
    "35": ("dns-spoof", "DNS Anti-Poisoning (Drop spoofed bogon responses)"),
    "36": ("spoof-tcp-syn", "TCP-SYN Spoof (Round-robin source IP spoofing)"),
    "37": ("spoof-udp-raw", "UDP Raw Spoof (Round-robin UDP packet spoofing)"),
    "38": ("spoof-icmp", "ICMP Echo Spoof (Data-over-ICMP tunnel)"),
    "39": ("qs-dns-hybrid", "QS-Tunnel Hybrid (DNS upload + Raw IP download)"),
    "40": ("hyperion-x", "HYPERION-X Tri-Vector (Multi-path stealth tunnel)"),
    "41": ("vxlan_ipsec", "VXLAN + IPsec (AES-256-GCM strongSwan encapsulation)"),
}

NON_BACKPACK_TRANSPORTS = {
    "gre", "waterwall", "gost", "frp", "hedioum",
    "geneve_ipsec", "vxlan", "vxlan_ipsec", "gre6", "ip6ip6", "wireguard", "slipstream",
    "tun", "dc6", "http", "https",
    "fake-sni", "split-tls", "hop-ttl-injection", "tcp-state-desync",
    "l3-ip-spoof", "l7-header-mutation", "udp-raw-spoof", "dns-spoof", "spoof",
    "spoof-tcp-syn", "spoof-udp-raw", "spoof-icmp", "qs-dns-hybrid", "hyperion-x"
}

def generate_token(length: int = 64) -> str:
    """Generates a secure 64-character hex token."""
    return secrets.token_hex(length // 2)

def build_iran_config(tunnel_port: int, transport: str, token: str, client_ports: List[str]) -> str:
    """Creates Iran server TOML config."""
    # Security: validate + TOML-escape every interpolated value so a crafted
    # port/transport can neither break the config nor inject TOML keys.
    tunnel_port = int(validate_port(tunnel_port))
    transport = validate_transport(transport, {k:v for k,v in SUPPORTED_TRANSPORTS.items() if v[0] not in NON_BACKPACK_TRANSPORTS})
    ports = validate_ports(client_ports)
    ports_str = ", ".join([f'"{toml_basic_string(p)}"' for p in ports])

    cfg = f"""# BackPack Server (Iran) Config
[server]
bind_addr = "0.0.0.0:{tunnel_port}"
transport = "{toml_basic_string(transport)}"
token = "{toml_basic_string(token)}"
ports = [{ports_str}]
accept_udp = true
nodelay = true
# Keep carrier TCP packets below a 1400-byte path MTU when ICMP is filtered.
mss = 1360
"""
    return cfg

def build_kharej_config(iran_ip: str, tunnel_port: int, transport: str, token: str) -> str:
    """Creates Kharej client TOML config."""
    tunnel_port = int(validate_port(tunnel_port))
    transport = validate_transport(transport, {k:v for k,v in SUPPORTED_TRANSPORTS.items() if v[0] not in NON_BACKPACK_TRANSPORTS})
    cfg = f"""# BackPack Client (Kharej) Config
[client]
remote_addr = "{toml_basic_string(str(iran_ip).strip())}:{tunnel_port}"
transport = "{toml_basic_string(transport)}"
token = "{toml_basic_string(token)}"
nodelay = true
# Keep carrier TCP packets below a 1400-byte path MTU when ICMP is filtered.
mss = 1360
"""
    return cfg

def build_systemd_unit(tunnel_name: str) -> str:
    """Creates systemd service file."""
    # Security: tunnel_name becomes part of a file path and (quoted) shell
    # commands -- whitelist it so it can never escape.
    tunnel_name = validate_tunnel_name(tunnel_name)
    return f"""[Unit]
Description=Backpack Tunnel ({tunnel_name})
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/backpack -c /etc/backpack/{tunnel_name}.toml
Restart=always
RestartSec=3
LimitNOFILE=1048576
# Hardening: the tunnel only needs network + its config file.
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""

def setup_tunnel_node(
    iran_ssh: SSHManager,
    kharej_ssh: SSHManager,
    tunnel_name: str,
    transport: str,
    tunnel_port: int,
    client_ports: List[str],
    token: str
) -> Tuple[bool, str]:
    """
    Configures and starts BackPack on both Iran and Kharej for a single tunnel node.
    """
    tunnel_name = validate_tunnel_name(tunnel_name)
    # 1. Setup Iran
    iran_cfg = build_iran_config(tunnel_port, transport, token, client_ports)
    iran_unit = build_systemd_unit(tunnel_name)

    if not iran_ssh.write_file(f"/etc/backpack/{tunnel_name}.toml", iran_cfg):
        return False, f"Failed to write configuration on Iran server ({iran_ssh.ip})"

    if not iran_ssh.write_file(f"/etc/systemd/system/backpack-{tunnel_name}.service", iran_unit):
        return False, f"Failed to create systemd service on Iran server ({iran_ssh.ip})"

    iran_ssh.execute("systemctl daemon-reload")
    c_ir, _, err_ir = iran_ssh.execute("systemctl enable --now " + shquote("backpack-%s.service" % tunnel_name))
    if c_ir != 0:
        return False, f"Failed to start service on Iran server: {err_ir}"

    # 2. Setup Kharej
    kharej_cfg = build_kharej_config(iran_ssh.ip, tunnel_port, transport, token)
    kharej_unit = build_systemd_unit(tunnel_name)

    if not kharej_ssh.write_file(f"/etc/backpack/{tunnel_name}.toml", kharej_cfg):
        return False, f"Failed to write configuration on Kharej server ({kharej_ssh.ip})"

    if not kharej_ssh.write_file(f"/etc/systemd/system/backpack-{tunnel_name}.service", kharej_unit):
        return False, f"Failed to create systemd service on Kharej server ({kharej_ssh.ip})"

    kharej_ssh.execute("systemctl daemon-reload")
    c_kh, _, err_kh = kharej_ssh.execute("systemctl enable --now " + shquote("backpack-%s.service" % tunnel_name))
    if c_kh != 0:
        return False, f"Failed to start service on Kharej server: {err_kh}"

    # systemd active only proves that the process started. New membership must
    # pass the same independent control/nonce check as a transport migration.
    from core.transport_change import install_and_verify
    diagnostics = []
    try:
        ready = install_and_verify(iran_ssh, kharej_ssh, f"backpack-{tunnel_name}.service",
                                   f"/etc/backpack/{tunnel_name}.toml", [iran_cfg, kharej_cfg], diagnostics=diagnostics)
    except Exception:
        diagnostics.append("اجرای بررسی یا بازگردانی تنظیمات تونل ناموفق بود")
        ready = False
    if not ready:
        for endpoint in (iran_ssh, kharej_ssh):
            try: stop_and_remove_tunnel(endpoint, tunnel_name)
            except Exception: pass
        return False, (diagnostics[-1] if diagnostics else "کانال کنترل یا عبور دادهٔ تونل تأیید نشد") + "؛ نود فعال نشد و سرویس‌های این تلاش پاک شدند"
    return True, "Tunnel control channel and independent data flow verified on both servers"

def stop_and_remove_tunnel(ssh: SSHManager, tunnel_name: str):
    """Stops and deletes a tunnel node from a server."""
    # NOTE: stored names from before validation existed may contain characters
    # outside the whitelist (e.g. dots, parens). Do NOT hard-validate here --
    # shlex.quote() below makes any string shell-safe, and raising would strand
    # orphaned tunnels that can never be torn down. Strict validation happens
    # at creation time (setup_tunnel_node).
    svc = shquote(f"backpack-{tunnel_name}.service")
    unit_path = shquote(f"/etc/systemd/system/backpack-{tunnel_name}.service")
    toml_path = shquote(f"/etc/backpack/{tunnel_name}.toml")
    ssh.execute(f"systemctl stop {svc} || true")
    ssh.execute(f"systemctl disable {svc} || true")
    ssh.execute(f"rm -f {unit_path}")
    ssh.execute(f"rm -f {toml_path}")
    code, _, _ = ssh.execute(
        f"systemctl daemon-reload && ! systemctl is-active --quiet {svc} "
        f"&& test ! -e {unit_path} && test ! -e {toml_path}"
    )
    return code == 0
