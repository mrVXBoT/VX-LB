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
    "1": ("tcp", "TCP — direct stream without additional tunnel encryption"),
    "2": ("stealth", "Stealth (Noise) — TCP with Noise encryption"),
    "3": ("pck", "PCK (Raw TCP) — raw TCP packet transport; depends on network/firewall compatibility"),
    "4": ("kcp", "KCP — reliable transport over UDP; requires UDP connectivity"),
    "5": ("wss", "WSS (WebSocket + TLS) — encrypted WebSocket transport"),
    "6": ("quic", "QUIC — encrypted transport over UDP"),
    # Additional Web & Advanced Stream Transports
    "7": ("ws", "WebSocket (WS) — WebSocket over TCP without TLS"),
    "8": ("http", "HTTP CONNECT — HTTP/1.1 CONNECT with an authenticated mTLS data channel"),
    "9": ("https", "HTTPS CONNECT — CONNECT over TLS 1.3 with mutual authentication"),
    # Kernel L3 Carriers
    "13": ("tun", "TUN — virtual Layer 3 interface over an authenticated Noise/UDP carrier"),
    "14": ("dc6", "DC6 — selectable GRE6, IP6IP6 or SIT carrier"),
    # Specialized / Tunnel Engines
    "18": ("gre", "GRE + IPsec — GRE over IPv4 protected by authenticated IPsec ESP"),
    "20": ("waterwall", "WaterWall — HalfDuplex, Reverse, Trojan, Bgp4 and Reality modes"),
    "21": ("gost", "GOST — Shadowsocks, obfs4, gRPC, SSH and proxy-chain profiles"),
    "42": ("frp", "FRP — reverse proxy with TCP, UDP or combined forwarding"),
    "43": ("hedioum", "Hedioum — SOCKS5, TUN or Layer 3 gateway mode"),
    "44": ("rathole", "Rathole — reverse proxy with TCP, TLS, Noise or WebSocket transport"),
    "45": ("paqet", "Paqet — KCP over raw packets with interface and MAC configuration"),
    "22": ("geneve_ipsec", "Geneve + IPsec — Layer 2 overlay protected by authenticated IPsec ESP"),
    "23": ("vxlan", "VXLAN — Layer 2 overlay over UDP (بدون رمزنگاری)"),
    "24": ("wireguard", "WireGuard — encrypted UDP tunnel with public-key authentication"),
    "25": ("gre6", "GRE6 — GRE over IPv6; no built-in encryption"),
    "26": ("ip6ip6", "IP6IP6 — IPv6 encapsulation over IPv6; no built-in encryption"),
    "27": ("slipstream", "Slipstream (DNS) — fallback tunnel using a delegated DNS subdomain"),
    # Spoof Tunnel & DPI Desync Suite
    "28": ("fake-sni", "Fake SNI + MD5/BadSum — verified production packet-processing profile"),
    "29": ("split-tls", "TLS Record + TCP Disorder — experimental packet-processing profile"),
    "30": ("hop-ttl-injection", "Limited TTL Injection — experimental packet-processing profile"),
    "31": ("tcp-state-desync", "RST + OOB — experimental packet-processing profile"),
    "32": ("l3-ip-spoof", "L3 Source-IP Spoofing — unavailable in this release"),
    "33": ("l7-header-mutation", "HTTP Host Header Mutation — experimental packet-processing profile"),
    "34": ("udp-raw-spoof", "Raw UDP / QUIC Spoofing — unavailable in this release"),
    "35": ("dns-spoof", "DNS Anti-Poisoning — unavailable in this release"),
    "36": ("spoof-tcp-syn", "TCP SYN Spoofing — unavailable in this release"),
    "37": ("spoof-udp-raw", "Raw UDP Spoofing — unavailable in this release"),
    "38": ("spoof-icmp", "ICMP Tunnel — unavailable in this release"),
    "39": ("qs-dns-hybrid", "QS-Tunnel Hybrid — unavailable in this release"),
    "40": ("hyperion-x", "HYPERION-X — unavailable in this release"),
    "41": ("vxlan_ipsec", "VXLAN + IPsec — Layer 2 overlay protected by authenticated IPsec ESP"),
    "46": ("candy-spoof", "Candy-Spoof — bidirectional IP-spoofing tunnel (Rust, SOCKS5 + ICMP/UDP, PSK)"),
    "47": ("parsaksh", "ParsaKSH Spoof Tunnel — mutual IP-spoofing UDP-pipe (Go/Rust, ICMP/UDP/TCP-SYN, XDP)"),
}

NON_BACKPACK_TRANSPORTS = {
    "gre", "waterwall", "gost", "frp", "hedioum", "rathole", "paqet",
    "geneve_ipsec", "vxlan", "vxlan_ipsec", "gre6", "ip6ip6", "wireguard", "slipstream",
    "tun", "dc6", "http", "https",
    "fake-sni", "split-tls", "hop-ttl-injection", "tcp-state-desync",
    "l3-ip-spoof", "l7-header-mutation", "udp-raw-spoof", "dns-spoof", "spoof",
    "spoof-tcp-syn", "spoof-udp-raw", "spoof-icmp", "qs-dns-hybrid", "hyperion-x",
    "candy-spoof", "parsaksh"
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

    def abandon_partial_setup():
        # Iran is started before Kharej. Any later failure must remove both
        # sides so a half-created service does not keep the tunnel port.
        for endpoint in (iran_ssh, kharej_ssh):
            try:
                stop_and_remove_tunnel(endpoint, tunnel_name)
            except Exception:
                pass

    iran_ssh.execute("systemctl daemon-reload")
    c_ir, _, err_ir = iran_ssh.execute("systemctl enable --now " + shquote("backpack-%s.service" % tunnel_name))
    if c_ir != 0:
        return False, f"Failed to start service on Iran server: {err_ir}"

    # 2. Setup Kharej
    kharej_cfg = build_kharej_config(iran_ssh.ip, tunnel_port, transport, token)
    kharej_unit = build_systemd_unit(tunnel_name)

    if not kharej_ssh.write_file(f"/etc/backpack/{tunnel_name}.toml", kharej_cfg):
        abandon_partial_setup()
        return False, f"Failed to write configuration on Kharej server ({kharej_ssh.ip})"

    if not kharej_ssh.write_file(f"/etc/systemd/system/backpack-{tunnel_name}.service", kharej_unit):
        abandon_partial_setup()
        return False, f"Failed to create systemd service on Kharej server ({kharej_ssh.ip})"

    kharej_ssh.execute("systemctl daemon-reload")
    c_kh, _, err_kh = kharej_ssh.execute("systemctl enable --now " + shquote("backpack-%s.service" % tunnel_name))
    if c_kh != 0:
        abandon_partial_setup()
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
        abandon_partial_setup()
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
