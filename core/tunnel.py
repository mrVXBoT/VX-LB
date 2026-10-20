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
    "1": ("tcp", "Standard TCP (کمترین مصرف پردازنده و سربار هدر)"),
    "2": ("stealth", "TCP + Stealth (Noise protocol, zero fingerprint, anti-DPI) [Recommended]"),
    "3": ("pck", "TCP + PCK (Raw TCP packets, immune to kernel resets & TCP RST injection) [High Resilience]"),
    "4": ("kcp", "UDP + KCP + FEC (Forward error correction, repairs loss, great for gaming)"),
    "5": ("wss", "WebSocket Secure TLS 1.3 (شبیه‌سازی اثرانگشت مرورگر و عبور از CDN)"),
    "6": ("quic", "UDP + QUIC (Standard session with TLS 1.3 encryption)"),
    # Additional Web & Advanced Stream Transports
    "7": ("ws", "Plaintext WebSocket RFC 6455 (عبور از ریورس‌پروکسی‌ها)"),
    "8": ("http", "HTTP/1.1 Chunked / h2c (جعل هدرهای استاندارد وب)"),
    "9": ("https", "HTTP/2 Multiplexed over TLS (شبیه‌سازی دقیق ترافیک وب‌گردی)"),
    # Loss-Resilient KCP & Gaming
    "10": ("quantum", "Quantum KCP Fast-ARQ (حذف گلوگاه TCP در پکت‌لاس متوسط)"),
    "11": ("quantum+", "Quantum+ KCP + Reed-Solomon FEC (مقاوم در پکت‌لاس‌های فاجعه‌بار تا ۳۰٪)"),
    "12": ("quantum-gaming", "Quantum Gaming Zero-Jitter KCP (پکت‌مد لحظه‌ای برای حداقل پینگ و جیتر بازی)"),
    # Kernel L3 Carriers
    "13": ("tun", "Linux Kernel Virtual L3 TUN (مسیریابی کامل لایه ۳ بدون مشکل TCP-over-TCP)"),
    "14": ("dc6", "Direct Connect IPv6 Carrier (استفاده از مسیرهای خلوت و فیلترنشده IPv6)"),
    # Advanced Anti-Censorship
    "15": ("xhttp", "Xray SplitHTTP (تفکیک دوطرفه دانلود و آپلود با پدینگ تصادفی)"),
    "16": ("xhttps", "XHTTP over TLS 1.3 / REALITY + xmux (استتار و ضدسانسور پیشرفته)"),
    "17": ("nova", "Nova Obfuscated Hybrid (ترکیب فرگمنتیشن TLS، پدینگ هوشمند و Port Hopping)"),
    # Specialized / Tunnel Engines
    "18": ("gre", "GRE IPv4 + IPsec AES-GCM + TCP/UDP forwarding"),
    "19": ("gre_xhttp", "GRE inside XHTTP + verified TLS 1.3 (encrypted HTTPS carrier)"),
    "20": ("waterwall", "WaterWall VLESS/TLS/Mux (flexible node-based routing)"),
    "21": ("paqet", "Paqet (آزمایشی — مسیر TCP/UDP با باینری رسمی آزموده شد)"),
    "22": ("geneve_ipsec", "Geneve + IPsec (آزمایشی — آزمون کرنلی لینک تأیید شد)"),
    "23": ("vxlan", "VXLAN (بدون رمزنگاری — سه متد P2P/Bridge/FDB؛ برای رمزنگاری VXLAN+IPsec را انتخاب کنید)"),
    "24": ("wireguard", "WireGuard (رمزنگاری Curve25519 + ChaCha20 — آزمون کرنلی لینک تأیید شد)"),
    "25": ("gre6", "GRE6 (آزمایشی — بدون رمزنگاری و استتار)"),
    "26": ("ip6ip6", "IP6IP6 (آزمایشی — بدون رمزنگاری و استتار)"),
    "27": ("slipstream", "Slipstream (تونل اضطراری DNS روی ساب‌دامین اختصاصی — آزمایشی)"),
    # Spoof Tunnel & DPI Desync Suite
    "28": ("fake-sni", "Fake SNI Injection (تزریق بسته جعلی با Auto-TTL / BadSum / MD5Sig)"),
    "29": ("split-tls", "TLS Record & TCP MultiSplit (تکه‌تکه‌سازی و معکوس‌سازی بسته ClientHello)"),
    "30": ("hop-ttl-injection", "Hop-Count Windowing (تزریق پکت با TTL کوتاه منقضی‌شونده قبل از مقصد)"),
    "31": ("tcp-state-desync", "TCP State Desync (مسموم‌سازی وضعیت DPI با RST و فلگ OOB)"),
    "32": ("l3-ip-spoof", "L3 Source-IP Spoofing (جعل آدرس آی‌پی مبدا لایه ۳ در سوکت خام)"),
    "33": ("l7-header-mutation", "HTTP/WS Header Mutation (دستکاری ساختار هدر و تفکیک‌کننده‌ها)"),
    "34": ("udp-raw-spoof", "Raw UDP / QUIC Spoofing (استتار و ضدسانسور ترافیک UDP)"),
    "35": ("dns-spoof", "DNS Anti-Poisoning (مسدودسازی پاسخ‌های جعلی و بوگون‌های زیرساخت)"),
    "36": ("spoof-tcp-syn", "ParsaKSH TCP-SYN Spoof (جعل سورس IP با TCP SYN و راند-رابین)"),
    "37": ("spoof-udp-raw", "ParsaKSH UDP Spoof (جعل پکت‌های خام UDP با راند-رابین IP)"),
    "38": ("spoof-icmp", "ParsaKSH ICMP Spoof (تونل داده در بسته‌های ICMP Echo)"),
    "39": ("qs-dns-hybrid", "QS-Tunnel Hybrid (آپلود DNS-Query بیس۳۲ + دانلود Raw IP-Spoof)"),
    "40": ("hyperion-x", "HYPERION-X Tri-Vector (شاهکار سه‌مسیره ضدگلوله با Dark Knock و تغییر چهره هوشمند)"),
    "41": ("vxlan_ipsec", "VXLAN + IPsec (آزمایشی — رمزنگاری AES-256-GCM با strongSwan، لینک کرنلی)"),
}

NON_BACKPACK_TRANSPORTS = {
    "gre", "xhttp", "xhttps", "gre_xhttp", "reality", "waterwall", "paqet",
    "geneve_ipsec", "vxlan", "vxlan_ipsec", "gre6", "ip6ip6", "wireguard", "slipstream",
    "quantum", "quantum+", "quantum-gaming", "tun", "dc6", "nova", "http", "https",
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
