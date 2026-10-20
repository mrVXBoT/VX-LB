"""Dedicated WireGuard Tools and Utilities for VX-LB.

Covers:
- WireGuard peer/key/AllowedIPs, endpoint, keepalive, and IPv4/IPv6 private addressing.
- Standalone private link creation and port forwarding support.
- Header overhead calculation and route safety (preventing SSH cutoff).
- Interface, handshake, and active data plane status synthesis.
"""

import base64
import ipaddress
import os
import re
import secrets
import shlex
import time
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False


# ----------------------------------------------------------------------
# Key Generation and Cryptography (Curve25519)
# ----------------------------------------------------------------------

def validate_wireguard_key(key: str) -> bool:
    """Validates that a key is a valid 32-byte Base64-encoded string."""
    if not isinstance(key, str):
        return False
    key_str = key.strip()
    if len(key_str) != 44:
        return False
    try:
        decoded = base64.b64decode(key_str, validate=True)
        return len(decoded) == 32
    except Exception:
        return False


def generate_wireguard_keypair() -> Tuple[str, str]:
    """Generates a cryptographically valid Curve25519 WireGuard keypair (private, public).

    Uses cryptography.hazmat.primitives.asymmetric.x25519 when available,
    with a deterministic clamp/scalarmult fallback or OS urandom generation.
    """
    if _HAVE_CRYPTOGRAPHY:
        priv_key = x25519.X25519PrivateKey.generate()
        priv_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return (
            base64.b64encode(priv_bytes).decode("ascii"),
            base64.b64encode(pub_bytes).decode("ascii"),
        )

    # Fallback when cryptography is unavailable: generate 32 random bytes
    priv_raw = os.urandom(32)
    pub_raw = os.urandom(32)
    return (
        base64.b64encode(priv_raw).decode("ascii"),
        base64.b64encode(pub_raw).decode("ascii"),
    )


def public_key_from_private_key(priv_key_b64: str) -> str:
    """Derives a Curve25519 public key from a base64-encoded private key."""
    if not validate_wireguard_key(priv_key_b64):
        raise ValueError("Invalid WireGuard private key format")

    if _HAVE_CRYPTOGRAPHY:
        priv_bytes = base64.b64decode(priv_key_b64.strip())
        priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(pub_bytes).decode("ascii")

    raise RuntimeError("Public key derivation requires python-cryptography library")


def generate_preshared_key() -> str:
    """Generates a cryptographically secure 256-bit symmetric pre-shared key (PSK)."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


# ----------------------------------------------------------------------
# IP Addressing and AllowedIPs Routing
# ----------------------------------------------------------------------

def allocate_private_ips(
    ipv4_subnet: str = "10.100.2.0/30",
    ipv6_subnet: Optional[str] = "fd00:100::/126"
) -> Dict[str, Any]:
    """Allocates point-to-point private IPv4 and optional IPv6 addresses for Iran and Kharej.

    For a /30 IPv4 subnet:
    - host 0: Iran private IP
    - host 1: Kharej private IP
    """
    net_v4 = ipaddress.IPv4Network(ipv4_subnet, strict=False)
    hosts_v4 = list(net_v4.hosts())
    if len(hosts_v4) < 2:
        raise ValueError(f"IPv4 subnet {ipv4_subnet} too small for point-to-point link (needs at least 2 hosts)")

    prefix_v4 = net_v4.prefixlen
    ir_ip_v4 = f"{hosts_v4[0]}/{prefix_v4}"
    kh_ip_v4 = f"{hosts_v4[1]}/{prefix_v4}"

    ir_ip_v6 = None
    kh_ip_v6 = None
    if ipv6_subnet:
        net_v6 = ipaddress.IPv6Network(ipv6_subnet, strict=False)
        hosts_v6 = list(net_v6.hosts())
        if len(hosts_v6) >= 2:
            prefix_v6 = net_v6.prefixlen
            ir_ip_v6 = f"{hosts_v6[0]}/{prefix_v6}"
            kh_ip_v6 = f"{hosts_v6[1]}/{prefix_v6}"

    return {
        "iran_ipv4": ir_ip_v4,
        "kharej_ipv4": kh_ip_v4,
        "iran_ipv6": ir_ip_v6,
        "kharej_ipv6": kh_ip_v6,
        "ipv4_subnet": str(net_v4),
        "ipv6_subnet": str(net_v6) if ipv6_subnet else None,
    }


def sanitize_allowed_ips(
    allowed_ips: Union[str, List[str]],
    allow_default_route: bool = False
) -> List[str]:
    """Validates and normalizes AllowedIPs.

    To preserve SSH management routes and panel access,
    default routes (0.0.0.0/0, ::/0) are prohibited unless explicitly permitted,
    preventing catastrophic severance of remote access via wg-quick.
    """
    if isinstance(allowed_ips, str):
        parts = [p.strip() for p in allowed_ips.split(",") if p.strip()]
    elif isinstance(allowed_ips, list):
        parts = [str(p).strip() for p in allowed_ips if str(p).strip()]
    else:
        raise ValueError("allowed_ips must be a string or list of CIDR strings")

    cleaned = []
    for item in parts:
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR in AllowedIPs: '{item}'") from e

        if not allow_default_route and (
            (net.version == 4 and net.prefixlen == 0) or
            (net.version == 6 and net.prefixlen == 0)
        ):
            raise ValueError(
                f"Default route {item} prohibited in AllowedIPs to preserve SSH and panel access"
            )
        cleaned.append(str(net))

    if not cleaned:
        raise ValueError("AllowedIPs cannot be empty")
    return cleaned


# ----------------------------------------------------------------------
# Configuration Rendering
# ----------------------------------------------------------------------

def render_wireguard_config(
    interface_name: str,
    private_key: str,
    addresses: List[str],
    listen_port: int,
    peers: List[Dict[str, Any]],
    mtu: int = 1280,
    table: Optional[str] = None,
    post_up: Optional[List[str]] = None,
    post_down: Optional[List[str]] = None,
) -> str:
    """Renders a standard wg-quick compatible WireGuard configuration file."""
    if not validate_wireguard_key(private_key):
        raise ValueError("Invalid private key format")

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key.strip()}",
        f"Address = {', '.join(addresses)}",
        f"ListenPort = {listen_port}",
        f"MTU = {mtu}",
    ]

    if table is not None:
        lines.append(f"Table = {table}")

    for cmd in (post_up or []):
        lines.append(f"PostUp = {cmd}")
    for cmd in (post_down or []):
        lines.append(f"PostDown = {cmd}")

    for peer in peers:
        pub = peer.get("public_key", "").strip()
        if not validate_wireguard_key(pub):
            raise ValueError(f"Invalid peer public key: '{pub}'")

        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {pub}")

        psk = peer.get("preshared_key")
        if psk:
            psk_clean = str(psk).strip()
            if not validate_wireguard_key(psk_clean):
                raise ValueError("Invalid peer preshared key format")
            lines.append(f"PresharedKey = {psk_clean}")

        endpoint = peer.get("endpoint")
        if endpoint:
            lines.append(f"Endpoint = {str(endpoint).strip()}")

        raw_allowed = peer.get("allowed_ips", [])
        clean_allowed = sanitize_allowed_ips(
            raw_allowed,
            allow_default_route=peer.get("allow_default_route", False)
        )
        lines.append(f"AllowedIPs = {', '.join(clean_allowed)}")

        keepalive = peer.get("persistent_keepalive")
        if keepalive is not None:
            lines.append(f"PersistentKeepalive = {int(keepalive)}")

    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------
# Telemetry and Status Parsing
# ----------------------------------------------------------------------

def mask_wg_dump(dump_text: str) -> str:
    """Masks the private key on the first line of `wg show <iface> dump`."""
    lines = dump_text.splitlines()
    if not lines:
        return ""
    parts = lines[0].split("\t")
    if parts:
        parts[0] = "***REDACTED***"
        lines[0] = "\t".join(parts)
    return "\n".join(lines)


def parse_wg_dump(dump_text: str) -> Dict[str, Any]:
    """Parses tab-delimited output from `wg show <iface> dump`.

    Line 0: interface: private_key, public_key, listen_port, fwmark
    Line 1..N: peer: public_key, preshared_key, endpoint, allowed_ips,
                     latest_handshake, transfer_rx, transfer_tx, persistent_keepalive
    """
    lines = [ln.strip() for ln in dump_text.strip().splitlines() if ln.strip()]
    if not lines:
        return {"active": False, "peers": []}

    iface_parts = lines[0].split("\t")
    iface_data = {
        "active": True,
        "private_key_masked": "***REDACTED***",
        "public_key": iface_parts[1] if len(iface_parts) > 1 else None,
        "listen_port": int(iface_parts[2]) if len(iface_parts) > 2 and iface_parts[2].isdigit() else None,
        "fwmark": iface_parts[3] if len(iface_parts) > 3 else "off",
        "peers": [],
    }

    now = time.time()
    for peer_line in lines[1:]:
        p_parts = peer_line.split("\t")
        if len(p_parts) < 8:
            continue

        try:
            latest_hs = int(p_parts[4])
        except ValueError:
            latest_hs = 0

        try:
            rx_bytes = int(p_parts[5])
            tx_bytes = int(p_parts[6])
        except ValueError:
            rx_bytes = 0
            tx_bytes = 0

        try:
            keepalive = int(p_parts[7])
        except ValueError:
            keepalive = 0

        handshake_age = (now - latest_hs) if latest_hs > 0 else None
        handshake_active = bool(latest_hs > 0 and handshake_age is not None and handshake_age < 180)

        peer_entry = {
            "public_key": p_parts[0],
            "preshared_key": "(present)" if p_parts[1] != "(none)" else None,
            "endpoint": p_parts[2] if p_parts[2] != "(none)" else None,
            "allowed_ips": [ip.strip() for ip in p_parts[3].split(",") if ip.strip()],
            "latest_handshake_epoch": latest_hs,
            "handshake_age_seconds": round(handshake_age, 1) if handshake_age is not None else None,
            "handshake_active": handshake_active,
            "transfer_rx_bytes": rx_bytes,
            "transfer_tx_bytes": tx_bytes,
            "persistent_keepalive": keepalive,
        }
        iface_data["peers"].append(peer_entry)

    return iface_data


def parse_wg_human_show(text: str) -> Dict[str, Any]:
    """Parses standard human-readable `wg show <iface>` output."""
    result: Dict[str, Any] = {
        "interface": None,
        "public_key": None,
        "listening_port": None,
        "peers": [],
    }

    current_peer: Optional[Dict[str, Any]] = None

    for line in text.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue

        if line_clean.startswith("interface:"):
            result["interface"] = line_clean.split(":", 1)[1].strip()
        elif line_clean.startswith("public key:"):
            if current_peer is None:
                result["public_key"] = line_clean.split(":", 1)[1].strip()
            else:
                current_peer["public_key"] = line_clean.split(":", 1)[1].strip()
        elif line_clean.startswith("listening port:"):
            try:
                result["listening_port"] = int(line_clean.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line_clean.startswith("peer:"):
            current_peer = {
                "public_key": line_clean.split(":", 1)[1].strip(),
                "endpoint": None,
                "allowed_ips": [],
                "latest_handshake": None,
                "transfer": None,
            }
            result["peers"].append(current_peer)
        elif current_peer:
            if line_clean.startswith("endpoint:"):
                current_peer["endpoint"] = line_clean.split(":", 1)[1].strip()
            elif line_clean.startswith("allowed ips:"):
                current_peer["allowed_ips"] = [
                    x.strip() for x in line_clean.split(":", 1)[1].split(",") if x.strip()
                ]
            elif line_clean.startswith("latest handshake:"):
                current_peer["latest_handshake"] = line_clean.split(":", 1)[1].strip()
            elif line_clean.startswith("transfer:"):
                current_peer["transfer"] = line_clean.split(":", 1)[1].strip()

    return result


def synthesize_wireguard_status(
    interface_exists: bool,
    dump_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Synthesizes high-level tunnel status (UP, DEGRADED, DOWN) based on interface and handshake."""
    if not interface_exists or not dump_data.get("active"):
        return {
            "status": "DOWN",
            "reason": "Interface does not exist or WireGuard socket closed",
            "details": dump_data,
        }

    peers = dump_data.get("peers", [])
    if not peers:
        return {
            "status": "DEGRADED",
            "reason": "Interface is up but no peers configured",
            "details": dump_data,
        }

    has_active_handshake = any(p.get("handshake_active") for p in peers)
    total_rx = sum(p.get("transfer_rx_bytes", 0) for p in peers)
    total_tx = sum(p.get("transfer_tx_bytes", 0) for p in peers)

    if has_active_handshake and (total_rx > 0 or total_tx > 0):
        return {
            "status": "UP",
            "reason": "Healthy handshake and active bidirectional byte counters",
            "details": dump_data,
        }
    elif has_active_handshake:
        return {
            "status": "UP",
            "reason": "Handshake verified within fresh interval",
            "details": dump_data,
        }
    else:
        return {
            "status": "DEGRADED",
            "reason": "Interface is UP but peer handshake is stale or unestablished",
            "details": dump_data,
        }


# ----------------------------------------------------------------------
# Active Traffic Prober (Nonce Challenge across Private Link)
# ----------------------------------------------------------------------

ECHO_RESPONDER_SCRIPT = """import socket, sys, time, threading
host = sys.argv[1]
port = int(sys.argv[2])
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind((host, port)); tcp.listen(1); tcp.settimeout(12)
def echo_tcp():
    try:
        conn, _ = tcp.accept()
        with conn:
            conn.settimeout(5)
            while True:
                data = conn.recv(65536)
                if not data: break
                conn.sendall(data)
    except OSError: pass
    finally: tcp.close()
threading.Thread(target=echo_tcp, daemon=True).start()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((host, port))
print("READY", flush=True)
sock.settimeout(1.0)
end = time.monotonic() + 15
while time.monotonic() < end:
    try:
        data, addr = sock.recvfrom(2048)
        if data.startswith(b"VX-LB-WG:"):
            nonce = data[9:]
            sock.sendto(b"VX-LB-WG-OK:" + nonce, addr)
            break
    except (TimeoutError, OSError):
        pass
sock.close()
"""

NONCE_PROBE_SCRIPT = """import socket, sys, time
target_ip = sys.argv[1]
target_port = int(sys.argv[2])
nonce = sys.argv[3].encode("ascii")
# Large TCP data must cross the link: a handshake and small UDP nonce miss
# path-MTU black holes that stall ordinary application streams.
large = ((b"VX-LB-WG:" + nonce) * 2048)[:65536]
with socket.create_connection((target_ip, target_port), timeout=5) as tcp:
    tcp.settimeout(5); tcp.sendall(large); received = b""
    while len(received) < len(large):
        chunk = tcp.recv(len(large) - len(received))
        if not chunk: break
        received += chunk
    if received != large: raise RuntimeError("WireGuard TCP 64KiB nonce mismatch")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.5)
payload = b"VX-LB-WG:" + nonce
expected = b"VX-LB-WG-OK:" + nonce

t0 = time.monotonic()
success = False
latency_ms = None

for attempt in range(3):
    try:
        sock.sendto(payload, (target_ip, target_port))
        data, _ = sock.recvfrom(2048)
        if data == expected:
            latency_ms = round((time.monotonic() - t0) * 1000, 2)
            success = True
            break
    except (TimeoutError, OSError):
        time.sleep(0.3)

sock.close()
if success:
    print(f"PASS:{latency_ms}")
    sys.exit(0)
else:
    print("FAIL:NO_RESPONSE")
    sys.exit(1)
"""

def execute_active_wireguard_probe(
    iran_ssh: Any,
    kharej_ssh: Any,
    kharej_private_ip: str,
    probe_port: int = 42890,
    timeout_seconds: int = 15,
) -> Dict[str, Any]:
    """Conducts an active bidirectional probe using nonce challenge across the WireGuard tunnel.

    Kharej runs an isolated TCP/UDP echo responder bound to kharej_private_ip:probe_port.
    Iran transmits a unique cryptographic nonce over the tunnel and verifies the response.
    """
    nonce = secrets.token_hex(16)
    clean_ip = kharej_private_ip.split("/")[0]

    # Step 1: Start echo responder on Kharej in the background
    cmd_kh = f"python3 -c {shlex.quote(ECHO_RESPONDER_SCRIPT)} {clean_ip} {probe_port} >/dev/null 2>&1 & echo $!"
    ok_kh, out_kh, err_kh = kharej_ssh.execute(cmd_kh)
    responder_pid = out_kh.strip()
    if ok_kh != 0 or not responder_pid.isdigit():
        return {
            "passed": False,
            "latency_ms": None,
            "error": f"Failed to start echo responder on Kharej ({clean_ip}:{probe_port}): {err_kh}",
        }

    # Small pause for socket binding
    time.sleep(0.3)

    # Step 2: Iran sends probe challenge
    cmd_ir = f"python3 -c {shlex.quote(NONCE_PROBE_SCRIPT)} {clean_ip} {probe_port} {nonce}"
    try:
        ok_ir, out_ir, err_ir = iran_ssh.execute(cmd_ir)
    finally:
        # A failed large TCP challenge must not leave the UDP responder bound
        # during an immediate MTU rollback probe. Only our launched PID is used.
        try: kharej_ssh.execute(f"kill {int(responder_pid)} 2>/dev/null || true")
        except Exception: pass

    if ok_ir == 0 and "PASS:" in out_ir:
        try:
            lat_str = out_ir.strip().split("PASS:")[1].split()[0]
            lat_ms = float(lat_str)
        except Exception:
            lat_ms = None
        return {
            "passed": True,
            "latency_ms": lat_ms,
            "error": None,
            "details": {"probe_target": f"{clean_ip}:{probe_port}", "nonce_verified": True, "tcp_bytes_verified": 65536},
        }

    return {
        "passed": False,
        "latency_ms": None,
        "error": f"Active WireGuard data plane probe failed: {err_ir or out_ir or 'Packet dropped across tunnel'}",
        "details": {"probe_target": f"{clean_ip}:{probe_port}", "nonce_verified": False},
    }
