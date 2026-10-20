"""Geneve (RFC 8926) Tunnel Tools and Configuration Helpers for VX-LB.

Coverage:
- Standalone Geneve Layer 2/3 Overlay over UDP port 6081 (RFC 8926).
- Two reference topology modes:
  1. Point-to-Point Unicast (P2P): direct peer encapsulation with explicit remote IP.
  2. Multi-Server FDB with Bridge (FDB Bridge): VNI overlay with forwarding database (FDB)
     peering, dedicated isolated bridge, and automated loop prevention.
- Security declaration: Inherent cleartext; unencrypted and unauthenticated.
- Preserves system bridges (docker0, br0, virbr0, cni0) and management WAN default routes.
"""
import ipaddress
import re
import secrets
import shlex
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_GENEVE_PORT = 6081
DEFAULT_GENEVE_VNI = 1000
DEFAULT_GENEVE_MTU = 1400
MIN_GENEVE_MTU = 576
MAX_GENEVE_MTU = 1460

GENEVE_METHOD_P2P = "p2p"
GENEVE_METHOD_FDB_BRIDGE = "fdb_bridge"
SUPPORTED_GENEVE_METHODS = [GENEVE_METHOD_P2P, GENEVE_METHOD_FDB_BRIDGE]

GENEVE_CLEARTEXT_WARNING = (
    "هشدار امنیتی: پروتکل Geneve مستقل (RFC 8926) روی پورت UDP 6081 کاملاً خام و بدون رمزنگاری یا استتار "
    "است. بسته‌های ارسالی در بستر اینترنت به صورت متن باز (Plaintext) عبور می‌کنند. برای تونل‌های دارای "
    "رمزنگاری، از پروفایل ترکیبی Geneve + IPsec استفاده کنید."
)

SYSTEM_PROTECTED_BRIDGES = {
    "docker0", "br0", "virbr0", "cni0", "flannel.1", "kube-bridge", "lxdbr0", "vmbr0"
}


def validate_vni(vni: Any) -> int:
    """Validates 24-bit Virtual Network Identifier (1..16777215)."""
    try:
        val = int(vni)
        if 1 <= val <= 16777215:
            return val
    except (TypeError, ValueError):
        pass
    raise ValueError(f"Geneve VNI must be an integer between 1 and 16777215 (got {vni!r})")


def validate_geneve_port(port: Any) -> int:
    """Validates destination UDP port (1..65535, default 6081)."""
    try:
        val = int(port)
        if 1 <= val <= 65535:
            return val
    except (TypeError, ValueError):
        pass
    raise ValueError(f"Geneve UDP port must be between 1 and 65535 (got {port!r})")


def validate_geneve_mtu(mtu: Any) -> int:
    """Validates MTU for Geneve overlay (576..1460, default 1400)."""
    try:
        val = int(mtu)
        if MIN_GENEVE_MTU <= val <= MAX_GENEVE_MTU:
            return val
    except (TypeError, ValueError):
        pass
    raise ValueError(
        f"Geneve MTU must be an integer between {MIN_GENEVE_MTU} and {MAX_GENEVE_MTU} (got {mtu!r})"
    )


def validate_geneve_method(method: Any) -> str:
    """Validates Geneve topology method ('p2p' or 'fdb_bridge')."""
    m = str(method or GENEVE_METHOD_P2P).strip().lower()
    if m in SUPPORTED_GENEVE_METHODS:
        return m
    raise ValueError(
        f"Unsupported Geneve method '{method}'. Supported methods: {', '.join(SUPPORTED_GENEVE_METHODS)}"
    )


def is_system_or_protected_bridge(bridge_name: str) -> bool:
    """Checks whether the given bridge name is a system/container managed interface."""
    return bridge_name.strip().lower() in SYSTEM_PROTECTED_BRIDGES


def validate_dedicated_bridge(bridge_name: str) -> str:
    """Validates bridge name and rejects system or protected bridges."""
    clean = re.sub(r"[^a-zA-Z0-9_-]", "", str(bridge_name).strip()).lower()
    if not clean or len(clean) > 15:
        raise ValueError(f"Bridge name '{bridge_name}' must be 1..15 alphanumeric characters")
    if is_system_or_protected_bridge(clean):
        raise ValueError(
            f"Bridge '{clean}' is a protected system interface and cannot be modified or deleted by VX-LB"
        )
    return clean


def make_geneve_iface(identifier: str) -> str:
    """Generates valid Linux interface name for Geneve (max 15 chars, IFNAMSIZ)."""
    clean_id = re.sub(r"[^a-zA-Z0-9]", "", identifier).lower()
    if not clean_id:
        clean_id = secrets.token_hex(4)
    # Prefix: 'gnv-' (4 chars) + clean_id (up to 10 chars)
    short_id = clean_id[:10]
    return f"gnv-{short_id}"


def make_geneve_bridge_name(identifier: str) -> str:
    """Generates valid Linux bridge interface name for Geneve (max 15 chars)."""
    clean_id = re.sub(r"[^a-zA-Z0-9]", "", identifier).lower()
    if not clean_id:
        clean_id = secrets.token_hex(4)
    short_id = clean_id[:10]
    return f"br-gnv-{short_id}"[:15]


def build_geneve_systemd_unit(
    service_name: str,
    interface: str,
    up_script_path: str,
    down_script_path: str,
    description: str = "VX-LB Geneve Overlay Tunnel",
) -> str:
    """Generates isolated systemd unit managing the lifecycle of the Geneve interface."""
    return f"""[Unit]
Description={description} ({interface})
After=network-online.target
Wants=network-online.target
PartOf=vxlb-tunnels.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash {up_script_path}
ExecStop=/bin/bash {down_script_path}

[Install]
WantedBy=multi-user.target
"""


def generate_geneve_scripts(
    interface: str,
    vni: int,
    dst_port: int,
    mtu: int,
    local_underlay_ip: str,
    remote_underlay_ip: Optional[str],
    method: str = GENEVE_METHOD_P2P,
    local_private_ip: Optional[str] = None,
    peer_private_ip: Optional[str] = None,
    bridge_name: Optional[str] = None,
    fdb_peers: Optional[List[str]] = None,
) -> Tuple[str, str]:
    """Generates bash setup and teardown scripts for the Geneve tunnel interface.

    Guarantees:
    - Scoped IP addressing and routing (never alters default route 0.0.0.0/0).
    - Teardown cleanly removes interfaces, unslaves bridges, and deletes dedicated bridges.
    - Loop prevention: filters local underlay IP out of FDB peers.
    """
    method = validate_geneve_method(method)
    vni = validate_vni(vni)
    dst_port = validate_geneve_port(dst_port)
    mtu = validate_geneve_mtu(mtu)

    up_lines = [
        "#!/bin/bash",
        "set -euo pipefail",
        "modprobe geneve 2>/dev/null || true",
        "modprobe bridge 2>/dev/null || true",
        f"ip link del {shlex.quote(interface)} 2>/dev/null || true",
    ]

    down_lines = [
        "#!/bin/bash",
        "set -x",
        f"ip link del {shlex.quote(interface)} 2>/dev/null || true",
    ]

    if method == GENEVE_METHOD_P2P:
        if not remote_underlay_ip:
            raise ValueError("Geneve P2P method requires remote underlay IP")
        up_lines.extend([
            f"ip link add {shlex.quote(interface)} type geneve id {vni} remote {shlex.quote(remote_underlay_ip)} dstport {dst_port} ttl 64 df set",
            f"ip link set {shlex.quote(interface)} mtu {mtu}",
        ])
        if local_private_ip:
            up_lines.append(f"ip addr add {shlex.quote(local_private_ip)} dev {shlex.quote(interface)}")
        up_lines.append(f"ip link set {shlex.quote(interface)} up")

    elif method == GENEVE_METHOD_FDB_BRIDGE:
        br = validate_dedicated_bridge(bridge_name or make_geneve_bridge_name(interface))
        up_lines.extend([
            f"ip link del {shlex.quote(br)} 2>/dev/null || true",
            f"ip link add {shlex.quote(br)} type bridge",
            f"ip link add {shlex.quote(interface)} type geneve id {vni} dstport {dst_port} ttl 64",
            f"ip link set {shlex.quote(interface)} mtu {mtu}",
            f"ip link set {shlex.quote(interface)} master {shlex.quote(br)}",
            f"ip link set {shlex.quote(interface)} up",
        ])
        if local_private_ip:
            up_lines.append(f"ip addr add {shlex.quote(local_private_ip)} dev {shlex.quote(br)}")
        up_lines.append(f"ip link set {shlex.quote(br)} up")

        # FDB peers with loop prevention
        fdb_list = fdb_peers or []
        if remote_underlay_ip and remote_underlay_ip not in fdb_list:
            fdb_list.append(remote_underlay_ip)

        for peer in fdb_list:
            peer_clean = str(peer).strip()
            if peer_clean and peer_clean != local_underlay_ip:
                up_lines.append(
                    f"bridge fdb append 00:00:00:00:00:00 dev {shlex.quote(interface)} dst {shlex.quote(peer_clean)} 2>/dev/null || true"
                )

        down_lines.extend([
            f"ip link set {shlex.quote(interface)} nomaster 2>/dev/null || true",
            f"ip link del {shlex.quote(br)} 2>/dev/null || true",
        ])

    up_script = "\n".join(up_lines) + "\n"
    down_script = "\n".join(down_lines) + "\n"
    return up_script, down_script
