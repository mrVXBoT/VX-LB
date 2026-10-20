"""Dedicated VXLAN (Virtual Extensible LAN) management tools for LD-BP.

Coverage:
- VXLAN Single-Server: Three Reference Methods (P2P, Bridge + IP Pointing, FDB + Bridge)
- VXLAN Multi-Server: VNI, Peer/FDB, Bridge, and Mesh topology
- Route, SSH, and Bridge preservation guarantees

IMPORTANT SECURITY NOTE:
Raw VXLAN (RFC 7348) encapsulates Layer 2 Ethernet frames into unencrypted Layer 4 UDP
packets (default dst_port 4789). It provides NO encryption, NO authentication, and NO
camouflage. Packets are visible in plaintext to intermediate network nodes.
"""
import ipaddress
import json
import logging
import re
import shlex
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("ldbp.vxlan")

# Standard constants
DEFAULT_VXLAN_PORT = 4789
DEFAULT_VXLAN_VNI = 1000
DEFAULT_VXLAN_MTU = 1280  # Conservative default for paths with a reduced underlay MTU.
MIN_VXLAN_MTU = 576
MAX_VXLAN_MTU = 1450
MAX_VNI = 16777215  # 24-bit VNI (RFC 7348)
MIN_VNI = 1
LINUX_IFNAMSIZ = 15  # Linux max network device name length

# Three reference methods from Azumi67 reference source
VXLAN_METHOD_P2P = "p2p"
VXLAN_METHOD_BRIDGE_POINTIP = "bridge_pointip"
VXLAN_METHOD_FDB_BRIDGE = "fdb_bridge"

SUPPORTED_METHODS = [
    VXLAN_METHOD_P2P,
    VXLAN_METHOD_BRIDGE_POINTIP,
    VXLAN_METHOD_FDB_BRIDGE,
]


def validate_vni(value: Any) -> int:
    """Validate 24-bit VXLAN Network Identifier (VNI)."""
    try:
        vni = int(str(value).strip())
    except (ValueError, TypeError):
        raise ValueError(f"VXLAN VNI must be an integer, got: {value!r}")
    if not (MIN_VNI <= vni <= MAX_VNI):
        raise ValueError(f"VXLAN VNI must be between {MIN_VNI} and {MAX_VNI}, got: {vni}")
    return vni


def validate_port(value: Any) -> int:
    """Validate UDP destination port (1-65535, default 4789)."""
    try:
        port = int(str(value).strip())
    except (ValueError, TypeError):
        raise ValueError(f"Port must be an integer, got: {value!r}")
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got: {port}")
    return port


def validate_mtu(value: Any) -> int:
    """Validate VXLAN MTU considering 50-byte encapsulation overhead."""
    try:
        mtu = int(str(value).strip())
    except (ValueError, TypeError):
        raise ValueError(f"MTU must be an integer, got: {value!r}")
    if not (MIN_VXLAN_MTU <= mtu <= MAX_VXLAN_MTU):
        raise ValueError(
            f"VXLAN MTU must be between {MIN_VXLAN_MTU} and {MAX_VXLAN_MTU} bytes (overhead: 50B), got: {mtu}"
        )
    return mtu


def validate_ip(value: Any, param_name: str = "IP") -> str:
    """Validate IPv4 or IPv6 address."""
    if value is None:
        raise ValueError(f"Invalid {param_name} address: None")
    s = str(value).strip()
    if not s:
        raise ValueError(f"Invalid {param_name} address: empty string")
    try:
        ip = ipaddress.ip_address(s)
        return str(ip)
    except ValueError:
        raise ValueError(f"Invalid {param_name} address: {value!r}")


def validate_ip_network_or_interface(value: Any, param_name: str = "Private IP") -> str:
    """Validate IP address with CIDR netmask (e.g., 10.200.1.1/30 or 2001:db8::1/64)."""
    if value is None:
        raise ValueError(f"Invalid CIDR {param_name}: None")
    s = str(value).strip()
    if not s:
        raise ValueError(f"Invalid CIDR {param_name}: empty string")
    try:
        iface = ipaddress.ip_interface(s)
        return str(iface)
    except ValueError:
        raise ValueError(f"Invalid CIDR {param_name}: {value!r}")


def validate_vxlan_method(method: str) -> str:
    """Validate one of the three reference VXLAN methods."""
    m = str(method).strip().lower()
    if m not in SUPPORTED_METHODS:
        raise ValueError(
            f"Unsupported VXLAN method {method!r}. Must be one of: {', '.join(SUPPORTED_METHODS)}"
        )
    return m


def sanitize_device_name(prefix: str, identifier: str) -> str:
    """Generate a clean, safe Linux device name <= 15 chars."""
    clean_id = re.sub(r"[^a-zA-Z0-9_-]", "", identifier).lower()
    # reserve space for prefix
    max_id_len = LINUX_IFNAMSIZ - len(prefix)
    if max_id_len < 1:
        raise ValueError(f"Prefix {prefix!r} is too long for Linux device name")
    name = f"{prefix}{clean_id[:max_id_len]}"
    if len(name) > LINUX_IFNAMSIZ:
        name = name[:LINUX_IFNAMSIZ]
    return name


def make_vxlan_iface(identifier: str) -> str:
    """Generate VXLAN interface name (e.g., vx-node1, max 15 chars)."""
    return sanitize_device_name("vx-", identifier)


def make_bridge_name(identifier: str) -> str:
    """Generate isolated dedicated bridge name (e.g., br-vx-node1, max 15 chars)."""
    return sanitize_device_name("br-vx-", identifier)


def is_system_or_protected_bridge(bridge_name: Optional[str]) -> bool:
    """Check if bridge name belongs to system or docker infrastructure and must not be touched."""
    if not bridge_name:
        return True
    b = str(bridge_name).lower().strip()
    protected = {"docker0", "br0", "virbr0", "cni0", "flannel.1", "kube-bridge", "lxdbr0"}
    if b in protected:
        return True
    # Dedicated bridges created by this adapter must start with br-vx-
    if not b.startswith("br-vx-"):
        return True
    return False


def validate_dedicated_bridge(bridge_name: Any) -> str:
    """Validate dedicated bridge name, strictly rejecting protected or system bridges."""
    if not bridge_name:
        raise ValueError("Bridge name cannot be empty or None")
    b = str(bridge_name).strip()
    if is_system_or_protected_bridge(b):
        raise ValueError(
            f"Bridge '{b}' is a protected system bridge and cannot be modified or managed by VXLAN adapter"
        )
    if len(b) > LINUX_IFNAMSIZ:
        raise ValueError(f"Bridge name '{b}' exceeds Linux IFNAMSIZ limit of {LINUX_IFNAMSIZ} characters")
    return b


def build_systemd_unit(
    service_name: str,
    description: str,
    start_script_path: str,
    stop_script_path: str,
) -> str:
    """Generate systemd unit file for durable link lifecycle."""
    return f"""[Unit]
Description={description}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash {start_script_path}
ExecStop=/bin/bash {stop_script_path}

[Install]
WantedBy=multi-user.target
"""


def generate_vxlan_scripts(
    method: str,
    iface: str,
    vni: int,
    port: int,
    mtu: int,
    local_ip: str,
    remote_ip: str,
    private_ip_cidr: str,
    peers: Optional[List[str]] = None,
    underlay_dev: Optional[str] = None,
    bridge_name: Optional[str] = None,
    nolearning: bool = False,
) -> Tuple[str, str]:
    """Generate bash start and stop scripts for the specified VXLAN method.

    Returns:
        (start_script_content, stop_script_content)
    """
    method = validate_vxlan_method(method)
    vni = validate_vni(vni)
    port = validate_port(port)
    mtu = validate_mtu(mtu)
    local_ip = validate_ip(local_ip, "local_ip")
    remote_ip = validate_ip(remote_ip, "remote_ip")
    private_ip_cidr = validate_ip_network_or_interface(private_ip_cidr, "private_ip_cidr")
    dev_arg = f"dev {shlex.quote(underlay_dev)} " if underlay_dev else ""

    start_lines = [
        "#!/bin/bash",
        "set -euo pipefail",
        "# Ensure kernel modules are present",
        "modprobe vxlan 2>/dev/null || true",
    ]
    stop_lines = [
        "#!/bin/bash",
        "set -euo pipefail",
    ]

    if method == VXLAN_METHOD_P2P:
        # Method 1: Point-to-Point Unicast VXLAN (no bridge, direct L3 IP on vxlan iface)
        start_lines.extend([
            f"# Method 1: VXLAN Point-to-Point Unicast",
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true",
            f"ip link add {shlex.quote(iface)} type vxlan id {vni} local {shlex.quote(local_ip)} remote {shlex.quote(remote_ip)} {dev_arg}dstport {port}",
            f"ip addr add {shlex.quote(private_ip_cidr)} dev {shlex.quote(iface)}",
            f"ip link set dev {shlex.quote(iface)} mtu {mtu}",
            f"ip link set dev {shlex.quote(iface)} up",
        ])
        stop_lines.extend([
            f"ip link set dev {shlex.quote(iface)} down 2>/dev/null || true",
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true",
        ])

    elif method == VXLAN_METHOD_BRIDGE_POINTIP:
        # Method 2: VXLAN Bridge Setup with IP Pointing (Bridge + remote IP on vxlan link)
        br = bridge_name or make_bridge_name(iface.replace("vx-", ""))
        validate_dedicated_bridge(br)

        start_lines.extend([
            "modprobe bridge 2>/dev/null || true",
            f"# Method 2: VXLAN Bridge Setup with Remote IP Pointing",
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true",
            f"ip link del {shlex.quote(br)} 2>/dev/null || true",
            f"ip link add {shlex.quote(br)} type bridge",
            f"ip link add {shlex.quote(iface)} type vxlan id {vni} remote {shlex.quote(remote_ip)} local {shlex.quote(local_ip)} {dev_arg}dstport {port}",
            f"ip link set {shlex.quote(iface)} master {shlex.quote(br)}",
            f"ip addr add {shlex.quote(private_ip_cidr)} dev {shlex.quote(br)}",
            f"ip link set dev {shlex.quote(iface)} mtu {mtu}",
            f"ip link set dev {shlex.quote(br)} mtu {mtu}",
            f"ip link set dev {shlex.quote(iface)} up",
            f"ip link set dev {shlex.quote(br)} up",
        ])
        stop_lines.extend([
            f"ip link set dev {shlex.quote(iface)} nomaster 2>/dev/null || true",
            f"ip link set dev {shlex.quote(iface)} down 2>/dev/null || true",
            f"ip link set dev {shlex.quote(br)} down 2>/dev/null || true",
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true",
            f"ip link del {shlex.quote(br)} 2>/dev/null || true",
        ])

    elif method == VXLAN_METHOD_FDB_BRIDGE:
        # Method 3: FDB VXLAN with Bridge (Forwarding Database unicast flooding / multi-peer)
        br = bridge_name or make_bridge_name(iface.replace("vx-", ""))
        validate_dedicated_bridge(br)

        # Filter out local_ip to prevent packet loops / self-flooding
        raw_peers = peers or [remote_ip]
        clean_peers: List[str] = []
        for p in raw_peers:
            p_val = validate_ip(p, "peer_ip")
            if p_val != local_ip and p_val not in clean_peers:
                clean_peers.append(p_val)
        if not clean_peers and remote_ip != local_ip:
            clean_peers.append(remote_ip)

        learning_opt = " nolearning" if nolearning else ""

        start_lines.extend([
            "modprobe bridge 2>/dev/null || true",
            f"# Method 3: FDB VXLAN with Bridge (RFC 7348 Unicast FDB)",
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true",
            f"ip link del {shlex.quote(br)} 2>/dev/null || true",
            f"ip link add {shlex.quote(br)} type bridge",
            f"ip link add {shlex.quote(iface)} type vxlan id {vni} local {shlex.quote(local_ip)} {dev_arg}dstport {port}{learning_opt}",
            f"ip link set {shlex.quote(iface)} master {shlex.quote(br)}",
        ])
        for p in clean_peers:
            start_lines.append(
                f"bridge fdb append to 00:00:00:00:00:00 dst {shlex.quote(p)} dev {shlex.quote(iface)}"
            )
        start_lines.extend([
            f"ip addr add {shlex.quote(private_ip_cidr)} dev {shlex.quote(br)}",
            f"ip link set dev {shlex.quote(iface)} mtu {mtu}",
            f"ip link set dev {shlex.quote(br)} mtu {mtu}",
            f"ip link set dev {shlex.quote(iface)} up",
            f"ip link set dev {shlex.quote(br)} up",
        ])
        stop_lines.extend([
            f"ip link set dev {shlex.quote(iface)} nomaster 2>/dev/null || true",
            f"ip link set dev {shlex.quote(iface)} down 2>/dev/null || true",
            f"ip link set dev {shlex.quote(br)} down 2>/dev/null || true",
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true",
            f"ip link del {shlex.quote(br)} 2>/dev/null || true",
        ])

    return "\n".join(start_lines) + "\n", "\n".join(stop_lines) + "\n"
