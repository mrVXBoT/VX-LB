"""6TO4 Unicast (RFC 3056) Tunnel Engine and Tools for VX-LB.

Coverage:
- Point-to-point unicast 6TO4 transition mechanism based on RFC 3056.
- Distinct from SIT/6in4: strictly derives IPv6 prefix (2002:V4ADDR::/48) from the public IPv4 endpoints.
- Strictly distinct from deprecated 6TO4 Anycast (RFC 7526, 192.88.99.1): uses explicit point-to-point remote unicast IPv4 endpoints.
- Eliminates any requirement for native IPv6 reachability from the ISP (runs over IPv4 underlay protocol 41).
- Private link creation with RFC 3056 IPv6 internal addressing and optional dual-stack IPv4 /30.
- MTU validation (1280..1480, default 1440; min 1280 per RFC 8200) and scoped routing (/48 and /128).
- Strict preservation of default routes, SSH management path, and existing tunnel resources.
- Independent lifecycle: install, configure, start, stop, status, probe, modify, rollback, clean.
- Security declaration: inherently cleartext; no cryptography or obfuscation.
"""
import copy
import ipaddress
import logging
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

from core.ipv6_tunnel_tools import (
    CLEARTEXT_WARNING,
    check_kernel_prerequisites,
    execute_active_data_probe,
    parse_link_telemetry,
    render_scoped_service,
    sanitize_interface_name,
    synthesize_status,
    validate_mtu,
)

logger = logging.getLogger("vxlb.6to4")

ENGINE_ID = "6to4_unicast"
TUNNEL_MODE = "sit"
KERNEL_MODULE = "sit"
DEFAULT_MTU = 1440
MIN_MTU = 1280  # RFC 8200 minimum MTU for IPv6
MAX_MTU = 1480  # 1500 - 20 (IPv4 outer header)


def ipv4_to_6to4_prefix(ipv4_addr: str) -> str:
    """Calculates the RFC 3056 6to4 /48 prefix for a given IPv4 address.

    Example:
        192.0.2.1 -> 192 (0xc0), 0 (0x00), 2 (0x02), 1 (0x01) -> 2002:c000:0201::/48
    """
    v4 = ipaddress.IPv4Address(ipv4_addr)
    raw_bytes = v4.packed
    w1 = (raw_bytes[0] << 8) | raw_bytes[1]
    w2 = (raw_bytes[2] << 8) | raw_bytes[3]
    return f"2002:{w1:04x}:{w2:04x}::/48"


def derive_6to4_address(ipv4_addr: str, subnet_id: int = 1, host_id: int = 1) -> str:
    """Generates an RFC 3056 6to4 host address with a given subnet ID.

    Example:
        192.0.2.1, subnet=1, host=1 -> 2002:c000:201:1::1/64
    """
    v4 = ipaddress.IPv4Address(ipv4_addr)
    raw_bytes = v4.packed
    w1 = (raw_bytes[0] << 8) | raw_bytes[1]
    w2 = (raw_bytes[2] << 8) | raw_bytes[3]
    return f"2002:{w1:04x}:{w2:04x}:{subnet_id:x}::{host_id:x}/64"


def validate_6to4_mtu(mtu_value: Any) -> int:
    """Validates MTU for 6TO4 Unicast tunnel."""
    return validate_mtu(mtu_value, MIN_MTU, MAX_MTU, tunnel_type="6TO4")


def check_ipv4_reachability(ssh: Any, remote_ipv4: str, count: int = 2, timeout: int = 3) -> Tuple[bool, str]:
    """Tests IPv4 reachability to remote endpoint via ping."""
    if not hasattr(ssh, "execute"):
        return False, "Invalid SSH manager for reachability check"
    try:
        norm_ip = str(ipaddress.IPv4Address(remote_ipv4))
    except Exception as e:
        return False, f"Invalid IPv4 address: {e}"

    cmd = f"ping -4 -c {count} -W {timeout} {norm_ip}"
    code, out, err = ssh.execute(cmd)
    if code != 0:
        return False, f"IPv4 reachability test to {norm_ip} failed: {err.strip() or out.strip()}"
    return True, f"IPv4 host {norm_ip} reachable"


def check_6to4_prerequisites(ssh: Any, remote_ipv4: Optional[str] = None) -> Tuple[bool, str]:
    """Verifies that kernel module 'sit' is present and IPv4 endpoint is reachable."""
    ok_kern, msg_kern = check_kernel_prerequisites(ssh, KERNEL_MODULE)
    if not ok_kern:
        return False, msg_kern

    if remote_ipv4:
        ok_ping, msg_ping = check_ipv4_reachability(ssh, remote_ipv4)
        if not ok_ping:
            return False, f"6TO4 IPv4 reachability check failed: {msg_ping}"

    return True, "6TO4 kernel module and IPv4 reachability prerequisites verified"


def configure_6to4_unicast_link(
    iran_node: dict,
    kharej_server: dict,
    pool_config: Optional[dict] = None,
) -> dict:
    """Generates complete configuration and systemd service specifications for 6TO4 Unicast.

    Specifies:
    - RFC 3056 prefix derivation from public IPv4 endpoints
    - Point-to-point unicast tunnel (explicit local & remote endpoints, NOT anycast)
    - External address family: IPv4 (no native IPv6 needed from ISP)
    - Internal address family: RFC 3056 IPv6 with optional dual-stack IPv4 (/30)
    - Inherently unencrypted cleartext status with mandatory disclaimer
    - Scoped routing restricted to dev interface
    """
    pool_config = pool_config or {}
    node_name = iran_node.get("node_name") or iran_node.get("name") or "6to4_node"
    iface = pool_config.get("interface") or sanitize_interface_name("6to4", node_name)

    mtu = validate_6to4_mtu(pool_config.get("mtu", DEFAULT_MTU))

    iran_ip = str(ipaddress.IPv4Address(iran_node["ip"]))
    kharej_ip = str(ipaddress.IPv4Address(kharej_server["ip"]))

    # Derive RFC 3056 addresses
    iran_6to4_prefix = ipv4_to_6to4_prefix(iran_ip)
    kharej_6to4_prefix = ipv4_to_6to4_prefix(kharej_ip)

    iran_ipv6 = derive_6to4_address(iran_ip, subnet_id=1, host_id=1)
    kharej_ipv6 = derive_6to4_address(kharej_ip, subnet_id=1, host_id=1)

    ipv4_subnet = pool_config.get("ipv4_subnet")
    iran_ipv4 = None
    kharej_ipv4 = None
    if ipv4_subnet:
        v4_net = ipaddress.IPv4Network(ipv4_subnet, strict=False)
        hosts = list(v4_net.hosts())
        if len(hosts) >= 2:
            iran_ipv4 = f"{hosts[0]}/{v4_net.prefixlen}"
            kharej_ipv4 = f"{hosts[1]}/{v4_net.prefixlen}"

    service_name = f"vxlb-6to4-{iface}.service"

    # Explicit point-to-point sit tunnel (RFC 3056 unicast)
    ir_create_cmd = f"ip link add {iface} type {TUNNEL_MODE} local {iran_ip} remote {kharej_ip} ttl 64"
    kh_create_cmd = f"ip link add {iface} type {TUNNEL_MODE} local {kharej_ip} remote {iran_ip} ttl 64"

    iran_unit = render_scoped_service(
        service_name=service_name,
        interface=iface,
        create_link_cmd=ir_create_cmd,
        mtu=mtu,
        local_priv_v4=iran_ipv4,
        local_priv_v6=iran_ipv6,
        peer_priv_v4=kharej_ipv4,
        peer_priv_v6=kharej_ipv6,
    )

    kharej_unit = render_scoped_service(
        service_name=service_name,
        interface=iface,
        create_link_cmd=kh_create_cmd,
        mtu=mtu,
        local_priv_v4=kharej_ipv4,
        local_priv_v6=kharej_ipv6,
        peer_priv_v4=iran_ipv4,
        peer_priv_v6=iran_ipv6,
    )

    client_ports = [str(p) for p in pool_config.get("client_ports", ["2222"])]
    target_ipv6 = kharej_ipv6.split("/")[0]

    from core.ipv6_tunnel_tools import render_relay_service

    relay_script, relay_unit = render_relay_service(
        service_name=f"vxlb-6to4-{iface}-relay.service",
        interface=iface,
        peer_ip=target_ipv6,
        ports=[int(p) for p in client_ports],
    )

    addressing = {
        "iran_ipv6": iran_ipv6,
        "kharej_ipv6": kharej_ipv6,
        "iran_6to4_prefix": iran_6to4_prefix,
        "kharej_6to4_prefix": kharej_6to4_prefix,
        "iran_ipv4": iran_ipv4,
        "kharej_ipv4": kharej_ipv4,
    }

    return {
        "engine": ENGINE_ID,
        "interface": iface,
        "service_name": service_name,
        "mtu": mtu,
        "rfc": "RFC 3056",
        "underlay": {
            "family": "ipv4",
            "iran_ip": iran_ip,
            "kharej_ip": kharej_ip,
        },
        "addressing": addressing,
        "security": {
            "requires_encryption": False,
            "encryption_type": "none",
            "cleartext": True,
            "warning": CLEARTEXT_WARNING,
        },
        "iran_config": {
            "unit": iran_unit,
            "unit_path": f"/etc/systemd/system/{service_name}",
            "relay_unit": relay_unit,
            "relay_unit_path": f"/etc/systemd/system/vxlb-6to4-{iface}-relay.service",
            "relay_script": relay_script,
            "relay_script_path": f"/etc/vxlb/{iface}-relay.py",
        },
        "kharej_config": {
            "unit": kharej_unit,
            "unit_path": f"/etc/systemd/system/{service_name}",
        },
    }
