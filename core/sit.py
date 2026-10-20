"""SIT / 6in4 (IPv6-over-IPv4) Tunnel Engine and Tools for LD-BP.

Coverage:
- Point-to-point IPv6-in-IPv4 tunnel carried over native IPv4 underlay (RFC 4213 / protocol 41)
- Eliminates any requirement for native IPv6 reachability from the ISP
- Private link creation with IPv6-primary internal addressing (/126 and optional dual-stack IPv4 /30)
- MTU validation (1280..1480, default 1440; min 1280 per RFC 8200) and scoped routing (/128)
- Strict preservation of default routes, SSH management path, and existing tunnel resources
- Independent lifecycle: install, configure, start, stop, status, probe, modify, rollback, clean
- Security declaration: inherently cleartext; no cryptography or obfuscation
"""
import copy
import hashlib
import ipaddress
import logging
import re
import secrets
import shlex
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from core.ipv6_tunnel_tools import (
    CLEARTEXT_WARNING,
    allocate_tunnel_ips,
    check_kernel_prerequisites,
    execute_active_data_probe,
    parse_link_telemetry,
    render_scoped_service,
    sanitize_interface_name,
    synthesize_status,
    validate_mtu,
)

logger = logging.getLogger("ldbp.sit")

ENGINE_ID = "sit"
TUNNEL_MODE = "sit"
KERNEL_MODULE = "sit"
DEFAULT_MTU = 1440
MIN_MTU = 1280  # RFC 8200 required minimum MTU for IPv6
MAX_MTU = 1480  # 1500 - 20 (outer IPv4 header)


def validate_sit_mtu(mtu_value: Any) -> int:
    """Validates MTU for SIT / 6in4 tunnel."""
    return validate_mtu(mtu_value, MIN_MTU, MAX_MTU, tunnel_type="SIT")


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


def check_sit_prerequisites(ssh: Any, remote_ipv4: Optional[str] = None) -> Tuple[bool, str]:
    """Verifies that kernel module 'sit' is present and IPv4 endpoint is reachable."""
    ok_kern, msg_kern = check_kernel_prerequisites(ssh, KERNEL_MODULE)
    if not ok_kern:
        return False, msg_kern

    if remote_ipv4:
        ok_ping, msg_ping = check_ipv4_reachability(ssh, remote_ipv4)
        if not ok_ping:
            return False, f"SIT IPv4 reachability check failed: {msg_ping}"

    return True, "SIT kernel module and IPv4 reachability prerequisites verified"


def configure_sit_link(
    iran_node: dict,
    kharej_server: dict,
    pool_config: Optional[dict] = None,
) -> dict:
    """Generates complete configuration and systemd service specifications for SIT / 6in4.

    Specifies:
    - External address family: IPv4 (no native IPv6 needed)
    - Internal address family: IPv6 primary (/126) with optional dual-stack IPv4 (/30)
    - Inherently unencrypted cleartext status
    - Scoped routing restricted dev interface
    """
    pool_config = pool_config or {}
    node_name = iran_node.get("node_name") or iran_node.get("name") or "sit_node"
    iface = pool_config.get("interface") or sanitize_interface_name(node_name, prefix="sit-")

    mtu = validate_sit_mtu(pool_config.get("mtu", DEFAULT_MTU))

    iran_ip = str(ipaddress.IPv4Address(iran_node["ip"]))
    kharej_ip = str(ipaddress.IPv4Address(kharej_server["ip"]))

    ipv6_subnet = pool_config.get("ipv6_subnet") or "2001:db8:100::/126"
    ipv4_subnet = pool_config.get("ipv4_subnet")
    addressing = allocate_tunnel_ips(ipv6_subnet, ipv4_subnet)

    service_name = f"ldbp-sit-{iface}.service"

    ir_create_cmd = f"ip link add {iface} type {TUNNEL_MODE} local {iran_ip} remote {kharej_ip} ttl 64"
    kh_create_cmd = f"ip link add {iface} type {TUNNEL_MODE} local {kharej_ip} remote {iran_ip} ttl 64"

    iran_unit = render_scoped_service(
        service_name=service_name,
        interface=iface,
        create_link_cmd=ir_create_cmd,
        mtu=mtu,
        local_priv_v4=addressing.get("iran_ipv4"),
        local_priv_v6=addressing["iran_ipv6"],
        peer_priv_v4=addressing.get("kharej_ipv4"),
        peer_priv_v6=addressing["kharej_ipv6"],
    )

    kharej_unit = render_scoped_service(
        service_name=service_name,
        interface=iface,
        create_link_cmd=kh_create_cmd,
        mtu=mtu,
        local_priv_v4=addressing.get("kharej_ipv4"),
        local_priv_v6=addressing["kharej_ipv6"],
        peer_priv_v4=addressing.get("iran_ipv4"),
        peer_priv_v6=addressing["iran_ipv6"],
    )


    client_ports = [str(p) for p in pool_config.get("client_ports", ["2222"])]
    target_ipv6 = addressing["kharej_ipv6"].split("/")[0]

    from core.ipv6_tunnel_tools import render_relay_service
    relay_script, relay_unit = render_relay_service(
        service_name=f"ldbp-sit-{iface}-relay.service",
        interface=iface,
        peer_ip=target_ipv6,
        ports=[int(p) for p in client_ports],
    )


    return {
        "engine": ENGINE_ID,
        "interface": iface,
        "service_name": service_name,
        "mtu": mtu,
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
            "relay_unit_path": f"/etc/systemd/system/ldbp-sit-{iface}-relay.service",
            "relay_script": relay_script,
            "relay_script_path": f"/etc/ldbp/{iface}-relay.py",
        },
        "kharej_config": {
            "unit": kharej_unit,
            "unit_path": f"/etc/systemd/system/{service_name}",
        },
    }
