"""ISATAP (Intra-Site Automatic Tunnel Addressing Protocol) Engine for LD-BP.

Coverage:
- RFC 5214 IPv6-over-IPv4 transition mechanism.
- Connects dual-stack nodes over an IPv4 network.
- Server (Router) and Client roles with IPv4-embedded IPv6 addresses (<prefix>:0:5efe:<ipv4>).
- Scoped systemd units, client port relay, active TCP/UDP data probe.
- MTU management (1280..1480, default 1440).
- Inherently cleartext security disclaimer.
"""
import ipaddress
import logging
import shlex
from typing import Any, Dict, List, Optional, Tuple

from core.ipv6_tunnel_tools import (
    CLEARTEXT_WARNING,
    check_kernel_prerequisites,
    execute_active_data_probe,
    parse_link_telemetry,
    render_relay_service,
    render_scoped_service,
    sanitize_interface_name,
    synthesize_status,
    validate_mtu,
)

logger = logging.getLogger("ldbp.isatap")

ENGINE_ID = "isatap"
DEFAULT_MTU = 1440
MIN_MTU = 1280
MAX_MTU = 1480
DEFAULT_ISATAP_PREFIX = "2001:db8:acad::"


def format_isatap_address(prefix: str, ipv4: str) -> str:
    """Formats an RFC 5214 IPv4-embedded ISATAP IPv6 address: <prefix_64>:0:5efe:<ipv4>."""
    v4 = ipaddress.IPv4Address(ipv4)
    v4_int = int(v4)
    high_word = (v4_int >> 16) & 0xFFFF
    low_word = v4_int & 0xFFFF

    base_prefix = prefix.split("/")[0].rstrip(":")
    # Ensure prefix has 4 16-bit blocks (64 bits)
    parts = base_prefix.split(":")
    while len(parts) < 4:
        parts.append("0")
    p64 = ":".join(parts[:4])
    return f"{p64}:0:5efe:{high_word:x}:{low_word:x}"


def validate_isatap_mtu(mtu_value: Any) -> int:
    return validate_mtu(mtu_value, MIN_MTU, MAX_MTU, tunnel_type="ISATAP")


def check_isatap_prerequisites(ssh: Any, remote_ipv4: Optional[str] = None) -> Tuple[bool, str]:
    ok_kern, msg_kern = check_kernel_prerequisites(ssh, "sit")
    if not ok_kern:
        return False, msg_kern

    if remote_ipv4:
        if not hasattr(ssh, "execute"):
            return False, "Invalid SSH manager"
        code, out, err = ssh.execute(f"ping -4 -c 2 -W 3 {shlex.quote(remote_ipv4)}")
        if code != 0:
            return False, f"ISATAP remote IPv4 reachability failed: {err.strip() or out.strip()}"

    return True, "ISATAP prerequisites verified"


def configure_isatap_link(
    iran_node: dict,
    kharej_server: dict,
    pool_config: Optional[dict] = None,
) -> dict:
    pool_config = pool_config or {}
    node_name = iran_node.get("node_name") or iran_node.get("name") or "isatap_node"
    iface = pool_config.get("interface") or sanitize_interface_name("isa", node_name)

    mtu = validate_isatap_mtu(pool_config.get("mtu", DEFAULT_MTU))
    iran_ip = str(ipaddress.IPv4Address(iran_node["ip"]))
    kharej_ip = str(ipaddress.IPv4Address(kharej_server["ip"]))

    prefix = pool_config.get("prefix") or DEFAULT_ISATAP_PREFIX
    iran_v6 = format_isatap_address(prefix, iran_ip)
    kharej_v6 = format_isatap_address(prefix, kharej_ip)

    addressing = {
        "iran_ipv6": f"{iran_v6}/64",
        "kharej_ipv6": f"{kharej_v6}/64",
        "iran_ipv4": None,
        "kharej_ipv4": None,
    }

    service_name = f"ldbp-isatap-{iface}.service"

    ir_create_cmd = f"ip link add {iface} type sit local {iran_ip} remote {kharej_ip} ttl 64"
    kh_create_cmd = f"ip link add {iface} type sit local {kharej_ip} remote {iran_ip} ttl 64"

    iran_unit = render_scoped_service(
        service_name=service_name,
        interface=iface,
        create_link_cmd=ir_create_cmd,
        mtu=mtu,
        local_priv_v4=addressing.get("iran_ipv4"),
        local_priv_v6=addressing.get("iran_ipv6"),
        peer_priv_v4=addressing.get("kharej_ipv4"),
        peer_priv_v6=addressing.get("kharej_ipv6"),
    )

    kharej_unit = render_scoped_service(
        service_name=service_name,
        interface=iface,
        create_link_cmd=kh_create_cmd,
        mtu=mtu,
        local_priv_v4=addressing.get("kharej_ipv4"),
        local_priv_v6=addressing.get("kharej_ipv6"),
        peer_priv_v4=addressing.get("iran_ipv4"),
        peer_priv_v6=addressing.get("iran_ipv6"),
    )

    client_ports = [str(p) for p in pool_config.get("client_ports", ["2222"])]
    target_ipv6 = kharej_v6

    relay_script, relay_unit = render_relay_service(
        service_name=f"ldbp-isatap-{iface}-relay.service",
        interface=iface,
        peer_ip=target_ipv6,
        ports=[int(p) for p in client_ports],
    )

    return {
        "engine": ENGINE_ID,
        "mode": "isatap",
        "interface": iface,
        "service_name": service_name,
        "mtu": mtu,
        "unit_script": ir_create_cmd,
        "local_ip": iran_ip,
        "remote_ip": kharej_ip,
        "private_subnet": prefix,
        "prefix": prefix,
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
        "iran_systemd_unit": iran_unit,
        "kharej_systemd_unit": kharej_unit,
        "relay_service_unit": relay_unit,
        "relay_script": relay_script,
    }
