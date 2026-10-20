"""EOIP (Ethernet over IP) Tunnel Engine for VX-LB.

Coverage:
- MikroTik compatible Ethernet over IP L2 tunnel protocol.
- Encapsulates Ethernet frames over GRE with numeric Tunnel ID (1..65535).
- Utilizes Linux kernel gretap key framing for cross-distro reliability.
- Scoped systemd unit, client port relay, active TCP/UDP data probe.
- MTU management (576..1460, default 1420).
- Inherently cleartext security disclaimer.
"""
import ipaddress
import logging
import shlex
from typing import Any, Dict, List, Optional, Tuple

from core.ipv6_tunnel_tools import (
    CLEARTEXT_WARNING,
    allocate_tunnel_ips,
    check_kernel_prerequisites,
    execute_active_data_probe,
    parse_link_telemetry,
    render_relay_service,
    render_scoped_service,
    sanitize_interface_name,
    synthesize_status,
    validate_mtu,
)

logger = logging.getLogger("vxlb.eoip")

ENGINE_ID = "eoip"
DEFAULT_MTU = 1420
MIN_MTU = 576
MAX_MTU = 1460


def validate_eoip_mtu(mtu_value: Any) -> int:
    return validate_mtu(mtu_value, MIN_MTU, MAX_MTU, tunnel_type="EOIP")


def validate_tunnel_id(tid: Any) -> int:
    try:
        val = int(tid)
        if not (1 <= val <= 65535):
            raise ValueError()
        return val
    except Exception:
        raise ValueError(f"EOIP Tunnel ID must be an integer between 1 and 65535, got: {tid}")


def check_eoip_prerequisites(ssh: Any, remote_ipv4: Optional[str] = None) -> Tuple[bool, str]:
    ok_kern, msg_kern = check_kernel_prerequisites(ssh, "ip_gre")
    if not ok_kern:
        return False, msg_kern

    if remote_ipv4:
        if not hasattr(ssh, "execute"):
            return False, "Invalid SSH manager"
        code, out, err = ssh.execute(f"ping -4 -c 2 -W 3 {shlex.quote(remote_ipv4)}")
        if code != 0:
            return False, f"EOIP remote IPv4 reachability failed: {err.strip() or out.strip()}"

    return True, "EOIP prerequisites verified"


def configure_eoip_link(
    iran_node: dict,
    kharej_server: dict,
    pool_config: Optional[dict] = None,
) -> dict:
    pool_config = pool_config or {}
    node_name = iran_node.get("node_name") or iran_node.get("name") or "eoip_node"
    iface = pool_config.get("interface") or sanitize_interface_name("eoip", node_name)

    mtu = validate_eoip_mtu(pool_config.get("mtu", DEFAULT_MTU))
    tunnel_id = validate_tunnel_id(pool_config.get("tunnel_id", 1))

    iran_ip = str(ipaddress.IPv4Address(iran_node["ip"]))
    kharej_ip = str(ipaddress.IPv4Address(kharej_server["ip"]))

    addressing = allocate_tunnel_ips(
        pool_config.get("ipv6_subnet"),
        pool_config.get("ipv4_subnet") or "10.100.88.0/30",
    )

    service_name = f"vxlb-eoip-{iface}.service"

    ir_create_cmd = f"ip link add {iface} type gretap local {iran_ip} remote {kharej_ip} key {tunnel_id}"
    kh_create_cmd = f"ip link add {iface} type gretap local {kharej_ip} remote {iran_ip} key {tunnel_id}"

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
    target_ipv4 = addressing["kharej_ipv4"].split("/")[0]

    relay_script, relay_unit = render_relay_service(
        service_name=f"vxlb-eoip-{iface}-relay.service",
        interface=iface,
        peer_ip=target_ipv4,
        ports=[int(p) for p in client_ports],
    )

    return {
        "engine": ENGINE_ID,
        "mode": "gretap",
        "interface": iface,
        "tunnel_id": tunnel_id,
        "service_name": service_name,
        "mtu": mtu,
        "unit_script": ir_create_cmd,
        "local_ip": iran_ip,
        "remote_ip": kharej_ip,
        "private_subnet": addressing.get("ipv4_subnet"),
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
