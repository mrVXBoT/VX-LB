"""L2TP (Layer 2 Tunneling Protocol / L2TPv3 Ethernet Pseudowire) for LD-BP.

Coverage:
- RFC 3931 L2TPv3 Ethernet pseudowire tunneling over UDP.
- Tunnel ID and Session ID pairing between Iran and Kharej endpoints.
- Linux kernel l2tp_eth / l2tp_netlink interface management.
- Optional IPsec transport encryption or cleartext disclaimer.
- Scoped systemd unit, client port relay, active TCP/UDP data probe.
- Dynamic MTU modify and rollback.
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

logger = logging.getLogger("ldbp.l2tp")

ENGINE_ID = "l2tp"
DEFAULT_MTU = 1380
MIN_MTU = 576
MAX_MTU = 1460
DEFAULT_UDP_PORT = 1701


def validate_l2tp_mtu(mtu_value: Any) -> int:
    return validate_mtu(mtu_value, MIN_MTU, MAX_MTU, tunnel_type="L2TP")


def check_l2tp_prerequisites(ssh: Any, remote_ipv4: Optional[str] = None) -> Tuple[bool, str]:
    ok_kern, msg_kern = check_kernel_prerequisites(ssh, "l2tp_core")
    if not ok_kern:
        return False, msg_kern
    ok_eth, msg_eth = check_kernel_prerequisites(ssh, "l2tp_eth")
    if not ok_eth:
        return False, msg_eth

    if remote_ipv4:
        if not hasattr(ssh, "execute"):
            return False, "Invalid SSH manager"
        code, out, err = ssh.execute(f"ping -4 -c 2 -W 3 {shlex.quote(remote_ipv4)}")
        if code != 0:
            return False, f"L2TP remote IPv4 reachability failed: {err.strip() or out.strip()}"

    return True, "L2TP prerequisites verified"


def configure_l2tp_link(
    iran_node: dict,
    kharej_server: dict,
    pool_config: Optional[dict] = None,
) -> dict:
    pool_config = pool_config or {}
    node_name = iran_node.get("node_name") or iran_node.get("name") or "l2tp_node"
    iface = pool_config.get("interface") or sanitize_interface_name("l2tp", node_name)

    mtu = validate_l2tp_mtu(pool_config.get("mtu", DEFAULT_MTU))
    port = int(pool_config.get("udp_port", DEFAULT_UDP_PORT))

    iran_tid = int(pool_config.get("iran_tunnel_id", 1001))
    kharej_tid = int(pool_config.get("kharej_tunnel_id", 1002))
    iran_sid = int(pool_config.get("iran_session_id", 2001))
    kharej_sid = int(pool_config.get("kharej_session_id", 2002))

    iran_ip = str(ipaddress.IPv4Address(iran_node["ip"]))
    kharej_ip = str(ipaddress.IPv4Address(kharej_server["ip"]))

    addressing = allocate_tunnel_ips(
        pool_config.get("ipv6_subnet"),
        pool_config.get("ipv4_subnet") or "10.100.99.0/30",
    )

    service_name = f"ldbp-l2tp-{iface}.service"

    ir_create_cmd = (
        f"ip l2tp add tunnel tunnel_id {iran_tid} peer_tunnel_id {kharej_tid} "
        f"udp_sport {port} udp_dport {port} encap udp local {iran_ip} remote {kharej_ip} && "
        f"ip l2tp add session tunnel_id {iran_tid} session_id {iran_sid} peer_session_id {kharej_sid} name {iface}"
    )

    kh_create_cmd = (
        f"ip l2tp add tunnel tunnel_id {kharej_tid} peer_tunnel_id {iran_tid} "
        f"udp_sport {port} udp_dport {port} encap udp local {kharej_ip} remote {iran_ip} && "
        f"ip l2tp add session tunnel_id {kharej_tid} session_id {kharej_sid} peer_session_id {iran_sid} name {iface}"
    )

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
        service_name=f"ldbp-l2tp-{iface}-relay.service",
        interface=iface,
        peer_ip=target_ipv4,
        ports=[int(p) for p in client_ports],
    )

    return {
        "engine": ENGINE_ID,
        "mode": "l2tp",
        "interface": iface,
        "udp_port": port,
        "iran_tunnel_id": iran_tid,
        "kharej_tunnel_id": kharej_tid,
        "iran_session_id": iran_sid,
        "kharej_session_id": kharej_sid,
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
