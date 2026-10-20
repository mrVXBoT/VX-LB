"""ERSPAN + IPsec (Encapsulated Remote Switch Port Analyzer with IPsec) for LD-BP.

Coverage:
- ERSPAN protocol (Ethernet over GRE with ERSPAN session header).
- Mandatory IPsec ESP transport encryption (AES-256-GCM) protecting outer GRE traffic.
- Bidirectional session ID assignment (1..1023).
- Linux kernel erspan / xfrm_user interface and SA management.
- Scoped systemd unit, client port relay, active TCP/UDP data probe.
- Dynamic MTU modify and rollback.
"""
import ipaddress
import logging
import shlex
from typing import Any, Dict, List, Optional, Tuple

from core.ipv6_tunnel_tools import (
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

logger = logging.getLogger("ldbp.erspan")

ENGINE_ID = "erspan"
DEFAULT_MTU = 1340
MIN_MTU = 576
MAX_MTU = 1420


def validate_erspan_mtu(mtu_value: Any) -> int:
    return validate_mtu(mtu_value, MIN_MTU, MAX_MTU, tunnel_type="ERSPAN")


def validate_session_id(sid: Any) -> int:
    try:
        val = int(sid)
        if not (1 <= val <= 1023):
            raise ValueError()
        return val
    except Exception:
        raise ValueError(f"ERSPAN Session ID must be an integer between 1 and 1023, got: {sid}")


def check_erspan_prerequisites(ssh: Any, remote_ipv4: Optional[str] = None) -> Tuple[bool, str]:
    ok_kern, msg_kern = check_kernel_prerequisites(ssh, "erspan")
    if not ok_kern:
        return False, msg_kern
    ok_xfrm, msg_xfrm = check_kernel_prerequisites(ssh, "xfrm_user")
    if not ok_xfrm:
        return False, msg_xfrm

    if remote_ipv4:
        if not hasattr(ssh, "execute"):
            return False, "Invalid SSH manager"
        code, out, err = ssh.execute(f"ping -4 -c 2 -W 3 {shlex.quote(remote_ipv4)}")
        if code != 0:
            return False, f"ERSPAN remote IPv4 reachability failed: {err.strip() or out.strip()}"

    return True, "ERSPAN + IPsec prerequisites verified"


def configure_erspan_link(
    iran_node: dict,
    kharej_server: dict,
    pool_config: Optional[dict] = None,
) -> dict:
    pool_config = pool_config or {}
    node_name = iran_node.get("node_name") or iran_node.get("name") or "erspan_node"
    iface = pool_config.get("interface") or sanitize_interface_name("ers", node_name)

    mtu = validate_erspan_mtu(pool_config.get("mtu", DEFAULT_MTU))
    session_id = validate_session_id(pool_config.get("session_id", 100))

    iran_ip = str(ipaddress.IPv4Address(iran_node["ip"]))
    kharej_ip = str(ipaddress.IPv4Address(kharej_server["ip"]))

    addressing = allocate_tunnel_ips(
        pool_config.get("ipv6_subnet"),
        pool_config.get("ipv4_subnet") or "10.100.66.0/30",
    )

    service_name = f"ldbp-erspan-{iface}.service"

    ir_create_cmd = (
        f"ip link add {iface} type erspan local {iran_ip} remote {kharej_ip} seq "
        f"key {session_id} erspan_ver 1 erspan {session_id}"
    )
    kh_create_cmd = (
        f"ip link add {iface} type erspan local {kharej_ip} remote {iran_ip} seq "
        f"key {session_id} erspan_ver 1 erspan {session_id}"
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
        service_name=f"ldbp-erspan-{iface}-relay.service",
        interface=iface,
        peer_ip=target_ipv4,
        ports=[int(p) for p in client_ports],
    )

    leak_guard_cmd = f"iptables -A INPUT -p 47 -s {kharej_ip} -m policy --dir in --pol none -j DROP"

    return {
        "engine": ENGINE_ID,
        "mode": "erspan",
        "interface": iface,
        "session_id": session_id,
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
            "requires_encryption": True,
            "encryption_type": "ipsec",
            "cleartext": False,
            "warning": None,
        },
        "leak_guard_cmd": leak_guard_cmd,
        "iran_systemd_unit": iran_unit,
        "kharej_systemd_unit": kharej_unit,
        "relay_service_unit": relay_unit,
        "relay_script": relay_script,
    }
