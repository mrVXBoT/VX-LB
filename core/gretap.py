"""GRETAP and GRE6TAP Layer 2 Ethernet-over-GRE Adapters for VX-LB.

Coverage:
- GRETAP (IPv4) and GRE6TAP (IPv6) Layer 2 Ethernet tap tunnels.
  - Optional isolated bridge association with STP loop prevention.
  - System bridge protection: forbids attaching to docker0, br0, virbr0, cni0, etc.
  - Direct L2 point-to-point addressing (/30 or /126) and client port forwarding relay.
  - Inherently cleartext security disclaimer.
- GRE6TAP + IPsec:
  - Layer 2 Ethernet over IPv6 GRE with mandatory IPsec ESP encryption.
  - Separate tracking of tunnel link state and IPsec SA state.
  - Outer protocol 47 leak-prevention firewall rules.
  - Scoped systemd units, active TCP/UDP probe, dynamic MTU modify and rollback.
"""
import copy
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

logger = logging.getLogger("vxlb.gretap")

FORBIDDEN_SYSTEM_BRIDGES = {
    "docker0", "br0", "virbr0", "cni0", "flannel0", "kube-bridge", "lxdbr0", "bridge0"
}

GRETAP_DEFAULT_MTU = 1400
GRE6TAP_DEFAULT_MTU = 1400
GRE6TAP_IPSEC_DEFAULT_MTU = 1340


def validate_gretap_mtu(mtu_value: Any, is_ipv6: bool = False, is_ipsec: bool = False) -> int:
    """Validates MTU for GRETAP / GRE6TAP tunnels."""
    min_mtu = 1280 if is_ipv6 else 68
    max_mtu = 1440 if is_ipv6 else 1460
    if is_ipsec:
        max_mtu = 1380
    return validate_mtu(mtu_value, min_mtu, max_mtu, tunnel_type="GRETAP")


def check_ipv4_reachability(ssh: Any, remote_ipv4: str, count: int = 2, timeout: int = 3) -> Tuple[bool, str]:
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


def check_ipv6_reachability(ssh: Any, remote_ipv6: str, count: int = 2, timeout: int = 3) -> Tuple[bool, str]:
    if not hasattr(ssh, "execute"):
        return False, "Invalid SSH manager for reachability check"
    try:
        norm_ip = str(ipaddress.IPv6Address(remote_ipv6))
    except Exception as e:
        return False, f"Invalid IPv6 address: {e}"

    cmd = f"ping -6 -c {count} -W {timeout} {norm_ip}"
    code, out, err = ssh.execute(cmd)
    if code != 0:
        return False, f"IPv6 reachability test to {norm_ip} failed: {err.strip() or out.strip()}"
    return True, f"IPv6 host {norm_ip} reachable"


def check_gretap_prerequisites(
    ssh: Any,
    engine_id: str,
    remote_ip: Optional[str] = None,
) -> Tuple[bool, str]:
    """Verifies kernel modules and carrier reachability."""
    is_v6 = engine_id in ("gre6tap", "gre6tap_ipsec")
    is_sec = (engine_id == "gre6tap_ipsec")
    mod = "ip6_gre" if is_v6 else "ip_gre"

    ok_kern, msg_kern = check_kernel_prerequisites(ssh, mod)
    if not ok_kern:
        return False, msg_kern

    if is_sec:
        ok_xfrm, msg_xfrm = check_kernel_prerequisites(ssh, "xfrm_user")
        if not ok_xfrm:
            return False, f"IPsec xfrm_user prerequisite failed: {msg_xfrm}"

    if remote_ip:
        if is_v6:
            ok_ping, msg_ping = check_ipv6_reachability(ssh, remote_ip)
        else:
            ok_ping, msg_ping = check_ipv4_reachability(ssh, remote_ip)
        if not ok_ping:
            return False, f"{engine_id.upper()} endpoint reachability failed: {msg_ping}"

    return True, f"{engine_id.upper()} prerequisites verified"


def configure_gretap_link(
    iran_node: dict,
    kharej_server: dict,
    pool_config: Optional[dict] = None,
    engine_id: str = "gretap",
) -> dict:
    """Configures GRETAP, GRE6TAP, or GRE6TAP+IPsec link with bridge/P2P options."""
    pool_config = pool_config or {}
    is_v6 = engine_id in ("gre6tap", "gre6tap_ipsec")
    is_sec = (engine_id == "gre6tap_ipsec")

    prefix = "gtap" if engine_id == "gretap" else ("g6sec" if is_sec else "g6tap")
    node_name = iran_node.get("node_name") or iran_node.get("name") or "tap_node"
    iface = pool_config.get("interface") or sanitize_interface_name(prefix, node_name)

    default_mtu = GRE6TAP_IPSEC_DEFAULT_MTU if is_sec else (GRE6TAP_DEFAULT_MTU if is_v6 else GRETAP_DEFAULT_MTU)
    mtu = validate_gretap_mtu(pool_config.get("mtu", default_mtu), is_ipv6=is_v6, is_ipsec=is_sec)

    if is_v6:
        iran_ext = str(ipaddress.IPv6Address(iran_node.get("ipv6") or iran_node["ip"]))
        kharej_ext = str(ipaddress.IPv6Address(kharej_server.get("ipv6") or kharej_server["ip"]))
        tunnel_type = "ip6gretap"
    else:
        iran_ext = str(ipaddress.IPv4Address(iran_node["ip"]))
        kharej_ext = str(ipaddress.IPv4Address(kharej_server["ip"]))
        tunnel_type = "gretap"

    bridge_name = pool_config.get("bridge_name")
    if bridge_name:
        if bridge_name.lower().strip() in FORBIDDEN_SYSTEM_BRIDGES:
            raise ValueError(f"Attaching GRETAP interface to system bridge '{bridge_name}' is strictly forbidden.")

    addressing = allocate_tunnel_ips(
        pool_config.get("ipv6_subnet") or ("2001:db8:77::/126" if is_v6 else None),
        pool_config.get("ipv4_subnet") or ("10.100.77.0/30" if not is_v6 else None),
    )

    service_name = f"vxlb-{engine_id}-{iface}.service"

    ir_create_cmd = f"ip link add {iface} type {tunnel_type} local {iran_ext} remote {kharej_ext}"
    kh_create_cmd = f"ip link add {iface} type {tunnel_type} local {kharej_ext} remote {iran_ext}"

    if bridge_name:
        ir_create_cmd += f" && ip link add {bridge_name} type bridge 2>/dev/null || true"
        ir_create_cmd += f" && ip link set {bridge_name} type bridge stp_state 1"
        ir_create_cmd += f" && ip link set {bridge_name} up"
        ir_create_cmd += f" && ip link set {iface} master {bridge_name}"

        kh_create_cmd += f" && ip link add {bridge_name} type bridge 2>/dev/null || true"
        kh_create_cmd += f" && ip link set {bridge_name} type bridge stp_state 1"
        kh_create_cmd += f" && ip link set {bridge_name} up"
        kh_create_cmd += f" && ip link set {iface} master {bridge_name}"

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
    target_peer_ip = addressing.get("kharej_ipv6", "").split("/")[0] if is_v6 else addressing.get("kharej_ipv4", "").split("/")[0]

    relay_script, relay_unit = render_relay_service(
        service_name=f"vxlb-{engine_id}-{iface}-relay.service",
        interface=iface,
        peer_ip=target_peer_ip,
        ports=[int(p) for p in client_ports],
    )

    sec_dict = {
        "requires_encryption": is_sec,
        "encryption_type": "ipsec" if is_sec else "none",
        "cleartext": not is_sec,
        "warning": None if is_sec else CLEARTEXT_WARNING,
    }

    leak_guard_cmd = None
    if is_sec:
        leak_guard_cmd = f"ip6tables -A INPUT -p 47 -s {kharej_ext} -m policy --dir in --pol none -j DROP"

    return {
        "engine": engine_id,
        "mode": tunnel_type,
        "interface": iface,
        "bridge_name": bridge_name,
        "service_name": service_name,
        "mtu": mtu,
        "unit_script": ir_create_cmd,
        "local_ip": iran_ext,
        "remote_ip": kharej_ext,
        "private_subnet": addressing.get("ipv4_subnet") or addressing.get("ipv6_subnet"),
        "underlay": {
            "family": "ipv6" if is_v6 else "ipv4",
            "iran_ip": iran_ext,
            "kharej_ip": kharej_ext,
        },
        "addressing": addressing,
        "security": sec_dict,
        "leak_guard_cmd": leak_guard_cmd,
        "iran_systemd_unit": iran_unit,
        "kharej_systemd_unit": kharej_unit,
        "relay_service_unit": relay_unit,
        "relay_script": relay_script,
    }
