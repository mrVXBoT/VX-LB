"""Dedicated Geneve (RFC 8926) tunnel adapter for VX-LB.

Coverage:
- Standalone Geneve Layer 2/3 Overlay over UDP port 6081 (RFC 8926).
- Two reference topology modes:
  1. Point-to-Point Unicast (P2P): direct peer encapsulation with explicit remote IP.
  2. Multi-Server FDB with Bridge (FDB Bridge): VNI overlay with forwarding database (FDB)
     peering, dedicated isolated bridge, and automated loop prevention.
- Security declaration: Inherent cleartext; unencrypted and unauthenticated.
- Preserves system bridges (docker0, br0, virbr0, cni0) and management WAN default routes.
- Full BaseTunnelAdapter contract: install, configure, start, stop, status, probe, modify, rollback, clean.
"""
import copy
import ipaddress
import logging
import re
import shlex
import time
from typing import Any, Dict, List, Optional, Tuple

from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.capabilities import get_capability
from core.geneve_tools import (
    DEFAULT_GENEVE_MTU,
    DEFAULT_GENEVE_PORT,
    DEFAULT_GENEVE_VNI,
    GENEVE_CLEARTEXT_WARNING,
    GENEVE_METHOD_FDB_BRIDGE,
    GENEVE_METHOD_P2P,
    SUPPORTED_GENEVE_METHODS,
    build_geneve_systemd_unit,
    generate_geneve_scripts,
    is_system_or_protected_bridge,
    make_geneve_bridge_name,
    make_geneve_iface,
    validate_dedicated_bridge,
    validate_geneve_method,
    validate_geneve_mtu,
    validate_geneve_port,
    validate_vni,
)
from core.ipv6_tunnel_tools import execute_active_data_probe, parse_link_telemetry, synthesize_status
from core.ssh_client import SSHManager
from core.validation import validate_tunnel_name

logger = logging.getLogger("vxlb.geneve_adapter")


def _normalize_geneve_identifier(identifier: Any) -> Tuple[str, str, str]:
    """Normalize identifier into (clean_id, iface, service_name)."""
    raw = str(identifier).strip()
    if raw.endswith(".service"):
        raw = raw[:-8]
    if raw.startswith("vxlb-geneve-"):
        raw = raw[12:]
    elif raw.startswith("vxlb-"):
        raw = raw[5:]
    if raw.startswith("gnv-"):
        raw_core = raw[4:]
    else:
        raw_core = raw
    clean_candidate = re.sub(r"^[^a-z0-9]+", "", raw_core.lower())
    clean_id = validate_tunnel_name(clean_candidate[:10] if clean_candidate else "node")
    iface = make_geneve_iface(clean_id)
    svc = f"vxlb-geneve-{iface}.service"
    return clean_id, iface, svc


class GeneveDedicatedAdapter(BaseTunnelAdapter):
    """Dedicated adapter for RFC 8926 Geneve tunnels supporting P2P and Multi-Server FDB modes."""

    def __init__(self, engine_id: str = "geneve"):
        super().__init__(engine_id)

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        """Verify prerequisites: geneve and bridge kernel modules, iproute2, and bridge utilities."""
        cmd = (
            "modprobe geneve 2>/dev/null || true; "
            "modprobe bridge 2>/dev/null || true; "
            "which ip systemctl"
        )
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Geneve prerequisites check failed: {err or out}"
        return True, "Geneve kernel module and prerequisites verified"

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        """Generates complete configuration for Geneve tunnel."""
        pool_config = pool_config or {}
        raw_name = iran_node.get("node_name") or iran_node.get("name") or "geneve_node"
        clean_id, iface, svc = _normalize_geneve_identifier(raw_name)

        method = validate_geneve_method(pool_config.get("method", GENEVE_METHOD_P2P))
        vni = validate_vni(pool_config.get("vni", DEFAULT_GENEVE_VNI))
        dst_port = validate_geneve_port(pool_config.get("dst_port", DEFAULT_GENEVE_PORT))
        mtu = validate_geneve_mtu(pool_config.get("mtu", DEFAULT_GENEVE_MTU))

        ir_ip = str(ipaddress.IPv4Address(iran_node["ip"]))
        kh_ip = str(ipaddress.IPv4Address(kharej_server["ip"]))

        # Internal addressing (/30)
        ipv4_subnet = pool_config.get("ipv4_subnet") or "10.201.1.0/30"
        v4_net = ipaddress.IPv4Network(ipv4_subnet, strict=False)
        hosts = list(v4_net.hosts())
        ir_priv = f"{hosts[0]}/{v4_net.prefixlen}"
        kh_priv = f"{hosts[1]}/{v4_net.prefixlen}"

        bridge_name = None
        if method == GENEVE_METHOD_FDB_BRIDGE:
            raw_br = pool_config.get("bridge_name") or make_geneve_bridge_name(iface)
            bridge_name = validate_dedicated_bridge(raw_br)

        fdb_peers = pool_config.get("fdb_peers", [])

        # Generate scripts for Iran and Kharej
        ir_up_path = f"/etc/vxlb/geneve-up-{iface}.sh"
        ir_down_path = f"/etc/vxlb/geneve-down-{iface}.sh"
        ir_up, ir_down = generate_geneve_scripts(
            interface=iface,
            vni=vni,
            dst_port=dst_port,
            mtu=mtu,
            local_underlay_ip=ir_ip,
            remote_underlay_ip=kh_ip,
            method=method,
            local_private_ip=ir_priv,
            peer_private_ip=kh_priv,
            bridge_name=bridge_name,
            fdb_peers=fdb_peers,
        )

        kh_up_path = f"/etc/vxlb/geneve-up-{iface}.sh"
        kh_down_path = f"/etc/vxlb/geneve-down-{iface}.sh"
        kh_up, kh_down = generate_geneve_scripts(
            interface=iface,
            vni=vni,
            dst_port=dst_port,
            mtu=mtu,
            local_underlay_ip=kh_ip,
            remote_underlay_ip=ir_ip,
            method=method,
            local_private_ip=kh_priv,
            peer_private_ip=ir_priv,
            bridge_name=bridge_name,
            fdb_peers=[ir_ip],
        )

        ir_unit = build_geneve_systemd_unit(svc, iface, ir_up_path, ir_down_path)
        kh_unit = build_geneve_systemd_unit(svc, iface, kh_up_path, kh_down_path)

        # Port forwarding relay
        client_ports = [int(p) for p in pool_config.get("client_ports", [2222])]
        target_priv_ip = str(hosts[1])

        from core.ipv6_tunnel_tools import render_relay_service
        relay_script, relay_unit = render_relay_service(
            service_name=f"vxlb-geneve-{iface}-relay.service",
            interface=bridge_name if method == GENEVE_METHOD_FDB_BRIDGE else iface,
            peer_ip=target_priv_ip,
            ports=client_ports,
        )

        return {
            "engine": self.engine_id,
            "rfc": "RFC 8926",
            "method": method,
            "interface": iface,
            "service_name": svc,
            "bridge_name": bridge_name,
            "vni": vni,
            "dst_port": dst_port,
            "mtu": mtu,
            "underlay": {
                "family": "ipv4",
                "iran_ip": ir_ip,
                "kharej_ip": kh_ip,
            },
            "addressing": {
                "ipv4_subnet": str(v4_net),
                "iran_ipv4": ir_priv,
                "kharej_ipv4": kh_priv,
            },
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": GENEVE_CLEARTEXT_WARNING,
            },
            "iran_config": {
                "unit": ir_unit,
                "unit_path": f"/etc/systemd/system/{svc}",
                "up_script": ir_up,
                "up_script_path": ir_up_path,
                "down_script": ir_down,
                "down_script_path": ir_down_path,
                "relay_unit": relay_unit,
                "relay_unit_path": f"/etc/systemd/system/vxlb-geneve-{iface}-relay.service",
                "relay_script": relay_script,
                "relay_script_path": f"/etc/vxlb/{iface}-relay.py",
            },
            "kharej_config": {
                "unit": kh_unit,
                "unit_path": f"/etc/systemd/system/{svc}",
                "up_script": kh_up,
                "up_script_path": kh_up_path,
                "down_script": kh_down,
                "down_script_path": kh_down_path,
            },
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        _, _, svc = _normalize_geneve_identifier(identifier)
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        _, _, svc = _normalize_geneve_identifier(identifier)
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        clean_id, iface, svc = _normalize_geneve_identifier(identifier)

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "rfc": "RFC 8926",
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": GENEVE_CLEARTEXT_WARNING,
            },
            "address_families": {
                "external": "ipv4",
                "internal": ["ipv4"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active Geneve probe unsupported: missing valid SSH connections or target configuration",
                "latency_ms": None,
            }

        kharej_priv_ip = kwargs.get("kharej_private_ip")
        if not kharej_priv_ip and isinstance(endpoint_kh, dict):
            kharej_priv_ip = (
                endpoint_kh.get("private_addressing", {}).get("kharej_ipv4")
                or endpoint_kh.get("kharej_ipv4")
            )

        if not kharej_priv_ip:
            return {
                "passed": False,
                "error": "Active Geneve probe requires target remote private IPv4 address",
                "latency_ms": None,
            }

        target_host = kharej_priv_ip.split("/")[0]
        probe_ports = ports or [2222]

        return execute_active_data_probe(
            iran_ssh=iran_ssh,
            kharej_ssh=kharej_ssh,
            target_ip=target_host,
            ports=probe_ports,
            is_ipv6=False,
        )

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")
        mtu = updates.get("mtu")

        if mtu:
            if not ssh or not raw_iface or not hasattr(ssh, "execute"):
                return False, f"Dynamic modify unsupported for pool '{pool_name}' without live SSH connection"

            try:
                new_mtu = validate_geneve_mtu(mtu)
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            _, iface, svc = _normalize_geneve_identifier(raw_iface)
            ok_cur, _, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            up_script = f"/etc/vxlb/geneve-up-{iface}.sh"
            up_bak = f"/etc/vxlb/geneve-up-{iface}.sh.bak"
            ssh.execute(f"cp {up_script} {up_bak} 2>/dev/null || true")

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live Geneve MTU to {new_mtu}: {err_set}"

            ssh.execute(f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {shlex.quote(up_script)} 2>/dev/null")
            return True, f"Geneve MTU updated to {new_mtu} for {iface}"

        return True, "No supported Geneve modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous geneve snapshot"

        _, iface, _ = _normalize_geneve_identifier(raw_iface)

        if prev_mtu:
            try:
                valid_mtu = validate_geneve_mtu(prev_mtu)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            up_script = f"/etc/vxlb/geneve-up-{iface}.sh"
            up_bak = f"/etc/vxlb/geneve-up-{iface}.sh.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} 2>/dev/null; "
                f"if [ -f {shlex.quote(up_bak)} ]; then cp {shlex.quote(up_bak)} {shlex.quote(up_script)}; fi"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"Geneve rollback failed for {iface}: {err or out}"
            return True, f"Geneve rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        _, iface, svc = _normalize_geneve_identifier(identifier)
        relay_svc = f"vxlb-geneve-{iface}-relay.service"
        br = make_geneve_bridge_name(iface)

        cmd = (
            f"systemctl stop {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null || true; "
            f"systemctl disable {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null || true; "
            f"ip link set {shlex.quote(iface)} nomaster 2>/dev/null || true; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true; "
            f"ip link del {shlex.quote(br)} 2>/dev/null || true; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/systemd/system/{shlex.quote(relay_svc)} "
            f"/etc/vxlb/geneve-up-{shlex.quote(iface)}.sh /etc/vxlb/geneve-down-{shlex.quote(iface)}.sh /etc/vxlb/{shlex.quote(iface)}-relay.py; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    # Multi-Server FDB Management with Loop Prevention
    def add_fdb_peer(self, ssh: SSHManager, interface: str, peer_ip: str, local_underlay_ip: Optional[str] = None) -> Tuple[bool, str]:
        """Adds a remote endpoint to the Geneve FDB with loop prevention."""
        _, iface, _ = _normalize_geneve_identifier(interface)
        peer = str(peer_ip).strip()
        if not peer:
            return False, "Peer IP is required"
        if local_underlay_ip and peer == local_underlay_ip.strip():
            return False, f"Refusing to add self as FDB peer (loop prevention): {peer}"

        cmd = f"bridge fdb append 00:00:00:00:00:00 dev {shlex.quote(iface)} dst {shlex.quote(peer)}"
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Failed adding Geneve FDB peer {peer}: {err or out}"
        return True, f"Geneve FDB peer {peer} added on {iface}"

    def del_fdb_peer(self, ssh: SSHManager, interface: str, peer_ip: str) -> Tuple[bool, str]:
        """Removes a remote endpoint from the Geneve FDB."""
        _, iface, _ = _normalize_geneve_identifier(interface)
        peer = str(peer_ip).strip()
        cmd = f"bridge fdb del 00:00:00:00:00:00 dev {shlex.quote(iface)} dst {shlex.quote(peer)}"
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Failed deleting Geneve FDB peer {peer}: {err or out}"
        return True, f"Geneve FDB peer {peer} removed from {iface}"

    def list_fdb_peers(self, ssh: SSHManager, interface: str) -> List[str]:
        """Lists active FDB peers for the given Geneve interface."""
        _, iface, _ = _normalize_geneve_identifier(interface)
        cmd = f"bridge fdb show dev {shlex.quote(iface)}"
        ok, out, _ = ssh.execute(cmd)
        if ok != 0:
            return []
        peers = []
        for line in out.splitlines():
            m = re.search(r"dst\s+([0-9a-fA-F\.:]+)", line)
            if m:
                peers.append(m.group(1))
        return list(dict.fromkeys(peers))


# Register Geneve dedicated adapter
register_adapter(GeneveDedicatedAdapter())
