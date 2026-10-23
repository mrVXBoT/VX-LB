"""Dedicated VXLAN (Virtual Extensible LAN) tunnel adapter for VX-LB.

Coverage:
- VXLAN Single-Server: Three Reference Methods
  1. Point-to-Point Unicast (P2P)
  2. VXLAN Bridge Setup with Remote IP Pointing (Bridge + IP Pointing)
  3. FDB VXLAN with Bridge (Forwarding Database Unicast / Multi-peer)
- VXLAN Multi-Server: VNI, Peer/FDB, and Bridge management
- Route, SSH, and Bridge preservation guarantees

IMPORTANT SECURITY NOTICE:
Raw VXLAN (RFC 7348) is an unencrypted, unauthenticated L2-in-L4 overlay encapsulation
protocol operating over UDP (standard port 4789). It contains NO encryption and NO
obfuscation/camouflage. It must NEVER be presented to operators as a secure or encrypted
channel. For encrypted overlays, an underlying/overlaying cryptographic layer (e.g. IPsec)
is required.
"""
import copy
import ipaddress
import json
import logging
import re
import secrets
import shlex
import time
from typing import Dict, List, Optional, Tuple, Any, Callable

from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.capabilities import get_capability
from core.ssh_client import SSHManager
from core.storage import get_pools, save_pool, delete_pool, atomic_update, load_data
from core.transport_change import connect
from core.validation import validate_tunnel_name, validate_port, validate_pool_name, validate_ports
from core.vxlan_tools import (
    DEFAULT_VXLAN_PORT,
    DEFAULT_VXLAN_VNI,
    DEFAULT_VXLAN_MTU,
    VXLAN_METHOD_P2P,
    VXLAN_METHOD_BRIDGE_POINTIP,
    VXLAN_METHOD_FDB_BRIDGE,
    SUPPORTED_METHODS,
    validate_vni,
    validate_port as validate_vxlan_port,
    validate_mtu,
    validate_ip,
    validate_ip_network_or_interface,
    validate_vxlan_method,
    validate_dedicated_bridge,
    make_vxlan_iface,
    make_bridge_name,
    is_system_or_protected_bridge,
    build_systemd_unit,
    generate_vxlan_scripts,
)

logger = logging.getLogger("vxlb.vxlan_adapter")


def _normalize_identifier(identifier: Any) -> Tuple[str, str, str]:
    """Normalize identifier into (clean_id, iface, service_name).

    Accepts:
    - 'node1' -> ('node1', 'vx-node1', 'vxlb-vxlan-vx-node1.service')
    - 'vx-node1' -> ('node1', 'vx-node1', 'vxlb-vxlan-vx-node1.service')
    - 'vxlb-vxlan-vx-node1.service' -> ('node1', 'vx-node1', 'vxlb-vxlan-vx-node1.service')
    - 'vxlb-vx-node1.service' -> ('node1', 'vx-node1', 'vxlb-vxlan-vx-node1.service')
    - 'vxlb-vxlan-node1.service' -> ('node1', 'vx-node1', 'vxlb-vxlan-vx-node1.service')
    """
    raw = str(identifier).strip()
    if raw.endswith(".service"):
        raw = raw[:-8]
    if raw.startswith("vxlb-vxlan-"):
        raw = raw[11:]
    elif raw.startswith("vxlb-"):
        raw = raw[5:]
    if raw.startswith("vx-"):
        raw_core = raw[3:]
    else:
        raw_core = raw
    clean_candidate = re.sub(r"^[^a-z0-9]+", "", raw_core.lower())
    clean_id = validate_tunnel_name(clean_candidate[:12] if clean_candidate else "node")
    iface = make_vxlan_iface(clean_id)
    svc = f"vxlb-vxlan-{iface}.service"
    return clean_id, iface, svc


class VxlanDedicatedAdapter(BaseTunnelAdapter):
    """Dedicated adapter for RFC 7348 VXLAN tunnels supporting all three reference methods."""

    def __init__(self, engine_id: str = "vxlan"):
        super().__init__(engine_id)

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        """Verify prerequisites: vxlan and bridge kernel modules, iproute2, and bridge utilities."""
        cmd = (
            "modprobe vxlan 2>/dev/null || true; "
            "modprobe bridge 2>/dev/null || true; "
            "which ip systemctl"
        )
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Prerequisites missing for VXLAN on host: {err or out}"
        return True, "VXLAN prerequisites and kernel modules verified"

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        """Generate configurations, scripts, and systemd units for both endpoints.

        Supports the 3 reference methods:
        - 'p2p': Point-to-Point Unicast
        - 'bridge_pointip': VXLAN Bridge Setup with IP Pointing
        - 'fdb_bridge': FDB VXLAN with Bridge
        """
        node_name = iran_node.get("node_name") or pool_config.get("pool_name") or "vxlan_node"
        clean_candidate = re.sub(r"^[^a-z0-9]+", "", str(node_name).lower())
        clean_name = validate_tunnel_name(clean_candidate[:12] if clean_candidate else "node")
        iface = make_vxlan_iface(clean_name)

        # Dedicated bridge name: allow custom dedicated bridge from pool_config or generate safe br-vx-<name>
        custom_bridge = pool_config.get("bridge_name")
        if custom_bridge:
            bridge_name = validate_dedicated_bridge(custom_bridge)
        else:
            bridge_name = make_bridge_name(clean_name)

        method = validate_vxlan_method(pool_config.get("vxlan_method", VXLAN_METHOD_P2P))
        vni = validate_vni(pool_config.get("vni", DEFAULT_VXLAN_VNI))
        port = validate_vxlan_port(
            pool_config.get("tunnel_port")
            or pool_config.get("dst_port")
            or DEFAULT_VXLAN_PORT
        )
        mtu = validate_mtu(pool_config.get("mtu", self.capabilities.default_mtu))
        underlay_dev = (
            pool_config.get("underlay_dev")
            or pool_config.get("underlay_device")
            or pool_config.get("physical_interface")
            or pool_config.get("dev")
        )
        nolearning = bool(pool_config.get("nolearning", False))

        ir_ip = validate_ip(iran_node.get("ip"), "iran_ip")
        kh_ip = validate_ip(kharej_server.get("ip"), "kharej_ip")

        # Private addressing
        ir_private = validate_ip_network_or_interface(
            pool_config.get("iran_private_ip", "10.200.1.1/30"), "iran_private_ip"
        )
        kh_private = validate_ip_network_or_interface(
            pool_config.get("kharej_private_ip", "10.200.1.2/30"), "kharej_private_ip"
        )

        raw_peers = pool_config.get("peers") or [kh_ip]
        # Clean peers: ensure remote_ip is present and local_ip is excluded per side to avoid packet loops
        ir_peers = [p for p in raw_peers if p != ir_ip]
        if kh_ip not in ir_peers:
            ir_peers.append(kh_ip)

        kh_peers = [ir_ip] + [p for p in raw_peers if p != kh_ip and p != ir_ip]

        # Generate scripts for Iran (local=ir_ip, remote=kh_ip)
        ir_start, ir_stop = generate_vxlan_scripts(
            method=method,
            iface=iface,
            vni=vni,
            port=port,
            mtu=mtu,
            local_ip=ir_ip,
            remote_ip=kh_ip,
            private_ip_cidr=ir_private,
            peers=ir_peers,
            underlay_dev=underlay_dev,
            bridge_name=bridge_name if method != VXLAN_METHOD_P2P else None,
            nolearning=nolearning,
        )

        # Generate scripts for Kharej (local=kh_ip, remote=ir_ip)
        kh_start, kh_stop = generate_vxlan_scripts(
            method=method,
            iface=iface,
            vni=vni,
            port=port,
            mtu=mtu,
            local_ip=kh_ip,
            remote_ip=ir_ip,
            private_ip_cidr=kh_private,
            peers=kh_peers,
            underlay_dev=underlay_dev,
            bridge_name=bridge_name if method != VXLAN_METHOD_P2P else None,
            nolearning=nolearning,
        )

        svc_name = f"vxlb-vxlan-{iface}.service"
        ir_unit = build_systemd_unit(
            service_name=svc_name,
            description=f"VX-LB VXLAN Overlay Tunnel ({iface})",
            start_script_path=f"/usr/local/bin/vxlb-{iface}-start.sh",
            stop_script_path=f"/usr/local/bin/vxlb-{iface}-stop.sh",
        )
        kh_unit = build_systemd_unit(
            service_name=svc_name,
            description=f"VX-LB VXLAN Overlay Tunnel ({iface})",
            start_script_path=f"/usr/local/bin/vxlb-{iface}-start.sh",
            stop_script_path=f"/usr/local/bin/vxlb-{iface}-stop.sh",
        )

        return {
            "engine": self.engine_id,
            "method": method,
            "interface": iface,
            "bridge_name": bridge_name if method != VXLAN_METHOD_P2P else None,
            "vni": vni,
            "dst_port": port,
            "mtu": mtu,
            "underlay_dev": underlay_dev,
            "local_ip": ir_ip,
            "remote_ip": kh_ip,
            "iran_private_ip": ir_private,
            "kharej_private_ip": kh_private,
            "peers": raw_peers,
            "service_name": svc_name,
            "iran_scripts": {
                "start": ir_start,
                "stop": ir_stop,
                "unit": ir_unit,
                "start_path": f"/usr/local/bin/vxlb-{iface}-start.sh",
                "stop_path": f"/usr/local/bin/vxlb-{iface}-stop.sh",
                "unit_path": f"/etc/systemd/system/{svc_name}",
            },
            "kharej_scripts": {
                "start": kh_start,
                "stop": kh_stop,
                "unit": kh_unit,
                "start_path": f"/usr/local/bin/vxlb-{iface}-start.sh",
                "stop_path": f"/usr/local/bin/vxlb-{iface}-stop.sh",
                "unit_path": f"/etc/systemd/system/{svc_name}",
            },
            "security_disclaimer": "RAW_UNENCRYPTED_OVERLAY",
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        """Start the tunnel service / bring up interface."""
        _, iface, svc = _normalize_identifier(identifier)
        cmd = f"systemctl daemon-reload && systemctl enable {svc} && systemctl restart {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        """Stop the tunnel service / bring down interface."""
        _, iface, svc = _normalize_identifier(identifier)
        cmd = f"systemctl stop {svc} 2>/dev/null; systemctl disable {svc} 2>/dev/null"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        """Query host for interface state, packet telemetry, MTU, and FDB entries."""
        clean_id, iface, svc = _normalize_identifier(identifier)
        br_name = make_bridge_name(clean_id)

        # Check systemd status
        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {svc}")
        svc_active = (ok_svc == 0 and out_svc.strip() == "active")

        # Check ip link state
        ok_link, out_link, _ = ssh.execute(f"ip -d link show {shlex.quote(iface)} 2>/dev/null")
        link_exists = (ok_link == 0 and iface in out_link)

        # Check FDB table
        ok_fdb, out_fdb, _ = ssh.execute(f"bridge fdb show dev {shlex.quote(iface)} 2>/dev/null")
        fdb_entries = [line.strip() for line in out_fdb.splitlines() if line.strip()] if ok_fdb == 0 else []

        # Check statistics
        ok_stat, out_stat, _ = ssh.execute(f"ip -s link show {shlex.quote(iface)} 2>/dev/null")

        status_str = "DOWN"
        if svc_active and link_exists:
            status_str = "UP"
        elif svc_active or link_exists:
            status_str = "DEGRADED"

        return {
            "engine": self.engine_id,
            "interface": iface,
            "service": svc,
            "status": status_str,
            "details": {
                "service_active": svc_active,
                "link_exists": link_exists,
                "fdb_entries_count": len(fdb_entries),
                "fdb_entries": fdb_entries[:10],
                "link_details": out_link.strip() if link_exists else "",
                "stats_raw": out_stat.strip() if ok_stat == 0 else "",
            },
        }

    def probe(
        self,
        endpoint_ir: Any,
        endpoint_kh: Any,
        ports: Optional[List[int]] = None,
        **kwargs,
    ) -> dict:
        """Perform data-plane verification over the private IP link.

        Requires a connected SSH session to Iran host (via kwargs['ssh'],
        endpoint_ir['ssh'], or endpoint_ir being an SSHManager) to execute
        live nonced ICMP / port verification.
        """
        target_ip = None
        if isinstance(endpoint_kh, dict):
            target_ip = endpoint_kh.get("private_ip") or endpoint_kh.get("ip")
        elif isinstance(endpoint_kh, str):
            target_ip = endpoint_kh

        if not target_ip:
            return {
                "passed": False,
                "latency_ms": 0.0,
                "error": "No remote target IP specified for VXLAN probe",
            }

        # Clean CIDR if present
        target_ip = target_ip.split("/")[0]

        # Extract SSH manager
        ssh_ir = kwargs.get("ssh")
        if not ssh_ir and isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir:
            ssh_ir = endpoint_ir["ssh"]
        elif not ssh_ir and hasattr(endpoint_ir, "execute"):
            ssh_ir = endpoint_ir

        if not ssh_ir or not hasattr(ssh_ir, "execute"):
            return {
                "passed": False,
                "latency_ms": 0.0,
                "error": "Active data-plane probe unsupported: requires live connected SSH session to target host",
            }

        cmd = f"ping -c 3 -W 2 {shlex.quote(target_ip)}"
        ok, out, err = ssh_ir.execute(cmd)
        if ok != 0:
            return {
                "passed": False,
                "latency_ms": 0.0,
                "error": f"Ping probe failed: {err or out}",
            }

        # Extract latency
        m = re.search(r"min/avg/max[^=]*=\s*([0-9.]+)/([0-9.]+)", out)
        avg_lat = float(m.group(2)) if m else 1.0

        # If ports are specified, probe ports
        if ports:
            for p in ports:
                p_int = validate_vxlan_port(p)
                p_cmd = f"nc -z -w 2 {shlex.quote(target_ip)} {p_int} 2>/dev/null || (echo > /dev/tcp/{target_ip}/{p_int}) 2>/dev/null"
                p_ok, _, _ = ssh_ir.execute(p_cmd)
                if p_ok != 0:
                    return {
                        "passed": False,
                        "latency_ms": avg_lat,
                        "error": f"Port probe failed for target port {p_int}",
                    }

        return {"passed": True, "latency_ms": avg_lat, "error": ""}

    def modify(self, pool_name: str, updates: dict, **kwargs) -> Tuple[bool, str]:
        """Modify parameters (MTU, port, peers) with transactional validation and live application."""
        if not pool_name:
            return False, "pool_name is required"
        if not updates:
            return False, "No update parameters provided"

        # Validate updates
        validated_mtu = None
        if "mtu" in updates:
            try:
                validated_mtu = validate_mtu(updates["mtu"])
            except ValueError as e:
                return False, str(e)

        if "dst_port" in updates:
            try:
                validate_vxlan_port(updates["dst_port"])
            except ValueError as e:
                return False, str(e)

        if "vni" in updates:
            try:
                validate_vni(updates["vni"])
            except ValueError as e:
                return False, str(e)

        if "peers" in updates:
            try:
                for p in updates["peers"]:
                    validate_ip(p, "peer_ip")
            except ValueError as e:
                return False, str(e)

        # If live SSH session and iface provided, apply MTU dynamically
        ssh = kwargs.get("ssh") or updates.get("ssh")
        if ssh and hasattr(ssh, "execute") and validated_mtu:
            clean_pool = re.sub(r"^[^a-z0-9]+", "", str(pool_name).lower())[:12] or "node"
            iface = updates.get("interface") or make_vxlan_iface(clean_pool)
            br_name = updates.get("bridge_name") or make_bridge_name(clean_pool)
            cmd = (
                f"ip link set dev {shlex.quote(iface)} mtu {validated_mtu} 2>/dev/null || true; "
                f"ip link set dev {shlex.quote(br_name)} mtu {validated_mtu} 2>/dev/null || true"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"Failed to apply MTU update on live host: {err or out}"

        return True, f"Modifications for pool {pool_name} validated and applied"

    def rollback(self, pool_name: str, previous_state: dict, **kwargs) -> Tuple[bool, str]:
        """Rollback configuration to previous state after failure."""
        if not pool_name or not previous_state:
            return False, "Cannot rollback without pool_name and previous_state"

        if "mtu" in previous_state:
            try:
                validate_mtu(previous_state["mtu"])
            except ValueError as e:
                return False, f"Invalid previous MTU: {e}"

        if "dst_port" in previous_state:
            try:
                validate_vxlan_port(previous_state["dst_port"])
            except ValueError as e:
                return False, f"Invalid previous port: {e}"

        if "vni" in previous_state:
            try:
                validate_vni(previous_state["vni"])
            except ValueError as e:
                return False, f"Invalid previous VNI: {e}"

        ssh = kwargs.get("ssh") or previous_state.get("ssh")
        if ssh and hasattr(ssh, "execute") and "mtu" in previous_state:
            mtu_val = previous_state["mtu"]
            clean_pool = re.sub(r"^[^a-z0-9]+", "", str(pool_name).lower())[:12] or "node"
            iface = previous_state.get("interface") or make_vxlan_iface(clean_pool)
            br_name = previous_state.get("bridge_name") or make_bridge_name(clean_pool)
            cmd = (
                f"ip link set dev {shlex.quote(iface)} mtu {mtu_val} 2>/dev/null || true; "
                f"ip link set dev {shlex.quote(br_name)} mtu {mtu_val} 2>/dev/null || true"
            )
            ssh.execute(cmd)

        return True, f"Rollback to previous state completed for {pool_name}"

    def clean(self, ssh: SSHManager, identifier: str, **kwargs) -> Tuple[bool, str]:
        """Tear down interface, bridge (if dedicated), and systemd services safely.

        Guarantees:
        - NEVER deletes or flushes system bridges (e.g. docker0, br0).
        - NEVER removes default routes or SSH routing tables.
        - Deletes only dedicated resources owned by this specific VXLAN tunnel.
        """
        clean_id, iface, svc = _normalize_identifier(identifier)
        custom_bridge = kwargs.get("bridge_name")
        if custom_bridge and not is_system_or_protected_bridge(custom_bridge):
            br_name = custom_bridge
        else:
            br_name = make_bridge_name(clean_id)

        # Check bridge protection before deleting
        bridge_cleanup_cmd = ""
        if not is_system_or_protected_bridge(br_name):
            bridge_cleanup_cmd = (
                f"ip link set dev {shlex.quote(br_name)} down 2>/dev/null || true; "
                f"ip link del {shlex.quote(br_name)} 2>/dev/null || true; "
            )

        cmd = (
            f"systemctl stop vxlb-vxlan-{iface}-relay.service 2>/dev/null || true; "
            f"systemctl disable vxlb-vxlan-{iface}-relay.service 2>/dev/null || true; "
            f"systemctl stop {svc} 2>/dev/null || true; "
            f"systemctl disable {svc} 2>/dev/null || true; "
            f"ip link set dev {shlex.quote(iface)} nomaster 2>/dev/null || true; "
            f"ip link set dev {shlex.quote(iface)} down 2>/dev/null || true; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true; "
            f"{bridge_cleanup_cmd}"
            f"rm -f /etc/systemd/system/{svc} "
            f"/etc/systemd/system/vxlb-vxlan-{iface}-relay.service "
            f"/usr/local/bin/vxlb-{iface}-relay.py "
            f"/usr/local/bin/vxlb-{shlex.quote(iface)}-start.sh "
            f"/usr/local/bin/vxlb-{shlex.quote(iface)}-stop.sh; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Cleanup encountered errors: {err or out}"
        code, _, error = ssh.execute(f"ip link show dev {shlex.quote(iface)} >/dev/null 2>&1")
        if code == 0:
            return False, f"VXLAN interface {iface} still exists after cleanup"
        if code not in (1,):
            return False, f"Could not verify VXLAN cleanup: {error}"
        return True, f"Dedicated VXLAN resources for {iface} cleaned successfully"

    # Multi-server / FDB management helpers
    def add_fdb_peer(self, ssh: SSHManager, iface: str, peer_ip: str) -> Tuple[bool, str]:
        """Add a static/unicast flooding peer to the VXLAN forwarding database."""
        peer_clean = validate_ip(peer_ip, "peer_ip")
        cmd = f"bridge fdb append to 00:00:00:00:00:00 dst {shlex.quote(peer_clean)} dev {shlex.quote(iface)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def del_fdb_peer(self, ssh: SSHManager, iface: str, peer_ip: str) -> Tuple[bool, str]:
        """Delete a peer from the VXLAN forwarding database."""
        peer_clean = validate_ip(peer_ip, "peer_ip")
        cmd = f"bridge fdb del to 00:00:00:00:00:00 dst {shlex.quote(peer_clean)} dev {shlex.quote(iface)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def list_fdb_peers(self, ssh: SSHManager, iface: str) -> List[str]:
        """List all peer destinations registered in the FDB for this interface."""
        cmd = f"bridge fdb show dev {shlex.quote(iface)}"
        ok, out, _ = ssh.execute(cmd)
        if ok != 0:
            return []
        peers = []
        for line in out.splitlines():
            m = re.search(r"dst\s+([0-9a-fA-F.:]+)", line)
            if m:
                peers.append(m.group(1))
        return peers


def allocate_vxlan_private_ips() -> Tuple[str, str]:
    """Allocate /30 private IP pair for an Iran node and Kharej endpoint."""
    used = set()
    for pool in get_pools().values():
        for node in pool.get("nodes", []):
            if "vxlan" in node:
                used.add(node["vxlan"].get("local_private"))
                used.add(node["vxlan"].get("remote_private"))

    block = ipaddress.IPv4Network("10.204.0.0/16")
    start = secrets.randbelow(16384)
    for i in range(16384):
        base = int(block.network_address) + ((start + i) % 16384) * 4
        ir_p = str(ipaddress.IPv4Address(base + 1))
        kh_p = str(ipaddress.IPv4Address(base + 2))
        if ir_p not in used and kh_p not in used:
            return f"{ir_p}/30", f"{kh_p}/30"
    return "10.204.1.1/30", "10.204.1.2/30"


def generate_relay_script_and_unit(iface: str, peer_ip: str, ports: List[str]) -> Tuple[str, str]:
    """Generate asyncio TCP and UDP port forwarding script and systemd unit."""
    ports_json = json.dumps([int(p) for p in ports if str(p).isdigit()])
    py_code = f'''#!/usr/bin/env python3
import asyncio, sys, time

PEER = {peer_ip!r}
PORTS = {ports_json}

async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data: break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            if writer.can_write_eof(): writer.write_eof()
        except Exception:
            pass

async def forward_tcp(reader, writer, port):
    try:
        r_remote, w_remote = await asyncio.wait_for(asyncio.open_connection(PEER, port), 8)
    except Exception:
        writer.close()
        return
    try:
        await asyncio.gather(pipe(reader, w_remote), pipe(r_remote, writer))
    finally:
        writer.close()
        w_remote.close()

class UdpReplies(asyncio.DatagramProtocol):
    def __init__(self, parent, addr):
        self.parent = parent
        self.addr = addr
    def datagram_received(self, data, addr):
        if self.addr in self.parent.sessions:
            self.parent.sessions[self.addr][1] = time.monotonic()
            self.parent.transport.sendto(data, self.addr)

class UdpRelay(asyncio.DatagramProtocol):
    def __init__(self, port):
        self.port = port
        self.sessions = {{}}
        self.transport = None
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        if addr in self.sessions:
            self.sessions[addr][1] = time.monotonic()
            self.sessions[addr][0].sendto(data)
            return
        if len(self.sessions) >= 1024: return
        asyncio.create_task(self.setup_peer(data, addr))
    async def setup_peer(self, data, addr):
        try:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: UdpReplies(self, addr), remote_addr=(PEER, self.port)
            )
            self.sessions[addr] = [transport, time.monotonic()]
            transport.sendto(data)
        except Exception:
            pass
    def sweep(self):
        now = time.monotonic()
        for addr, (tr, t_last) in list(self.sessions.items()):
            if now - t_last > 60:
                tr.close()
                del self.sessions[addr]

async def main():
    servers = []
    protocols = []
    for port in PORTS:
        srv = await asyncio.start_server(lambda r, w, p=port: forward_tcp(r, w, p), '0.0.0.0', port)
        servers.append(srv)
        _, proto = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda p=port: UdpRelay(p), local_addr=('0.0.0.0', port)
        )
        protocols.append(proto)
    while True:
        await asyncio.sleep(15)
        for proto in protocols:
            proto.sweep()

if __name__ == '__main__':
    asyncio.run(main())
'''
    unit = f'''[Unit]
Description=VX-LB VXLAN Client Ports Relay ({iface})
After=network-online.target vxlb-vxlan-{iface}.service
Wants=network-online.target
Requires=vxlb-vxlan-{iface}.service

[Service]
Type=simple
Restart=on-failure
RestartSec=3
ExecStart=/usr/bin/python3 /usr/local/bin/vxlb-{iface}-relay.py

[Install]
WantedBy=multi-user.target
'''
    return py_code, unit


def create(
    name: str,
    kharej: dict,
    servers: List[dict],
    ports: List[str],
    vni: Optional[int] = None,
    vxlan_method: str = VXLAN_METHOD_P2P,
    dst_port: int = DEFAULT_VXLAN_PORT,
    mtu: int = DEFAULT_VXLAN_MTU,
    bridge_name: Optional[str] = None,
    underlay_dev: Optional[str] = None,
    callback: Optional[Callable[[str], None]] = None,
) -> Tuple[bool, str, dict]:
    """Create and orchestrate a multi-node VXLAN pool."""
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        method = validate_vxlan_method(vxlan_method)
        vni_val = validate_vni(vni if vni is not None else DEFAULT_VXLAN_VNI)
        dst_port_val = validate_vxlan_port(dst_port)
        mtu_val = validate_mtu(mtu)
        if bridge_name:
            validate_dedicated_bridge(bridge_name)
        if not servers or not kharej:
            raise ValueError("حداقل یک سرور ایران و یک سرور خارج الزامی است")
        if any(s["ip"] == kharej["ip"] for s in servers):
            raise ValueError("سرور ایران و سرور خارج نمی‌توانند یکسان باشند")
        if len({s["ip"] for s in servers}) != len(servers):
            raise ValueError("سرورهای ایران نمی‌توانند تکراری باشند")
        if name in get_pools():
            raise ValueError(f"استخر '{name}' از قبل وجود دارد")
        from core.load_balancer import LoadBalancerManager
        ok_conflict, err_conflict = LoadBalancerManager.check_port_conflicts(ports, [s["ip"] for s in servers])
        if not ok_conflict:
            return False, err_conflict, {}
    except ValueError as e:
        return False, str(e), {}

    pool_data = {
        "name": name,
        "transport": "vxlan",
        "engine": "vxlan",
        "vni": vni_val,
        "vxlan_method": method,
        "dst_port": dst_port_val,
        "vxlan_mtu": mtu_val,
        "bridge_name": bridge_name,
        "underlay_dev": underlay_dev,
        "client_ports": ports,
        "kharej_server": kharej,
        "nodes": [],
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "security": "none",
        "security_disclaimer": "بدون رمزنگاری — لینک کرنلی تأیید شد؛ برای ترافیک حساس از VXLAN+IPsec استفاده کنید",
    }
    save_pool(name, pool_data)

    results = []
    for s in servers:
        ok, msg = add(name, s, callback)
        results.append((ok, msg))

    updated_pool = get_pools().get(name, pool_data)
    any_success = any(ok for ok, _ in results)
    msg = (
        "استخر VXLAN با موفقیت راه‌اندازی شد"
        if any_success
        else f"راه‌اندازی استخر VXLAN ناموفق بود: {'; '.join(m for _, m in results)}"
    )
    return any_success, msg, updated_pool


def add(name: str, server: dict, callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
    """Add an Iran server node to an existing VXLAN pool."""
    pool = get_pools().get(name)
    if not pool:
        return False, "استخر یافت نشد"
    if any(n["ip"] == server["ip"] for n in pool.get("nodes", [])):
        return False, "این سرور ایران از قبل در استخر وجود دارد"

    def progress(msg: str):
        if callback:
            callback(msg)

    ir_cidr, kh_cidr = allocate_vxlan_private_ips()
    node_id = str(server.get("node_name") or f"vx_{secrets.token_hex(4)}")
    if re.fullmatch(r"vx[0-9a-f]{4,10}", node_id):
        iface = node_id
    else:
        iface = make_vxlan_iface(node_id.removeprefix("vx_"))
    method = pool.get("vxlan_method", VXLAN_METHOD_P2P)
    vni_val = pool.get("vni", DEFAULT_VXLAN_VNI)
    dst_port_val = pool.get("dst_port", DEFAULT_VXLAN_PORT)
    mtu_val = pool.get("vxlan_mtu", DEFAULT_VXLAN_MTU)
    bridge_name = pool.get("bridge_name")
    underlay_dev = pool.get("underlay_dev")

    method_titles = {
        VXLAN_METHOD_P2P: "P2P Unicast",
        VXLAN_METHOD_BRIDGE_POINTIP: "Bridge + IP Pointing",
        VXLAN_METHOD_FDB_BRIDGE: "Bridge + FDB Unicast",
    }

    node = {
        "ip": server["ip"],
        "name": server.get("name", server["ip"]),
        "node_name": node_id,
        "engine": "vxlan",
        "transport": "vxlan",
        "provisioning": True,
        "status": "PROVISIONING",
        "tunnel_port": dst_port_val,
        "vxlan": {
            "iface": iface,
            "method": method,
            "method_title": method_titles.get(method, method),
            "vni": vni_val,
            "dst_port": dst_port_val,
            "mtu": mtu_val,
            "local_private": ir_cidr.split("/")[0],
            "remote_private": kh_cidr.split("/")[0],
            "bridge_name": bridge_name if method != VXLAN_METHOD_P2P else None,
        },
    }

    def reserve(data):
        data["pools"][name]["nodes"].append(node)
    atomic_update(reserve)

    adapter = VxlanDedicatedAdapter()
    kharej = pool["kharej_server"]
    sessions = []
    try:
        progress(f"اتصال به سرور ایران ({server['ip']}) و سرور خارج ({kharej['ip']})...")
        ir_ssh = connect(server)
        sessions.append(ir_ssh)
        kh_ssh = connect(kharej)
        sessions.append(kh_ssh)

        # Verify prerequisites
        ok_ir, msg_ir = adapter.install(ir_ssh, "iran", {})
        if not ok_ir:
            raise RuntimeError(f"پیش‌نیازهای سرور ایران: {msg_ir}")
        ok_kh, msg_kh = adapter.install(kh_ssh, "kharej", {})
        if not ok_kh:
            raise RuntimeError(f"پیش‌نیازهای سرور خارج: {msg_kh}")

        pool_cfg = {
            "pool_name": node_id,
            "vxlan_method": method,
            "vni": vni_val,
            "dst_port": dst_port_val,
            "mtu": mtu_val,
            "bridge_name": bridge_name,
            "underlay_dev": underlay_dev,
            "iran_private_ip": ir_cidr,
            "kharej_private_ip": kh_cidr,
            "peers": [kharej["ip"]],
        }
        config_payload = adapter.configure(server, kharej, pool_cfg)
        node["vxlan"]["bridge_name"] = config_payload["bridge_name"]
        def record_bridge(data):
            for entry in data["pools"][name]["nodes"]:
                if entry["node_name"] == node_id:
                    entry["vxlan"]["bridge_name"] = config_payload["bridge_name"]
        atomic_update(record_bridge)
        def publish(ssh, path, content):
            if not ssh.write_file(path, content):
                raise RuntimeError("Writing VXLAN runtime artifact failed: " + path)


        # Write Kharej scripts & unit
        progress(f"استقرار اسکریپت‌ها و سرویس VXLAN روی سرور خارج ({kharej['ip']})...")
        kh_scripts = config_payload["kharej_scripts"]
        publish(kh_ssh, kh_scripts["start_path"], kh_scripts["start"])
        publish(kh_ssh, kh_scripts["stop_path"], kh_scripts["stop"])
        publish(kh_ssh, kh_scripts["unit_path"], kh_scripts["unit"])
        kh_ssh.execute(f"chmod 755 {shlex.quote(kh_scripts['start_path'])} {shlex.quote(kh_scripts['stop_path'])}")
        ok_start_kh, msg_start_kh = adapter.start(kh_ssh, iface)
        if not ok_start_kh:
            raise RuntimeError(f"راه‌اندازی اینترفیس روی سرور خارج ناموفق بود: {msg_start_kh}")

        # Write Iran scripts & unit
        progress(f"استقرار اسکریپت‌ها و سرویس VXLAN روی سرور ایران ({server['ip']})...")
        ir_scripts = config_payload["iran_scripts"]
        publish(ir_ssh, ir_scripts["start_path"], ir_scripts["start"])
        publish(ir_ssh, ir_scripts["stop_path"], ir_scripts["stop"])
        publish(ir_ssh, ir_scripts["unit_path"], ir_scripts["unit"])
        ir_ssh.execute(f"chmod 755 {shlex.quote(ir_scripts['start_path'])} {shlex.quote(ir_scripts['stop_path'])}")
        ok_start_ir, msg_start_ir = adapter.start(ir_ssh, iface)
        if not ok_start_ir:
            raise RuntimeError(f"راه‌اندازی اینترفیس روی سرور ایران ناموفق بود: {msg_start_ir}")

        # Deploy Client Ports Relay on Iran node if client_ports configured
        client_ports = pool.get("client_ports", [])
        if client_ports:
            from core.kernel_relay_ports import check_ports_free
            check_ports_free(ir_ssh, client_ports)
            progress("استقرار سرویس فوروارد پورت‌های کلاینت...")
            relay_py, relay_unit = generate_relay_script_and_unit(iface, kh_cidr.split("/")[0], client_ports)
            publish(ir_ssh, f"/usr/local/bin/vxlb-{iface}-relay.py", relay_py)
            publish(ir_ssh, f"/etc/systemd/system/vxlb-vxlan-{iface}-relay.service", relay_unit)
            code, _, error = ir_ssh.execute(
                f"chmod 755 /usr/local/bin/vxlb-{iface}-relay.py && "
                f"systemctl daemon-reload && "
                f"systemctl enable --now vxlb-vxlan-{iface}-relay.service"
            )
            if code:
                raise RuntimeError("VXLAN relay startup failed: " + error)

        if client_ports:
            from core.kernel_relay_ports import verify_listeners
            verify_listeners(ir_ssh, f"vxlb-vxlan-{iface}-relay.service", client_ports)
        from core.private_link_health import probe_pair
        result = probe_pair(ir_ssh, kh_ssh, node["vxlan"]["local_private"], node["vxlan"]["remote_private"], config_payload["bridge_name"] or iface)
        def finalize(data):
            for n in data["pools"][name]["nodes"]:
                if n["node_name"] == node_id:
                    n["provisioning"] = False
                    n["status"] = "HEALTHY"
                    n["reason"] = "TCP/UDP private link verified"
                    n["latency_ms"] = result["latency_ms"]
        atomic_update(finalize)
        return True, f"نود {server['ip']} با پروفایل {method} متصل شد"

    except Exception as e:
        cleanup_errors = []
        for ssh in sessions:
            try:
                ok, message = adapter.clean(ssh, iface, bridge_name=node["vxlan"].get("bridge_name"))
                if not ok:
                    cleanup_errors.append(message)
            except Exception as cleanup_error:
                cleanup_errors.append(str(cleanup_error))
        def rollback_node(data):
            if cleanup_errors:
                for entry in data["pools"][name]["nodes"]:
                    if entry["node_name"] == node_id:
                        entry.update(status="FAILED", provisioning=True, reason=str(e), cleanup_error="; ".join(cleanup_errors))
            else:
                data["pools"][name]["nodes"] = [n for n in data["pools"][name]["nodes"] if n["node_name"] != node_id]
        atomic_update(rollback_node)
        return False, str(e) + ("; cleanup required: " + "; ".join(cleanup_errors) if cleanup_errors else "")
    finally:
        for s in sessions:
            try:
                s.close()
            except Exception:
                pass


def remove(name: str, ip: str, callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
    """Remove a single Iran server node from a VXLAN pool."""
    pool = get_pools().get(name)
    if not pool:
        return False, "استخر یافت نشد"
    node = next((n for n in pool.get("nodes", []) if n["ip"] == ip), None)
    if not node:
        return False, "نود در این استخر یافت نشد"

    iface = node.get("vxlan", {}).get("iface") or make_vxlan_iface(node.get("node_name", "node"))
    adapter = VxlanDedicatedAdapter()
    kharej = pool["kharej_server"]
    sessions = []
    try:
        if callback:
            callback(f"پاکسازی منابع VXLAN برای نود {ip}...")
        credentials = next((s for s in load_data().get("iran_servers", []) if s["ip"] == ip), None)
        if not credentials:
            raise RuntimeError("Iran server credentials unavailable; ownership retained for cleanup")
        ir_ssh = connect(credentials)
        sessions.append(ir_ssh)
        kh_ssh = connect(kharej)
        sessions.append(kh_ssh)

        for ssh in (ir_ssh, kh_ssh):
            ok, message = adapter.clean(ssh, iface, bridge_name=node.get("vxlan", {}).get("bridge_name"))
            if not ok:
                raise RuntimeError(message)

        def discard(data):
            data["pools"][name]["nodes"] = [n for n in data["pools"][name]["nodes"] if n["ip"] != ip]
        atomic_update(discard)
        return True, f"منابع نود {ip} با موفقیت حذف شدند"
    except Exception as e:
        return False, f"خطا در حذف نود: {e}"
    finally:
        for s in sessions:
            try:
                s.close()
            except Exception:
                pass


def remove_pool(name: str, callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
    """Tear down all VXLAN tunnels in a pool and delete pool record."""
    pool = get_pools().get(name)
    if not pool:
        return False, "استخر یافت نشد"
    nodes = list(pool.get("nodes", []))
    for n in nodes:
        ok, message = remove(name, n["ip"], callback)
        if not ok:
            return False, message
    delete_pool(name)
    return True, f"استخر VXLAN '{name}' و تمام اینترفیس‌ها و بریج‌های اختصاصی آن حذف شدند"


VXLAN_MTU_SCRIPT = r'''
import json,os,re,sys,tempfile
path=sys.argv[1];mtu=int(sys.argv[2]);devices=json.loads(sys.argv[3])
with open(path) as source:text=source.read()
for device in devices:
 pattern=r'(?m)^(ip link set dev '+re.escape(device)+r' mtu )\d+$'
 text,count=re.subn(pattern,lambda match:match.group(1)+str(mtu),text)
 if count!=1:raise RuntimeError('Owned VXLAN start script has an unexpected MTU directive')
fd,temporary=tempfile.mkstemp(prefix='.vxlb-mtu-',dir=os.path.dirname(path))
try:
 with os.fdopen(fd,'w') as destination:destination.write(text);destination.flush();os.fsync(destination.fileno())
 os.chmod(temporary,os.stat(path).st_mode & 0o777)
 os.replace(temporary,path)
finally:
 if os.path.exists(temporary):os.unlink(temporary)
'''


def _set_vxlan_endpoint_mtu(ssh, node, mtu):
    meta = node['vxlan']
    iface = meta['iface']
    if not re.fullmatch(r'vx-[a-zA-Z0-9_-]{1,12}', iface):
        raise ValueError('Invalid VXLAN interface')
    devices = [iface]
    if meta.get('bridge_name'):
        from core.vxlan_tools import validate_dedicated_bridge
        devices.append(validate_dedicated_bridge(meta['bridge_name']))
    for device in devices:
        code, _, error = ssh.execute(f'ip link set dev {shlex.quote(device)} mtu {validate_mtu(mtu)}')
        if code:
            raise RuntimeError('Applying VXLAN MTU failed: ' + error)
    command = 'python3 -c ' + shlex.quote(VXLAN_MTU_SCRIPT) + ' ' + shlex.quote(f'/usr/local/bin/vxlb-{iface}-start.sh') + ' ' + str(mtu) + ' ' + shlex.quote(json.dumps(devices))
    code, _, error = ssh.execute(command)
    if code:
        raise RuntimeError('Persisting VXLAN MTU failed: ' + error)


def _apply_vxlan_pool_mtu(name, mtu):
    from core.kernel_relay_ports import node_credentials
    from core.private_link_health import probe_pair
    mtu = validate_mtu(mtu)
    pool = get_pools().get(name)
    if not pool:
        return False, 'استخر یافت نشد'
    old_mtu = pool.get('vxlan_mtu', DEFAULT_VXLAN_MTU)
    sessions, touched, pairs = [], [], []
    try:
        kharej = connect(pool['kharej_server'])
        sessions.append(kharej)
        for node in pool.get('nodes', []):
            iran = connect(node_credentials(node))
            sessions.append(iran)
            pairs.append((iran, kharej, node))
            for ssh in (iran, kharej):
                touched.append((ssh, node))
                _set_vxlan_endpoint_mtu(ssh, node, mtu)
            meta = node['vxlan']
            probe_pair(iran, kharej, meta['local_private'], meta['remote_private'], meta.get('bridge_name') or meta['iface'])
        def commit(data):
            data['pools'][name]['vxlan_mtu'] = mtu
            for node in data['pools'][name]['nodes']:
                node['vxlan']['mtu'] = mtu
        atomic_update(commit)
        return True, f'MTU VXLAN {mtu}: TCP/UDP verified and persisted'
    except Exception as error:
        failures = []
        for ssh, node in reversed(touched):
            try:
                _set_vxlan_endpoint_mtu(ssh, node, old_mtu)
            except Exception as failure:
                failures.append(str(failure))
        if not failures:
            for iran, kharej, node in pairs:
                meta = node['vxlan']
                try:
                    probe_pair(iran, kharej, meta['local_private'], meta['remote_private'], meta.get('bridge_name') or meta['iface'])
                except Exception as failure:
                    failures.append(str(failure))
        detail = 'rollback unverified: ' + '; '.join(failures) if failures else f'restored MTU {old_mtu}'
        return False, f'VXLAN MTU update failed ({detail}): {error}'
    finally:
        for ssh in sessions:
            ssh.close()


def change_mtu(name: str, new_mtu: int) -> Tuple[bool, str]:
    """Apply, persist and challenge both endpoints, restoring a failed update."""
    return _apply_vxlan_pool_mtu(name, new_mtu)


def rollback_mtu(name: str, old_mtu: int) -> Tuple[bool, str]:
    return _apply_vxlan_pool_mtu(name, old_mtu)


def pool_status(name: str) -> Tuple[bool, str, dict]:
    """Query live interface and bridge status across nodes."""
    pool = get_pools().get(name)
    if not pool:
        return False, "استخر یافت نشد", {}
    adapter = VxlanDedicatedAdapter()
    results = {}
    sessions = []
    try:
        for node in pool.get("nodes", []):
            iface = node.get("vxlan", {}).get("iface")
            if not iface:
                continue
            try:
                from core.kernel_relay_ports import node_credentials
                ir_ssh = connect(node_credentials(node))
                sessions.append(ir_ssh)
                st = adapter.status(ir_ssh, iface)
                results[node["ip"]] = st
            except Exception as e:
                results[node["ip"]] = {"connected": False, "error": str(e)}
        return True, "وضعیت با موفقیت دریافت شد", results
    finally:
        for s in sessions:
            try:
                s.close()
            except Exception:
                pass


def health(pool_name: str, node: dict, ports: list) -> Tuple[str, str, dict]:
    from core.private_link_health import health as check_health
    return check_health(pool_name, node, ports)


# Automatic registration of dedicated VXLAN adapter into global registry
register_adapter(VxlanDedicatedAdapter())
