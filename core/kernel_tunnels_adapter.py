"""Kernel and Network Layer Tunnel Adapters for VX-LB.

Coverage:
- IP6IP6
- GRE6
- GRETAP & GRE6TAP
- GRE6TAP + IPsec
- SIT / 6in4
- 6TO4 Unicast
- ERSPAN + IPsec
- EOIP
- L2TP
- ISATAP
"""
import shlex
from typing import Dict, List, Tuple, Optional, Any
from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.ssh_client import SSHManager
from core.validation import validate_tunnel_name, validate_port

class KernelTunnelBaseAdapter(BaseTunnelAdapter):
    """Base class providing standard Linux iproute2 and systemd unit management for kernel tunnels."""

    def __init__(self, engine_id: str, tunnel_mode: str, kernel_module: str):
        super().__init__(engine_id)
        self.tunnel_mode = tunnel_mode
        self.kernel_module = kernel_module

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        cmd = f"modprobe {self.kernel_module} 2>/dev/null; which ip iptables ip6tables"
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Kernel module or tool missing for {self.engine_id}: {err or out}"
        return True, f"Prerequisites for {self.engine_id} verified"

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        node_name = iran_node.get("node_name", f"{self.engine_id}_node")
        clean_name = validate_tunnel_name(node_name[:12])
        iface = f"{self.engine_id[:5]}-{clean_name}"
        mtu = pool_config.get("mtu", self.capabilities.default_mtu)
        
        ir_ip = iran_node.get("ip")
        kh_ip = kharej_server.get("ip")
        priv_net = pool_config.get("private_subnet", "10.100.1.0/30")

        return {
            "engine": self.engine_id,
            "mode": self.tunnel_mode,
            "interface": iface,
            "mtu": mtu,
            "local_ip": ir_ip,
            "remote_ip": kh_ip,
            "private_subnet": priv_net,
            "service_name": f"vxlb-{iface}.service",
            "unit_script": f"ip link add {iface} type {self.tunnel_mode} local {ir_ip} remote {kh_ip} && ip link set {iface} mtu {mtu} up"
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {svc} && systemctl restart {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-{identifier}.service"
        cmd = f"systemctl stop {svc} && systemctl disable {svc}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-{identifier}.service"
        ok, out, _ = ssh.execute(f"systemctl is-active {svc}")
        is_active = (ok == 0 and out.strip() == "active")
        return {
            "engine": self.engine_id,
            "service": svc,
            "status": "UP" if is_active else "DOWN",
        }

    def probe(self, endpoint_ir: dict, endpoint_kh: dict, ports: List[int]) -> dict:
        return {
            "passed": False,
            "error": f"Active kernel data probe is unsupported/unimplemented for tunnel '{self.engine_id}'",
            "latency_ms": None
        }

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        return False, f"Dynamic modify is unsupported for kernel tunnel '{self.engine_id}'"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        return False, f"Rollback is unsupported for kernel tunnel '{self.engine_id}'"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-", "").replace(".service", "")
        svc = f"vxlb-{iface}.service"
        cmd = f"systemctl stop {svc} 2>/dev/null; ip link del {iface} 2>/dev/null; rm -f /etc/systemd/system/{svc}; systemctl daemon-reload"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class Gre6Adapter(BaseTunnelAdapter):
    """Adapter for GRE over IPv6 (ip6gre) tunnels (RFC 7676 / RFC 2784)."""

    def __init__(self):
        super().__init__("gre6")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.gre6 import check_gre6_prerequisites
        if role == "iran":
            remote_ipv6 = config.get("remote_ip") or config.get("kharej_ip") or config.get("kharej_ipv6") or config.get("remote_ipv6")
        else:
            remote_ipv6 = config.get("remote_ip") or config.get("iran_ip") or config.get("iran_ipv6") or config.get("remote_ipv6")
        return check_gre6_prerequisites(ssh, remote_ipv6)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.gre6 import configure_gre6_link
        return configure_gre6_link(iran_node, kharej_server, pool_config)

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre6-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre6-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre6-{identifier}.service"
        iface = identifier.replace("vxlb-gre6-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status, CLEARTEXT_WARNING
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": CLEARTEXT_WARNING,
            },
            "address_families": {
                "external": "ipv6",
                "internal": ["ipv4", "ipv6"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active GRE6 probe unsupported: missing valid SSH connections or target configuration",
                "latency_ms": None,
            }

        kharej_priv_ip = kwargs.get("kharej_private_ip")
        if not kharej_priv_ip and isinstance(endpoint_kh, dict):
            kharej_priv_ip = (
                endpoint_kh.get("private_addressing", {}).get("kharej_ipv6")
                or endpoint_kh.get("private_addressing", {}).get("kharej_ipv4")
                or endpoint_kh.get("private_ipv6")
                or endpoint_kh.get("private_ip")
            )
        if not kharej_priv_ip and isinstance(endpoint_ir, dict):
            kharej_priv_ip = (
                endpoint_ir.get("private_addressing", {}).get("kharej_ipv6")
                or endpoint_ir.get("private_addressing", {}).get("kharej_ipv4")
            )

        if not kharej_priv_ip:
            kharej_priv_ip = kwargs.get("target_ip") or "fd00:1db0:6::2"

        probe_port = int(ports[0]) if ports else int(kwargs.get("probe_port", 42892))
        try:
            return execute_active_data_probe(iran_ssh, kharej_ssh, kharej_priv_ip, probe_port)
        except Exception as e:
            return {
                "passed": False,
                "latency_ms": None,
                "error": f"GRE6 active probe exception: {str(e)}",
            }

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.gre6 import validate_gre6_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Dynamic modify unsupported for pool '{pool_name}' without active gre6 context"

        iface = raw_iface.replace("vxlb-gre6-", "").replace(".service", "")

        if "mtu" in updates:
            try:
                new_mtu = validate_gre6_mtu(updates["mtu"])
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-gre6-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            code, _, error = ssh.execute(f"cp {unit_file} {unit_bak}")
            if code:
                return False, "Could not back up native IPv6 service: " + error

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            code, _, error = ssh.execute(update_unit_cmd)
            if code:
                return False, "Could not persist native IPv6 MTU: " + error
            return True, f"GRE6 MTU updated to {new_mtu} for {iface}"

        return True, "No supported GRE6 modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.gre6 import validate_gre6_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous gre6 snapshot"

        iface = raw_iface.replace("vxlb-gre6-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_gre6_mtu(prev_mtu)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-gre6-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} && "
                f"test -r {unit_bak} && cp {unit_bak} {unit_file} && systemctl daemon-reload"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"GRE6 rollback failed for {iface}: {err or out}"
            return True, f"GRE6 rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-gre6-", "").replace(".service", "")
        svc = f"vxlb-gre6-{iface}.service"
        unit_file = f"/etc/systemd/system/{svc}"
        unit_bak = f"/etc/systemd/system/{svc}.bak"
        conf_file = f"/etc/vxlb/gre6/{iface}.json"

        cmd = (
            f"systemctl stop {shlex.quote(svc)} 2>/dev/null || true; "
            f"systemctl disable {shlex.quote(svc)} 2>/dev/null || true; "
            f"ip link set {shlex.quote(iface)} down 2>/dev/null || true; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true; "
            f"rm -f {shlex.quote(unit_file)} {shlex.quote(unit_bak)} {shlex.quote(conf_file)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Fail-closed cleanup of GRE6 interface {iface} encountered error: {err or out}"

        # Verify interface has truly been removed from kernel
        chk_code, _, _ = ssh.execute(f"ip link show {shlex.quote(iface)} 2>/dev/null")
        if chk_code == 0:
            return False, f"Fail-closed cleanup failed: GRE6 interface {iface} still present in kernel"

        return True, f"GRE6 interface {iface} and associated resources cleaned successfully"


class Ip6Ip6Adapter(BaseTunnelAdapter):
    """Adapter for IP6IP6 (IPv6-in-IPv6 RFC 2473) kernel tunnels."""

    def __init__(self):
        super().__init__("ip6ip6")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.ip6ip6 import check_ip6ip6_prerequisites
        if role == "iran":
            remote_ipv6 = config.get("remote_ip") or config.get("kharej_ip") or config.get("kharej_ipv6") or config.get("remote_ipv6")
        else:
            remote_ipv6 = config.get("remote_ip") or config.get("iran_ip") or config.get("iran_ipv6") or config.get("remote_ipv6")
        return check_ip6ip6_prerequisites(ssh, remote_ipv6)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.ip6ip6 import configure_ip6ip6_link
        return configure_ip6ip6_link(iran_node, kharej_server, pool_config)

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-ip6ip6-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-ip6ip6-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-ip6ip6-{identifier}.service"
        iface = identifier.replace("vxlb-ip6ip6-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status, CLEARTEXT_WARNING
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        # Check if interface has dual-stack IPv4 addressing configured
        has_v4 = bool("inet " in out_link or "10.206" in out_link)
        internal_af = ["ipv6", "ipv4"] if has_v4 else ["ipv6"]

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": CLEARTEXT_WARNING,
            },
            "address_families": {
                "external": "ipv6",
                "internal": internal_af,
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active IP6IP6 probe unsupported: missing valid SSH connections or target configuration",
                "latency_ms": None,
            }

        kharej_priv_ip = kwargs.get("kharej_private_ip")
        if not kharej_priv_ip and isinstance(endpoint_kh, dict):
            kharej_priv_ip = (
                endpoint_kh.get("private_addressing", {}).get("kharej_ipv6")
                or endpoint_kh.get("private_addressing", {}).get("kharej_ipv4")
                or endpoint_kh.get("private_ipv6")
                or endpoint_kh.get("private_ip")
            )
        if not kharej_priv_ip and isinstance(endpoint_ir, dict):
            kharej_priv_ip = (
                endpoint_ir.get("private_addressing", {}).get("kharej_ipv6")
                or endpoint_ir.get("private_addressing", {}).get("kharej_ipv4")
            )

        if not kharej_priv_ip:
            kharej_priv_ip = kwargs.get("target_ip") or "fd00:1db0:66::2"

        probe_port = int(ports[0]) if ports else int(kwargs.get("probe_port", 42892))
        try:
            return execute_active_data_probe(iran_ssh, kharej_ssh, kharej_priv_ip, probe_port)
        except Exception as e:
            return {
                "passed": False,
                "latency_ms": None,
                "error": f"IP6IP6 active probe exception: {str(e)}",
            }

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.ip6ip6 import validate_ip6ip6_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Dynamic modify unsupported for pool '{pool_name}' without active ip6ip6 context"

        iface = raw_iface.replace("vxlb-ip6ip6-", "").replace(".service", "")

        if "mtu" in updates:
            try:
                new_mtu = validate_ip6ip6_mtu(updates["mtu"])
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-ip6ip6-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            code, _, error = ssh.execute(f"cp {unit_file} {unit_bak}")
            if code:
                return False, "Could not back up native IPv6 service: " + error

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            code, _, error = ssh.execute(update_unit_cmd)
            if code:
                return False, "Could not persist native IPv6 MTU: " + error
            return True, f"IP6IP6 MTU updated to {new_mtu} for {iface}"

        return True, "No supported IP6IP6 modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.ip6ip6 import validate_ip6ip6_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous ip6ip6 snapshot"

        iface = raw_iface.replace("vxlb-ip6ip6-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_ip6ip6_mtu(prev_mtu)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-ip6ip6-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} && "
                f"test -r {unit_bak} && cp {unit_bak} {unit_file} && systemctl daemon-reload"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"IP6IP6 rollback failed for {iface}: {err or out}"
            return True, f"IP6IP6 rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-ip6ip6-", "").replace(".service", "")
        svc = f"vxlb-ip6ip6-{iface}.service"
        unit_file = f"/etc/systemd/system/{svc}"
        unit_bak = f"/etc/systemd/system/{svc}.bak"
        conf_file = f"/etc/vxlb/ip6ip6/{iface}.json"

        cmd = (
            f"systemctl stop {shlex.quote(svc)} 2>/dev/null || true; "
            f"systemctl disable {shlex.quote(svc)} 2>/dev/null || true; "
            f"ip link set {shlex.quote(iface)} down 2>/dev/null || true; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true; "
            f"rm -f {shlex.quote(unit_file)} {shlex.quote(unit_bak)} {shlex.quote(conf_file)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        if ok != 0:
            return False, f"Fail-closed cleanup of IP6IP6 interface {iface} encountered error: {err or out}"

        # Verify interface has truly been removed from kernel
        chk_code, _, _ = ssh.execute(f"ip link show {shlex.quote(iface)} 2>/dev/null")
        if chk_code == 0:
            return False, f"Fail-closed cleanup failed: IP6IP6 interface {iface} still present in kernel"

        return True, f"IP6IP6 interface {iface} and associated resources cleaned successfully"

class GreTapAdapter(BaseTunnelAdapter):
    """Adapter for Layer 2 GRETAP (Ethernet over IPv4 GRE) tunnels."""

    def __init__(self):
        super().__init__("gretap")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.gretap import check_gretap_prerequisites
        remote_ip = config.get("remote_ip") or (config.get("kharej_ip") if role == "iran" else config.get("iran_ip"))
        return check_gretap_prerequisites(ssh, self.engine_id, remote_ip)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.gretap import configure_gretap_link
        return configure_gretap_link(iran_node, kharej_server, pool_config, engine_id="gretap")

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gretap-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gretap-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gretap-{identifier}.service"
        iface = identifier.replace("vxlb-gretap-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status, CLEARTEXT_WARNING
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": CLEARTEXT_WARNING,
            },
            "address_families": {
                "external": "ipv4",
                "internal": ["ipv4"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active GRETAP probe unsupported: missing valid SSH connections or target configuration",
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
                "error": "Active GRETAP probe requires target remote private IPv4 address",
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
        from core.gretap import validate_gretap_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")
        mtu = updates.get("mtu")

        if mtu:
            if not ssh or not raw_iface or not hasattr(ssh, "execute"):
                return False, f"Dynamic modify unsupported for pool '{pool_name}' without live SSH connection"

            try:
                new_mtu = validate_gretap_mtu(mtu, is_ipv6=False, is_ipsec=False)
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            iface = raw_iface.replace("vxlb-gretap-", "").replace(".service", "")
            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-gretap-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            ssh.execute(f"cp {unit_file} {unit_bak} 2>/dev/null || true")

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            ssh.execute(update_unit_cmd)
            return True, f"GRETAP MTU updated to {new_mtu} for {iface}"

        return True, "No supported GRETAP modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.gretap import validate_gretap_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous gretap snapshot"

        iface = raw_iface.replace("vxlb-gretap-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_gretap_mtu(prev_mtu, is_ipv6=False, is_ipsec=False)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-gretap-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} 2>/dev/null; "
                f"if [ -f {unit_bak} ]; then cp {unit_bak} {unit_file} && systemctl daemon-reload; fi"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"GRETAP rollback failed for {iface}: {err or out}"
            return True, f"GRETAP rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-gretap-", "").replace("vxlb-", "").replace(".service", "")
        svc = f"vxlb-gretap-{iface}.service"
        relay_svc = f"vxlb-gretap-{iface}-relay.service"
        relay_script = f"/etc/vxlb/{iface}-relay.py"

        cmd = (
            f"systemctl stop {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"systemctl disable {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/systemd/system/{shlex.quote(relay_svc)} {shlex.quote(relay_script)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class Gre6TapAdapter(BaseTunnelAdapter):
    """Adapter for Layer 2 GRE6TAP (Ethernet over IPv6 GRE) tunnels."""

    def __init__(self):
        super().__init__("gre6tap")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.gretap import check_gretap_prerequisites
        remote_ip = config.get("remote_ip") or (config.get("kharej_ip") if role == "iran" else config.get("iran_ip"))
        return check_gretap_prerequisites(ssh, self.engine_id, remote_ip)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.gretap import configure_gretap_link
        return configure_gretap_link(iran_node, kharej_server, pool_config, engine_id="gre6tap")

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre6tap-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre6tap-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre6tap-{identifier}.service"
        iface = identifier.replace("vxlb-gre6tap-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status, CLEARTEXT_WARNING
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": CLEARTEXT_WARNING,
            },
            "address_families": {
                "external": "ipv6",
                "internal": ["ipv6", "ipv4"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active GRE6TAP probe unsupported: missing valid SSH connections or target configuration",
                "latency_ms": None,
            }

        kharej_priv_ip = kwargs.get("kharej_private_ip")
        if not kharej_priv_ip and isinstance(endpoint_kh, dict):
            kharej_priv_ip = (
                endpoint_kh.get("private_addressing", {}).get("kharej_ipv6")
                or endpoint_kh.get("kharej_ipv6")
                or endpoint_kh.get("private_addressing", {}).get("kharej_ipv4")
            )

        if not kharej_priv_ip:
            return {
                "passed": False,
                "error": "Active GRE6TAP probe requires target remote private IP address",
                "latency_ms": None,
            }

        target_host = kharej_priv_ip.split("/")[0]
        probe_ports = ports or [2222]

        return execute_active_data_probe(
            iran_ssh=iran_ssh,
            kharej_ssh=kharej_ssh,
            target_ip=target_host,
            ports=probe_ports,
            is_ipv6=(":" in target_host),
        )

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.gretap import validate_gretap_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")
        mtu = updates.get("mtu")

        if mtu:
            if not ssh or not raw_iface or not hasattr(ssh, "execute"):
                return False, f"Dynamic modify unsupported for pool '{pool_name}' without live SSH connection"

            try:
                new_mtu = validate_gretap_mtu(mtu, is_ipv6=True, is_ipsec=False)
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            iface = raw_iface.replace("vxlb-gre6tap-", "").replace(".service", "")
            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-gre6tap-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            ssh.execute(f"cp {unit_file} {unit_bak} 2>/dev/null || true")

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            ssh.execute(update_unit_cmd)
            return True, f"GRE6TAP MTU updated to {new_mtu} for {iface}"

        return True, "No supported GRE6TAP modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.gretap import validate_gretap_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous gre6tap snapshot"

        iface = raw_iface.replace("vxlb-gre6tap-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_gretap_mtu(prev_mtu, is_ipv6=True, is_ipsec=False)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-gre6tap-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} 2>/dev/null; "
                f"if [ -f {unit_bak} ]; then cp {unit_bak} {unit_file} && systemctl daemon-reload; fi"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"GRE6TAP rollback failed for {iface}: {err or out}"
            return True, f"GRE6TAP rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-gre6tap-", "").replace("vxlb-", "").replace(".service", "")
        svc = f"vxlb-gre6tap-{iface}.service"
        relay_svc = f"vxlb-gre6tap-{iface}-relay.service"
        relay_script = f"/etc/vxlb/{iface}-relay.py"

        cmd = (
            f"systemctl stop {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"systemctl disable {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/systemd/system/{shlex.quote(relay_svc)} {shlex.quote(relay_script)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class Gre6TapIpsecAdapter(BaseTunnelAdapter):
    """Adapter for Layer 2 GRE6TAP + IPsec tunnels."""

    def __init__(self):
        super().__init__("gre6tap_ipsec")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.gretap import check_gretap_prerequisites
        remote_ip = config.get("remote_ip") or (config.get("kharej_ip") if role == "iran" else config.get("iran_ip"))
        return check_gretap_prerequisites(ssh, self.engine_id, remote_ip)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.gretap import configure_gretap_link
        return configure_gretap_link(iran_node, kharej_server, pool_config, engine_id="gre6tap_ipsec")

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre6tap_ipsec-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre6tap_ipsec-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-gre6tap_ipsec-{identifier}.service"
        iface = identifier.replace("vxlb-gre6tap_ipsec-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        ok_xfrm, out_xfrm, _ = ssh.execute("ip xfrm state count 2>/dev/null || true")
        sa_established = (ok_xfrm == 0 and "0" not in out_xfrm.strip())

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": True,
                "encryption_type": "ipsec",
                "cleartext": False,
                "sa_established": sa_established,
                "warning": None,
            },
            "address_families": {
                "external": "ipv6",
                "internal": ["ipv6", "ipv4"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active GRE6TAP+IPsec probe unsupported: missing valid SSH connections or target configuration",
                "latency_ms": None,
            }

        kharej_priv_ip = kwargs.get("kharej_private_ip")
        if not kharej_priv_ip and isinstance(endpoint_kh, dict):
            kharej_priv_ip = (
                endpoint_kh.get("private_addressing", {}).get("kharej_ipv6")
                or endpoint_kh.get("kharej_ipv6")
            )

        if not kharej_priv_ip:
            return {
                "passed": False,
                "error": "Active GRE6TAP+IPsec probe requires target remote private IPv6 address",
                "latency_ms": None,
            }

        target_host = kharej_priv_ip.split("/")[0]
        probe_ports = ports or [2222]

        return execute_active_data_probe(
            iran_ssh=iran_ssh,
            kharej_ssh=kharej_ssh,
            target_ip=target_host,
            ports=probe_ports,
            is_ipv6=True,
        )

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.gretap import validate_gretap_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")
        mtu = updates.get("mtu")

        if mtu:
            if not ssh or not raw_iface or not hasattr(ssh, "execute"):
                return False, f"Dynamic modify unsupported for pool '{pool_name}' without live SSH connection"

            try:
                new_mtu = validate_gretap_mtu(mtu, is_ipv6=True, is_ipsec=True)
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            iface = raw_iface.replace("vxlb-gre6tap_ipsec-", "").replace(".service", "")
            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-gre6tap_ipsec-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            ssh.execute(f"cp {unit_file} {unit_bak} 2>/dev/null || true")

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            ssh.execute(update_unit_cmd)
            return True, f"GRE6TAP+IPsec MTU updated to {new_mtu} for {iface}"

        return True, "No supported GRE6TAP+IPsec modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.gretap import validate_gretap_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous gre6tap_ipsec snapshot"

        iface = raw_iface.replace("vxlb-gre6tap_ipsec-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_gretap_mtu(prev_mtu, is_ipv6=True, is_ipsec=True)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-gre6tap_ipsec-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} 2>/dev/null; "
                f"if [ -f {unit_bak} ]; then cp {unit_bak} {unit_file} && systemctl daemon-reload; fi"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"GRE6TAP+IPsec rollback failed for {iface}: {err or out}"
            return True, f"GRE6TAP+IPsec rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-gre6tap_ipsec-", "").replace("vxlb-", "").replace(".service", "")
        svc = f"vxlb-gre6tap_ipsec-{iface}.service"
        relay_svc = f"vxlb-gre6tap_ipsec-{iface}-relay.service"
        relay_script = f"/etc/vxlb/{iface}-relay.py"

        cmd = (
            f"systemctl stop {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"systemctl disable {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"ip6tables -D INPUT -p 47 -m policy --dir in --pol none -j DROP 2>/dev/null || true; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/systemd/system/{shlex.quote(relay_svc)} {shlex.quote(relay_script)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class SitAdapter(BaseTunnelAdapter):
    """Adapter for SIT / 6in4 (IPv6 over IPv4) tunnels (RFC 4213)."""

    def __init__(self):
        super().__init__("sit")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.sit import check_sit_prerequisites
        remote_ip = config.get("remote_ip") or (config.get("kharej_ip") if role == "iran" else config.get("iran_ip"))
        return check_sit_prerequisites(ssh, remote_ip)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.sit import configure_sit_link
        return configure_sit_link(iran_node, kharej_server, pool_config)

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-sit-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-sit-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-sit-{identifier}.service"
        iface = identifier.replace("vxlb-sit-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status, CLEARTEXT_WARNING
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": CLEARTEXT_WARNING,
            },
            "address_families": {
                "external": "ipv4",
                "internal": ["ipv6", "ipv4"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active SIT probe unsupported: missing valid SSH connections or target configuration",
                "latency_ms": None,
            }

        kharej_priv_ip = kwargs.get("kharej_private_ip")
        if not kharej_priv_ip and isinstance(endpoint_kh, dict):
            kharej_priv_ip = (
                endpoint_kh.get("private_addressing", {}).get("kharej_ipv6")
                or endpoint_kh.get("kharej_ipv6")
            )

        if not kharej_priv_ip:
            return {
                "passed": False,
                "error": "Active SIT probe requires target remote private IPv6 address",
                "latency_ms": None,
            }

        target_host = kharej_priv_ip.split("/")[0]
        probe_ports = ports or [2222]

        return execute_active_data_probe(
            iran_ssh=iran_ssh,
            kharej_ssh=kharej_ssh,
            target_ip=target_host,
            ports=probe_ports,
            is_ipv6=True,
        )

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.sit import validate_sit_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")
        mtu = updates.get("mtu")

        if mtu:
            if not ssh or not raw_iface or not hasattr(ssh, "execute"):
                return False, f"Dynamic modify unsupported for pool '{pool_name}' without live SSH connection"

            try:
                new_mtu = validate_sit_mtu(mtu)
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            iface = raw_iface.replace("vxlb-sit-", "").replace(".service", "")
            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-sit-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            ssh.execute(f"cp {unit_file} {unit_bak} 2>/dev/null || true")

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            ssh.execute(update_unit_cmd)
            return True, f"SIT MTU updated to {new_mtu} for {iface}"

        return True, "No supported SIT modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.sit import validate_sit_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous sit snapshot"

        iface = raw_iface.replace("vxlb-sit-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_sit_mtu(prev_mtu)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-sit-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} 2>/dev/null; "
                f"if [ -f {unit_bak} ]; then cp {unit_bak} {unit_file} && systemctl daemon-reload; fi"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"SIT rollback failed for {iface}: {err or out}"
            return True, f"SIT rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:

        iface = identifier.replace("vxlb-sit-", "").replace("vxlb-", "").replace(".service", "")
        svc = f"vxlb-sit-{iface}.service"
        relay_svc = f"vxlb-sit-{iface}-relay.service"
        relay_script = f"/etc/vxlb/{iface}-relay.py"

        cmd = (
            f"systemctl stop {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"systemctl disable {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/systemd/system/{shlex.quote(relay_svc)} {shlex.quote(relay_script)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class SixToFourUnicastAdapter(BaseTunnelAdapter):
    """Adapter for 6TO4 Unicast tunnels (RFC 3056 point-to-point without Anycast)."""

    def __init__(self):
        super().__init__("6to4_unicast")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.six_to_four import check_6to4_prerequisites
        remote_ip = config.get("remote_ip") or (config.get("kharej_ip") if role == "iran" else config.get("iran_ip"))
        return check_6to4_prerequisites(ssh, remote_ip)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.six_to_four import configure_6to4_unicast_link
        return configure_6to4_unicast_link(iran_node, kharej_server, pool_config)

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-6to4-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-6to4-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-6to4-{identifier}.service"
        iface = identifier.replace("vxlb-6to4-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status, CLEARTEXT_WARNING
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "rfc": "RFC 3056",
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": CLEARTEXT_WARNING,
            },
            "address_families": {
                "external": "ipv4",
                "internal": ["ipv6", "ipv4"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active 6TO4 probe unsupported: missing valid SSH connections or target configuration",
                "latency_ms": None,
            }

        kharej_priv_ip = kwargs.get("kharej_private_ip")
        if not kharej_priv_ip and isinstance(endpoint_kh, dict):
            kharej_priv_ip = (
                endpoint_kh.get("private_addressing", {}).get("kharej_ipv6")
                or endpoint_kh.get("kharej_ipv6")
            )

        if not kharej_priv_ip:
            return {
                "passed": False,
                "error": "Active 6TO4 probe requires target remote RFC 3056 IPv6 address",
                "latency_ms": None,
            }

        target_host = kharej_priv_ip.split("/")[0]
        probe_ports = ports or [2222]

        return execute_active_data_probe(
            iran_ssh=iran_ssh,
            kharej_ssh=kharej_ssh,
            target_ip=target_host,
            ports=probe_ports,
            is_ipv6=True,
        )

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.six_to_four import validate_6to4_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")
        mtu = updates.get("mtu")

        if mtu:
            if not ssh or not raw_iface or not hasattr(ssh, "execute"):
                return False, f"Dynamic modify unsupported for pool '{pool_name}' without live SSH connection"

            try:
                new_mtu = validate_6to4_mtu(mtu)
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            iface = raw_iface.replace("vxlb-6to4-", "").replace(".service", "")
            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-6to4-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            ssh.execute(f"cp {unit_file} {unit_bak} 2>/dev/null || true")

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            ssh.execute(update_unit_cmd)
            return True, f"6TO4 MTU updated to {new_mtu} for {iface}"

        return True, "No supported 6TO4 modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.six_to_four import validate_6to4_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous 6to4 snapshot"

        iface = raw_iface.replace("vxlb-6to4-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_6to4_mtu(prev_mtu)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-6to4-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} 2>/dev/null; "
                f"if [ -f {unit_bak} ]; then cp {unit_bak} {unit_file} && systemctl daemon-reload; fi"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"6TO4 rollback failed for {iface}: {err or out}"
            return True, f"6TO4 rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-6to4-", "").replace("vxlb-", "").replace(".service", "")
        svc = f"vxlb-6to4-{iface}.service"
        relay_svc = f"vxlb-6to4-{iface}-relay.service"
        relay_script = f"/etc/vxlb/{iface}-relay.py"

        cmd = (
            f"systemctl stop {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"systemctl disable {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/systemd/system/{shlex.quote(relay_svc)} {shlex.quote(relay_script)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class ErspanIpsecAdapter(BaseTunnelAdapter):
    """Adapter for ERSPAN + IPsec tunnels."""

    def __init__(self):
        super().__init__("erspan")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.erspan import check_erspan_prerequisites
        remote_ip = config.get("remote_ip") or (config.get("kharej_ip") if role == "iran" else config.get("iran_ip"))
        return check_erspan_prerequisites(ssh, remote_ip)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.erspan import configure_erspan_link
        return configure_erspan_link(iran_node, kharej_server, pool_config)

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-erspan-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-erspan-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-erspan-{identifier}.service"
        iface = identifier.replace("vxlb-erspan-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        ok_xfrm, out_xfrm, _ = ssh.execute("ip xfrm state count 2>/dev/null || true")
        sa_established = (ok_xfrm == 0 and "0" not in out_xfrm.strip())

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": True,
                "encryption_type": "ipsec",
                "cleartext": False,
                "sa_established": sa_established,
                "warning": None,
            },
            "address_families": {
                "external": "ipv4",
                "internal": ["ipv4"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active ERSPAN probe unsupported: missing valid SSH connections or target configuration",
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
                "error": "Active ERSPAN probe requires target remote private IPv4 address",
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
        from core.erspan import validate_erspan_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")
        mtu = updates.get("mtu")

        if mtu:
            if not ssh or not raw_iface or not hasattr(ssh, "execute"):
                return False, f"Dynamic modify unsupported for pool '{pool_name}' without live SSH connection"

            try:
                new_mtu = validate_erspan_mtu(mtu)
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            iface = raw_iface.replace("vxlb-erspan-", "").replace(".service", "")
            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-erspan-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            ssh.execute(f"cp {unit_file} {unit_bak} 2>/dev/null || true")

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            ssh.execute(update_unit_cmd)
            return True, f"ERSPAN MTU updated to {new_mtu} for {iface}"

        return True, "No supported ERSPAN modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.erspan import validate_erspan_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous erspan snapshot"

        iface = raw_iface.replace("vxlb-erspan-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_erspan_mtu(prev_mtu)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-erspan-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} 2>/dev/null; "
                f"if [ -f {unit_bak} ]; then cp {unit_bak} {unit_file} && systemctl daemon-reload; fi"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"ERSPAN rollback failed for {iface}: {err or out}"
            return True, f"ERSPAN rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-erspan-", "").replace("vxlb-", "").replace(".service", "")
        svc = f"vxlb-erspan-{iface}.service"
        relay_svc = f"vxlb-erspan-{iface}-relay.service"
        relay_script = f"/etc/vxlb/{iface}-relay.py"

        cmd = (
            f"systemctl stop {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"systemctl disable {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"iptables -D INPUT -p 47 -m policy --dir in --pol none -j DROP 2>/dev/null || true; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/systemd/system/{shlex.quote(relay_svc)} {shlex.quote(relay_script)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class EoipAdapter(BaseTunnelAdapter):
    """Adapter for MikroTik-compatible EOIP (Ethernet over IP) tunnels."""

    def __init__(self):
        super().__init__("eoip")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.eoip import check_eoip_prerequisites
        remote_ip = config.get("remote_ip") or (config.get("kharej_ip") if role == "iran" else config.get("iran_ip"))
        return check_eoip_prerequisites(ssh, remote_ip)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.eoip import configure_eoip_link
        return configure_eoip_link(iran_node, kharej_server, pool_config)

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-eoip-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-eoip-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-eoip-{identifier}.service"
        iface = identifier.replace("vxlb-eoip-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status, CLEARTEXT_WARNING
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": CLEARTEXT_WARNING,
            },
            "address_families": {
                "external": "ipv4",
                "internal": ["ipv4"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active EOIP probe unsupported: missing valid SSH connections or target configuration",
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
                "error": "Active EOIP probe requires target remote private IPv4 address",
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
        from core.eoip import validate_eoip_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")
        mtu = updates.get("mtu")

        if mtu:
            if not ssh or not raw_iface or not hasattr(ssh, "execute"):
                return False, f"Dynamic modify unsupported for pool '{pool_name}' without live SSH connection"

            try:
                new_mtu = validate_eoip_mtu(mtu)
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            iface = raw_iface.replace("vxlb-eoip-", "").replace(".service", "")
            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-eoip-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            ssh.execute(f"cp {unit_file} {unit_bak} 2>/dev/null || true")

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            ssh.execute(update_unit_cmd)
            return True, f"EOIP MTU updated to {new_mtu} for {iface}"

        return True, "No supported EOIP modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.eoip import validate_eoip_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous eoip snapshot"

        iface = raw_iface.replace("vxlb-eoip-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_eoip_mtu(prev_mtu)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-eoip-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} 2>/dev/null; "
                f"if [ -f {unit_bak} ]; then cp {unit_bak} {unit_file} && systemctl daemon-reload; fi"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"EOIP rollback failed for {iface}: {err or out}"
            return True, f"EOIP rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-eoip-", "").replace("vxlb-", "").replace(".service", "")
        svc = f"vxlb-eoip-{iface}.service"
        relay_svc = f"vxlb-eoip-{iface}-relay.service"
        relay_script = f"/etc/vxlb/{iface}-relay.py"

        cmd = (
            f"systemctl stop {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"systemctl disable {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/systemd/system/{shlex.quote(relay_svc)} {shlex.quote(relay_script)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class L2tpAdapter(BaseTunnelAdapter):
    """Adapter for L2TPv3 Ethernet pseudowire tunnels."""

    def __init__(self):
        super().__init__("l2tp")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.l2tp import check_l2tp_prerequisites
        remote_ip = config.get("remote_ip") or (config.get("kharej_ip") if role == "iran" else config.get("iran_ip"))
        return check_l2tp_prerequisites(ssh, remote_ip)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.l2tp import configure_l2tp_link
        return configure_l2tp_link(iran_node, kharej_server, pool_config)

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-l2tp-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-l2tp-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-l2tp-{identifier}.service"
        iface = identifier.replace("vxlb-l2tp-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status, CLEARTEXT_WARNING
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": CLEARTEXT_WARNING,
            },
            "address_families": {
                "external": "ipv4",
                "internal": ["ipv4"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active L2TP probe unsupported: missing valid SSH connections or target configuration",
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
                "error": "Active L2TP probe requires target remote private IPv4 address",
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
        from core.l2tp import validate_l2tp_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")
        mtu = updates.get("mtu")

        if mtu:
            if not ssh or not raw_iface or not hasattr(ssh, "execute"):
                return False, f"Dynamic modify unsupported for pool '{pool_name}' without live SSH connection"

            try:
                new_mtu = validate_l2tp_mtu(mtu)
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            iface = raw_iface.replace("vxlb-l2tp-", "").replace(".service", "")
            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-l2tp-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            ssh.execute(f"cp {unit_file} {unit_bak} 2>/dev/null || true")

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            ssh.execute(update_unit_cmd)
            return True, f"L2TP MTU updated to {new_mtu} for {iface}"

        return True, "No supported L2TP modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.l2tp import validate_l2tp_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous l2tp snapshot"

        iface = raw_iface.replace("vxlb-l2tp-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_l2tp_mtu(prev_mtu)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-l2tp-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} 2>/dev/null; "
                f"if [ -f {unit_bak} ]; then cp {unit_bak} {unit_file} && systemctl daemon-reload; fi"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"L2TP rollback failed for {iface}: {err or out}"
            return True, f"L2TP rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-l2tp-", "").replace("vxlb-", "").replace(".service", "")
        svc = f"vxlb-l2tp-{iface}.service"
        relay_svc = f"vxlb-l2tp-{iface}-relay.service"
        relay_script = f"/etc/vxlb/{iface}-relay.py"

        cmd = (
            f"systemctl stop {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"systemctl disable {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/systemd/system/{shlex.quote(relay_svc)} {shlex.quote(relay_script)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class IsatapAdapter(BaseTunnelAdapter):
    """Adapter for ISATAP (RFC 5214) tunnels."""

    def __init__(self):
        super().__init__("isatap")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        from core.isatap import check_isatap_prerequisites
        remote_ip = config.get("remote_ip") or (config.get("kharej_ip") if role == "iran" else config.get("iran_ip"))
        return check_isatap_prerequisites(ssh, remote_ip)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.isatap import configure_isatap_link
        return configure_isatap_link(iran_node, kharej_server, pool_config)

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-isatap-{identifier}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        svc = identifier if identifier.endswith(".service") else f"vxlb-isatap-{identifier}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        svc = identifier if identifier.endswith(".service") else f"vxlb-isatap-{identifier}.service"
        iface = identifier.replace("vxlb-isatap-", "").replace(".service", "")

        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        is_active = (ok_svc == 0 and out_svc.strip() == "active")

        ok_link, out_link, _ = ssh.execute(f"ip -d -s link show {shlex.quote(iface)}")
        link_exists = (ok_link == 0)

        from core.ipv6_tunnel_tools import parse_link_telemetry, synthesize_status, CLEARTEXT_WARNING
        telemetry = parse_link_telemetry(out_link if link_exists else "")
        synth = synthesize_status(is_active, link_exists, telemetry)

        return {
            "engine": self.engine_id,
            "service": svc,
            "interface": iface,
            "status": synth["status"],
            "reason": synth.get("reason"),
            "details": synth["telemetry"],
            "security": {
                "requires_encryption": False,
                "encryption_type": "none",
                "cleartext": True,
                "warning": CLEARTEXT_WARNING,
            },
            "address_families": {
                "external": "ipv4",
                "internal": ["ipv6"],
            },
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        from core.ipv6_tunnel_tools import execute_active_data_probe
        iran_ssh = endpoint_ir.get("ssh") if isinstance(endpoint_ir, dict) and "ssh" in endpoint_ir else endpoint_ir
        kharej_ssh = endpoint_kh.get("ssh") if isinstance(endpoint_kh, dict) and "ssh" in endpoint_kh else endpoint_kh

        if not hasattr(iran_ssh, "execute") or not hasattr(kharej_ssh, "execute"):
            return {
                "passed": False,
                "error": "Active ISATAP probe unsupported: missing valid SSH connections or target configuration",
                "latency_ms": None,
            }

        kharej_priv_ip = kwargs.get("kharej_private_ip")
        if not kharej_priv_ip and isinstance(endpoint_kh, dict):
            kharej_priv_ip = (
                endpoint_kh.get("private_addressing", {}).get("kharej_ipv6")
                or endpoint_kh.get("kharej_ipv6")
            )

        if not kharej_priv_ip:
            return {
                "passed": False,
                "error": "Active ISATAP probe requires target remote ISATAP IPv6 address",
                "latency_ms": None,
            }

        target_host = kharej_priv_ip.split("/")[0]
        probe_ports = ports or [2222]

        return execute_active_data_probe(
            iran_ssh=iran_ssh,
            kharej_ssh=kharej_ssh,
            target_ip=target_host,
            ports=probe_ports,
            is_ipv6=True,
        )

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        from core.isatap import validate_isatap_mtu
        ssh = updates.get("ssh")
        raw_iface = updates.get("interface")
        mtu = updates.get("mtu")

        if mtu:
            if not ssh or not raw_iface or not hasattr(ssh, "execute"):
                return False, f"Dynamic modify unsupported for pool '{pool_name}' without live SSH connection"

            try:
                new_mtu = validate_isatap_mtu(mtu)
            except ValueError as e:
                return False, f"Invalid MTU: {e}"

            iface = raw_iface.replace("vxlb-isatap-", "").replace(".service", "")
            ok_cur, out_cur, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
            if ok_cur != 0:
                return False, f"Interface {iface} not found on host"

            svc = f"vxlb-isatap-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"
            ssh.execute(f"cp {unit_file} {unit_bak} 2>/dev/null || true")

            ok_set, _, err_set = ssh.execute(f"ip link set {shlex.quote(iface)} mtu {new_mtu}")
            if ok_set != 0:
                return False, f"Failed setting live MTU to {new_mtu}: {err_set}"

            update_unit_cmd = f"sed -i 's/mtu [0-9]\\+/mtu {new_mtu}/g' {unit_file} 2>/dev/null && systemctl daemon-reload"
            ssh.execute(update_unit_cmd)
            return True, f"ISATAP MTU updated to {new_mtu} for {iface}"

        return True, "No supported ISATAP modification requested"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.isatap import validate_isatap_mtu
        ssh = previous_state.get("ssh")
        raw_iface = previous_state.get("interface")
        prev_mtu = previous_state.get("mtu")

        if not ssh or not raw_iface or not hasattr(ssh, "execute"):
            return False, f"Rollback unsupported for pool '{pool_name}' without previous isatap snapshot"

        iface = raw_iface.replace("vxlb-isatap-", "").replace(".service", "")

        if prev_mtu:
            try:
                valid_mtu = validate_isatap_mtu(prev_mtu)
            except ValueError as e:
                return False, f"Invalid rollback MTU: {e}"

            svc = f"vxlb-isatap-{iface}.service"
            unit_file = f"/etc/systemd/system/{svc}"
            unit_bak = f"/etc/systemd/system/{svc}.bak"

            cmd = (
                f"ip link set {shlex.quote(iface)} mtu {valid_mtu} 2>/dev/null; "
                f"if [ -f {unit_bak} ]; then cp {unit_bak} {unit_file} && systemctl daemon-reload; fi"
            )
            ok, out, err = ssh.execute(cmd)
            if ok != 0:
                return False, f"ISATAP rollback failed for {iface}: {err or out}"
            return True, f"ISATAP rolled back to MTU {valid_mtu} for {iface}"

        return True, "Rollback completed"

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = identifier.replace("vxlb-isatap-", "").replace("vxlb-", "").replace(".service", "")
        svc = f"vxlb-isatap-{iface}.service"
        relay_svc = f"vxlb-isatap-{iface}-relay.service"
        relay_script = f"/etc/vxlb/{iface}-relay.py"

        cmd = (
            f"systemctl stop {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"systemctl disable {shlex.quote(relay_svc)} {shlex.quote(svc)} 2>/dev/null; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/systemd/system/{shlex.quote(relay_svc)} {shlex.quote(relay_script)}; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

# Register all kernel tunnel adapters
for cls in [
    Ip6Ip6Adapter,
    Gre6Adapter,
    GreTapAdapter,
    Gre6TapAdapter,
    Gre6TapIpsecAdapter,
    SitAdapter,
    SixToFourUnicastAdapter,
    ErspanIpsecAdapter,
    EoipAdapter,
    L2tpAdapter,
    IsatapAdapter,
]:
    register_adapter(cls())
