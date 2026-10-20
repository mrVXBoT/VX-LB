"""IP6IP6 (IPv6-in-IPv6) Tunnel Engine and Tools for VX-LB.

Coverage:
- Direct IPv6-in-IPv6 tunnel carried over native IPv6 underlay (RFC 2473)
- Verification of IPv6 reachability and return route between Iran and Kharej endpoints
- Private link creation with IPv6-primary internal addressing (IPv6 /126 and optional dual-stack IPv4 /30)
- MTU validation (1280..1460, default 1280; min 1280 per RFC 8200) and scoped routing (/128 and /32)
- Strict preservation of default routes, SSH management path, and existing tunnel resources
- Independent lifecycle: install, configure, start, stop, status, probe, modify, rollback, clean
- Security declaration: inherently cleartext; no cryptography or obfuscation
"""
import copy
import hashlib
import logging
import re
import secrets
import shlex
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from core.ipv6_tunnel_tools import (
    CLEARTEXT_WARNING,
    allocate_tunnel_ips,
    check_ipv6_reachability,
    check_kernel_prerequisites,
    execute_active_data_probe,
    parse_link_telemetry,
    render_scoped_service,
    sanitize_interface_name,
    synthesize_status,
    validate_ipv6_address,
    validate_mtu,
)

from core.ssh_client import SSHManager

logger = logging.getLogger("vxlb.ip6ip6")

ENGINE_ID = "ip6ip6"
TUNNEL_MODE = "ip6tnl"
TUNNEL_SUBMODE = "ip6ip6"
KERNEL_MODULE = "ip6_tunnel"
DEFAULT_MTU = 1280
MIN_MTU = 1280  # RFC 8200 required minimum MTU for IPv6
MAX_MTU = 1460  # 1500 - 40 (outer IPv6 header)


def validate_ip6ip6_mtu(mtu_value: Any) -> int:
    """Validates MTU for IP6IP6 tunnel."""
    return validate_mtu(mtu_value, MIN_MTU, MAX_MTU, tunnel_type="IP6IP6")


def check_return_route(ssh: Any, remote_ipv6: str) -> Tuple[bool, str]:
    """Verifies that the target host's kernel routing table contains a valid route to the remote IPv6."""
    if not hasattr(ssh, "execute"):
        return False, "Invalid SSH manager for return route check"

    norm_ip = validate_ipv6_address(remote_ipv6)
    cmd = f"ip -6 route get {shlex.quote(norm_ip)}"
    code, out, err = ssh.execute(cmd)
    if code != 0:
        return False, f"Return route check to {norm_ip} failed: {err.strip() or out.strip()}"

    if "unreachable" in out.lower() or "throw" in out.lower():
        return False, f"Route to {norm_ip} is marked unreachable in kernel routing table"

    return True, f"Valid route to {norm_ip} found: {out.strip().splitlines()[0]}"


def check_ip6ip6_prerequisites(ssh: Any, remote_ipv6: Optional[str] = None) -> Tuple[bool, str]:
    """Verifies that kernel module 'ip6_tunnel' is present, IPv6 is reachable, and return route exists."""
    ok_kern, msg_kern = check_kernel_prerequisites(ssh, KERNEL_MODULE)
    if not ok_kern:
        return False, msg_kern

    if remote_ipv6:
        ok_route, msg_route = check_return_route(ssh, remote_ipv6)
        if not ok_route:
            return False, f"IP6IP6 return route check failed: {msg_route}"

        ok_ping, msg_ping = check_ipv6_reachability(ssh, remote_ipv6)
        if not ok_ping:
            return False, f"IP6IP6 IPv6 reachability preflight failed: {msg_ping}"

    return True, "IP6IP6 kernel module, return route, and IPv6 reachability prerequisites verified"


def configure_ip6ip6_link(
    iran_node: dict,
    kharej_server: dict,
    pool_config: Optional[dict] = None,
) -> dict:
    """Generates complete configuration and systemd service specifications for IP6IP6.

    Specifies:
    - External address family: IPv6
    - Internal address family: IPv6 (RFC 2473 native) with optional dual-stack IPv4
    - Inherently unencrypted cleartext status
    - Scoped routing restricted dev interface
    """
    pool_config = pool_config or {}

    ir_ip = validate_ipv6_address(iran_node.get("ip"))
    kh_ip = validate_ipv6_address(kharej_server.get("ip"))

    if ir_ip == kh_ip:
        raise ValueError("IP6IP6 local and remote endpoints must be distinct IPv6 addresses")

    custom_iface = pool_config.get("interface")
    if custom_iface:
        iface = sanitize_interface_name("lip6", custom_iface.replace("lip6-", ""))
    else:
        peer_name = kharej_server.get("server_name") or pool_config.get("pool_name") or ""
        clean_node = re.sub(r"[^a-zA-Z0-9]", "", iran_node.get("node_name") or "ir").lower()
        peer_key = f"{peer_name}_{kh_ip}"
        h = hashlib.md5(peer_key.encode("utf-8")).hexdigest()[:4]
        max_node_len = 15 - len("lip6") - 1 - 4
        iface = f"lip6-{clean_node[:max_node_len]}{h}"

    mtu = validate_ip6ip6_mtu(pool_config.get("mtu", DEFAULT_MTU))

    # Allocate private point-to-point addressing
    ips = allocate_tunnel_ips(
        base_id=f"ip6ip6-{iface}-{ir_ip}-{kh_ip}",
        ipv4_subnet=pool_config.get("ipv4_subnet"),
        ipv6_subnet=pool_config.get("ipv6_subnet"),
        prefix_v4="10.206",
        prefix_v6="fd00:1db0:66",
    )

    svc_name = f"vxlb-ip6ip6-{iface}.service"
    conf_path = f"/etc/vxlb/ip6ip6/{iface}.json"

    # Command for Iran endpoint: ip link add ... type ip6tnl mode ip6ip6 ...
    ir_create_cmd = (
        f"ip link add {iface} type {TUNNEL_MODE} mode {TUNNEL_SUBMODE} "
        f"local {ir_ip} remote {kh_ip} encaplimit 4 hoplimit 64"
    )
    # Command for Kharej endpoint
    kh_create_cmd = (
        f"ip link add {iface} type {TUNNEL_MODE} mode {TUNNEL_SUBMODE} "
        f"local {kh_ip} remote {ir_ip} encaplimit 4 hoplimit 64"
    )

    unit_script = f"{ir_create_cmd} && ip link set {iface} mtu {mtu} up"

    # Internal address family for IP6IP6: RFC 2473 encapsulates IPv6 only by default in kernel mode ip6ip6
    include_ipv4 = bool(pool_config.get("enable_dual_stack", False))

    ir_service_unit = render_scoped_service(
        service_name=svc_name,
        interface=iface,
        create_link_cmd=ir_create_cmd,
        mtu=mtu,
        local_priv_v4=ips["iran_ipv4"] if include_ipv4 else None,
        local_priv_v6=ips["iran_ipv6"],
        peer_priv_v4=ips["kharej_ipv4"] if include_ipv4 else None,
        peer_priv_v6=ips["kharej_ipv6"],
    )

    kh_service_unit = render_scoped_service(
        service_name=svc_name,
        interface=iface,
        create_link_cmd=kh_create_cmd,
        mtu=mtu,
        local_priv_v4=ips["kharej_ipv4"] if include_ipv4 else None,
        local_priv_v6=ips["kharej_ipv6"],
        peer_priv_v4=ips["iran_ipv4"] if include_ipv4 else None,
        peer_priv_v6=ips["iran_ipv6"],
    )

    return {
        "engine": ENGINE_ID,
        "mode": TUNNEL_MODE,
        "tunnel_submode": TUNNEL_SUBMODE,
        "interface": iface,
        "mtu": mtu,
        "local_ip": ir_ip,
        "remote_ip": kh_ip,
        "service_name": svc_name,
        "unit_script": unit_script,
        "config_path": conf_path,
        "iran_service_unit": ir_service_unit,
        "kharej_service_unit": kh_service_unit,
        "address_families": {
            "external": "ipv6",
            "internal": ["ipv6", "ipv4"] if include_ipv4 else ["ipv6"],
        },
        "private_addressing": {
            "iran_ipv6": ips["iran_ipv6"],
            "kharej_ipv6": ips["kharej_ipv6"],
            "ipv6_subnet": ips["ipv6_subnet"],
            "iran_ipv4": ips["iran_ipv4"] if include_ipv4 else None,
            "kharej_ipv4": ips["kharej_ipv4"] if include_ipv4 else None,
            "ipv4_subnet": ips["ipv4_subnet"] if include_ipv4 else None,
        },
        "security": {
            "requires_encryption": False,
            "encryption_type": "none",
            "cleartext": True,
            "warning": CLEARTEXT_WARNING,
        },
        "ssh_management_protection": {
            "default_route_altered": False,
            "routing_scope": "interface-only host routes (/128" + (" and /32)" if include_ipv4 else ")"),
        },
    }


def connect(node: dict) -> SSHManager:
    ssh = SSHManager(
        ip=node["ip"],
        port=node.get("port", 22),
        username=node.get("username", "root"),
        password=node.get("password"),
        timeout=15,
    )
    ok, err = ssh.connect()
    if not ok:
        raise RuntimeError(f"SSH connection failed to {node['ip']}: {err}")
    return ssh


def create(name: str, kharej: dict, servers: list, ports: list, mtu: int = 1280, callback=None) -> Tuple[bool, str, dict]:
    import json
    from core.storage import get_pools, save_pool
    from core.validation import validate_pool_name, validate_ports

    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        mtu = validate_ip6ip6_mtu(mtu)
        # Mandatory outer IPv6 validation on both sides
        validate_ipv6_address(kharej.get("ip"))
        if not servers:
            raise ValueError("Select at least one Iran server")
        for server in servers:
            validate_ipv6_address(server.get("ip"))
        if len({s["ip"] for s in servers}) != len(servers):
            raise ValueError("Duplicate Iran server")
        if name in get_pools():
            raise ValueError("Pool name already exists")
        from core.load_balancer import LoadBalancerManager
        ok, message = LoadBalancerManager.check_port_conflicts(ports, [s["ip"] for s in servers])
        if not ok:
            return False, message, {}
    except ValueError as error:
        return False, str(error), {}

    pool = dict(
        name=name,
        engine="ip6ip6",
        transport="ip6ip6",
        ip6ip6_mtu=mtu,
        client_ports=ports,
        kharej_server=kharej,
        nodes=[],
        created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
    )
    save_pool(name, pool)
    failures = []
    for server in servers:
        ok, message = add(name, server, callback)
        if not ok:
            failures.append(f"{server['ip']}: {message}")

    pool = get_pools().get(name, pool)
    ready = [n for n in pool.get("nodes", []) if not n.get("provisioning")]
    return (
        bool(ready),
        (
            "IP6IP6 pool ready"
            + ("; failures: " + "; ".join(failures) if failures else "")
            if ready
            else "; ".join(failures)
        ),
        pool,
    )


def add(pool_name: str, server: dict, callback=None) -> Tuple[bool, str]:
    import json
    from core.adapter_registry import get_adapter
    from core.storage import get_pools, atomic_update
    from core.ipv6_tunnel_tools import render_relay_service

    pool = get_pools().get(pool_name)
    if not pool:
        return False, "Pool not found"
    kharej = pool["kharej_server"]
    try:
        validate_ipv6_address(server.get("ip"))
        validate_ipv6_address(kharej.get("ip"))
    except ValueError as e:
        return False, f"IP6IP6 requires native IPv6 address: {e}"

    adapter = get_adapter("ip6ip6")
    if not adapter:
        return False, "IP6IP6 adapter not found in registry"

    sessions = []
    conf = None
    from core.native_ipv6_lifecycle import publish, cleanup_endpoint
    try:
        if callback:
            callback(f"Connecting to Iran server {server['ip']} and Kharej {kharej['ip']}...")
        ir_ssh = connect(server)
        sessions.append(ir_ssh)
        kh_ssh = connect(kharej)
        sessions.append(kh_ssh)

        ok_ir, msg_ir = adapter.install(ir_ssh, "iran", {"remote_ip": kharej["ip"]})
        if not ok_ir:
            return False, f"Iran prerequisite check failed: {msg_ir}"
        ok_kh, msg_kh = adapter.install(kh_ssh, "kharej", {"remote_ip": server["ip"]})
        if not ok_kh:
            return False, f"Kharej prerequisite check failed: {msg_kh}"

        conf = adapter.configure(iran_node=server, kharej_server=kharej, pool_config={"mtu": pool.get("ip6ip6_mtu", 1420), "pool_name": pool_name, "enable_dual_stack": False})
        iface = conf["interface"]
        svc = conf["service_name"]

        node = {
            "server_name": server.get("name", server["ip"]),
            "ip": server["ip"],
            "node_name": iface,
            "engine": "ip6ip6",
            "transport": "ip6ip6",
            "ip6ip6": {
                "interface": iface,
                "mtu": conf["mtu"],
                "local_ipv6": conf["local_ip"],
                "remote_ipv6": conf["remote_ip"],
                "local_private": conf["private_addressing"]["iran_ipv6"],
                "remote_private": conf["private_addressing"]["kharej_ipv6"],
                "private_addressing": conf["private_addressing"],
                "configs": [conf],
            },
            "status": "PROVISIONING",
            "provisioning": True,
        }
        def append_node(data):
            data["pools"][pool_name]["nodes"].append(node)
        atomic_update(append_node)

        # Deploy on Kharej
        kh_ssh.execute("mkdir -p /etc/vxlb/ip6ip6")
        publish(kh_ssh, f"/etc/systemd/system/{svc}", conf["kharej_service_unit"])
        publish(kh_ssh, conf["config_path"], json.dumps(conf, indent=2))
        ok_start_kh, msg_start_kh = adapter.start(kh_ssh, iface)
        if not ok_start_kh:
            raise RuntimeError(f"Failed starting IP6IP6 on Kharej: {msg_start_kh}")

        # Deploy on Iran
        ir_ssh.execute("mkdir -p /etc/vxlb/ip6ip6")
        publish(ir_ssh, f"/etc/systemd/system/{svc}", conf["iran_service_unit"])
        publish(ir_ssh, conf["config_path"], json.dumps(conf, indent=2))
        ok_start_ir, msg_start_ir = adapter.start(ir_ssh, iface)
        if not ok_start_ir:
            raise RuntimeError(f"Failed starting IP6IP6 on Iran: {msg_start_ir}")

        # Deploy TCP/UDP relay on Iran forwarding to Kharej IPv6 private endpoint
        ports = pool.get("client_ports", [])
        if ports:
            target_priv = conf["private_addressing"]["kharej_ipv6"]
            relay_code, relay_unit = render_relay_service(f"vxlb-ip6ip6-{iface}-relay.service", iface, target_priv, ports)
            publish(ir_ssh, f"/etc/vxlb/{iface}-relay.py", relay_code)
            publish(ir_ssh, f"/etc/systemd/system/vxlb-ip6ip6-{iface}-relay.service", relay_unit)
            code, _, error = ir_ssh.execute(f"systemctl daemon-reload && systemctl enable --now vxlb-ip6ip6-{iface}-relay.service")
            if code:
                raise RuntimeError("Native IPv6 relay startup failed: " + error)

        if ports:
            from core.kernel_relay_ports import verify_listeners
            verify_listeners(ir_ssh, f"vxlb-ip6ip6-{iface}-relay.service", ports)
        from core.private_link_health import probe_pair
        result = probe_pair(ir_ssh, kh_ssh, node["ip6ip6"]["local_private"], node["ip6ip6"]["remote_private"], iface)
        def finalize(data):
            for entry in data["pools"][pool_name]["nodes"]:
                if entry["node_name"] == iface:
                    entry.update(provisioning=False, status="HEALTHY", reason="TCP/UDP private link verified", latency_ms=result["latency_ms"])
        atomic_update(finalize)
        return True, "IP6IP6 node added successfully"
    except Exception as err:
        cleanup_errors = []
        if conf is not None:
            for ssh in sessions:
                try:
                    cleanup_endpoint(ssh, adapter, conf["interface"], "ip6ip6")
                except Exception as cleanup_error:
                    cleanup_errors.append(str(cleanup_error))
            def record_failure(data):
                nodes = data["pools"][pool_name]["nodes"]
                if not cleanup_errors:
                    data["pools"][pool_name]["nodes"] = [n for n in nodes if n["node_name"] != conf["interface"]]
                else:
                    for entry in nodes:
                        if entry["node_name"] == conf["interface"]:
                            entry.update(status="FAILED", provisioning=True, reason=str(err), cleanup_error="; ".join(cleanup_errors))
            atomic_update(record_failure)
        return False, str(err) + ("; cleanup required: " + "; ".join(cleanup_errors) if cleanup_errors else "")
    finally:
        for s in sessions:
            s.close()


def remove(pool_name: str, ip: str, callback=None) -> Tuple[bool, str]:
    from core.adapter_registry import get_adapter
    from core.storage import get_pools, atomic_update

    pool = get_pools().get(pool_name, {})
    node = next((n for n in pool.get("nodes", []) if n["ip"] == ip), None)
    if not node:
        return False, "Node not found in pool"
    iface = node.get("node_name") or node.get("ip6ip6", {}).get("interface", "")
    adapter = get_adapter("ip6ip6")
    sessions = []
    try:
        from core.kernel_relay_ports import node_credentials
        ir_ssh = connect(node_credentials(node))
        sessions.append(ir_ssh)
        kh_ssh = connect(pool["kharej_server"])
        sessions.append(kh_ssh)

        from core.native_ipv6_lifecycle import cleanup_endpoint
        for ssh in (ir_ssh, kh_ssh):
            cleanup_endpoint(ssh, adapter, iface, "ip6ip6")

        def discard(data):
            data["pools"][pool_name]["nodes"] = [n for n in data["pools"][pool_name]["nodes"] if n["ip"] != ip]
        atomic_update(discard)
        return True, "IP6IP6 node removed successfully"
    except Exception as err:
        return False, str(err)
    finally:
        for s in sessions:
            s.close()


def remove_pool(name: str, callback=None) -> Tuple[bool, str]:
    from core.storage import get_pools, delete_pool

    pool = get_pools().get(name)
    if not pool:
        return False, "Pool not found"
    for node in list(pool.get("nodes", [])):
        ok, msg = remove(name, node["ip"], callback)
        if not ok:
            return False, msg
    delete_pool(name)
    return True, f"IP6IP6 pool '{name}' removed successfully"


def change_mtu(pool_name: str, new_mtu: int) -> Tuple[bool, str]:
    from core.adapter_registry import get_adapter
    from core.storage import get_pools, atomic_update

    new_mtu = validate_ip6ip6_mtu(new_mtu)
    pool = get_pools().get(pool_name)
    if not pool:
        return False, "Pool not found"
    old_mtu = pool.get("ip6ip6_mtu", 1420)
    if old_mtu == new_mtu:
        return True, "MTU is already up-to-date"

    adapter = get_adapter("ip6ip6")
    if not adapter:
        return False, "IP6IP6 adapter not found"

    from core.kernel_relay_ports import node_credentials
    from core.private_link_health import probe_pair
    sessions = []
    updated_nodes = []
    updated_endpoints = []
    try:
        kh_ssh = connect(pool["kharej_server"])
        sessions.append(kh_ssh)
        for node in pool.get("nodes", []):
            iface = node.get("node_name") or node.get("ip6ip6", {}).get("interface", "")
            ir_ssh = connect(node_credentials(node))
            sessions.append(ir_ssh)
            updated_nodes.append((ir_ssh, kh_ssh, iface, node))
            updated_endpoints.append((ir_ssh, iface))
            ok_ir, msg_ir = adapter.modify(pool_name, {"ssh": ir_ssh, "interface": iface, "mtu": new_mtu})
            if not ok_ir:
                raise RuntimeError(f"Failed setting MTU on Iran node {node['ip']}: {msg_ir}")
            updated_endpoints.append((kh_ssh, iface))
            ok_kh, msg_kh = adapter.modify(pool_name, {"ssh": kh_ssh, "interface": iface, "mtu": new_mtu})
            if not ok_kh:
                raise RuntimeError(f"Failed setting MTU on Kharej for {node['ip']}: {msg_kh}")
            probe_pair(ir_ssh, kh_ssh, node["ip6ip6"]["local_private"], node["ip6ip6"]["remote_private"], iface)

        def update_p(data):
            data["pools"][pool_name]["ip6ip6_mtu"] = new_mtu
            for n in data["pools"][pool_name]["nodes"]:
                n.setdefault("ip6ip6", {})["mtu"] = new_mtu
        atomic_update(update_p)
        return True, f"IP6IP6 MTU updated to {new_mtu}"
    except Exception as err:
        errors = []
        for ssh, iface in reversed(updated_endpoints):
            try:
                ok, message = adapter.rollback(pool_name, {"ssh": ssh, "interface": iface, "mtu": old_mtu})
                if not ok:
                    errors.append(message)
            except Exception as rollback_error:
                errors.append(str(rollback_error))
        if not errors:
            for ir_ssh, kh_ssh, iface, node in updated_nodes:
                try:
                    probe_pair(ir_ssh, kh_ssh, node["ip6ip6"]["local_private"], node["ip6ip6"]["remote_private"], iface)
                except Exception as rollback_error:
                    errors.append(str(rollback_error))
        detail = "rollback unverified: " + "; ".join(errors) if errors else f"restored MTU {old_mtu}"
        return False, f"MTU update failed ({detail}): {err}"
    finally:
        for s in sessions:
            s.close()


def health(pool_name: str, node: dict, ports: list) -> Tuple[str, str, dict]:
    from core.private_link_health import health as check_health
    return check_health(pool_name, node, ports)


def pool_status(name: str) -> Tuple[bool, str, dict]:
    """Inspect live status of all IP6IP6 nodes in the pool."""
    from core.adapter_registry import get_adapter
    from core.storage import get_pools

    pool = get_pools().get(name)
    if not pool:
        return False, "استخر یافت نشد", {}
    adapter = get_adapter("ip6ip6")
    results = {}
    sessions = []
    try:
        for node in pool.get("nodes", []):
            iface = node.get("node_name") or node.get("ip6ip6", {}).get("interface", "")
            try:
                ir_ssh = connect(node)
                sessions.append(ir_ssh)
                st = adapter.status(ir_ssh, iface) if adapter else {"status": "UNKNOWN"}
                results[node["ip"]] = st
            except Exception as e:
                results[node["ip"]] = {"connected": False, "error": str(e), "status": "DOWN"}
        return True, "وضعیت با موفقیت دریافت شد", results
    finally:
        for s in sessions:
            try:
                s.close()
            except Exception:
                pass


