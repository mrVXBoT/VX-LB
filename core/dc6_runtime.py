"""Owned DC6 lifecycle over native IPv6 GRE/IP6IP6 or IPv4 SIT."""
import json
import time
from functools import wraps
import ipaddress
from typing import Tuple
from core.storage import get_pools, save_pool, atomic_update
from core.transport_change import connect, mutation_lock
from core.ipv6_tunnel_tools import validate_ipv6_address


def validate_outer(value, carrier):
    if carrier == 'sit':
        try:
            address = ipaddress.IPv4Address(value)
        except (ipaddress.AddressValueError, ValueError):
            raise ValueError(f"حامل SIT نیازمند آدرس IPv4 معتبر است؛ '{value}' IPv4 نیست")
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError('SIT requires a unicast outer IPv4 address')
        return str(address)
    try:
        return validate_ipv6_address(value)
    except ValueError:
        raise ValueError(f"حامل {carrier} نیازمند IPv6 عمومی است؛ سرور '{value}' IPv4 دارد — حامل 'sit' را انتخاب کنید یا IPv6 سرور را فعال کنید")


def validate_dc6_mtu(value):
    from core.dc6_adapter import validate_dc6_mtu as validate
    return validate(value)


def validate_carrier_type(value):
    from core.dc6_adapter import validate_carrier_type as validate
    return validate(value)


def serialized(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with mutation_lock():
            return function(*args, **kwargs)
    return wrapped


@serialized
def create(name: str, kharej: dict, servers: list, ports: list, mtu: int = 1280, callback=None, carrier="ip6gre") -> Tuple[bool, str, dict]:
    import json
    from core.storage import get_pools, save_pool
    from core.validation import validate_pool_name, validate_ports

    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        mtu = validate_dc6_mtu(mtu)
        carrier = validate_carrier_type(carrier)
        # For IPv6 carriers `ip` may be IPv4 while a global IPv6 lives in `ipv6`
        # or is discoverable over SSH during add() — don't hard-fail here.
        if carrier == "sit":
            validate_outer(kharej.get("ip"), carrier)
            for server in servers:
                validate_outer(server.get("ip"), carrier)
        else:
            for endpoint in [kharej, *servers]:
                ip, v6 = str(endpoint.get("ip") or ""), str(endpoint.get("ipv6") or "")
                if ":" not in ip and ":" not in v6:
                    raise ValueError(
                        f"حامل {carrier} نیازمند IPv6 عمومی است؛ سرور '{ip}' IPv6 ندارد — "
                        "IPv6 را در فرم سرور وارد کنید یا حامل 'sit' را انتخاب کنید"
                    )
                validate_outer(_dc6_outer(endpoint, carrier), carrier)
        if not ports or not servers:
            raise ValueError("Select at least one Iran server")
        if len({s["ip"] for s in servers}) != len(servers):
            raise ValueError("Duplicate Iran server")
        if name in get_pools():
            raise ValueError("Pool name already exists")
        from core.load_balancer import LoadBalancerManager
        ok, message = LoadBalancerManager.check_port_conflicts(ports, [s["ip"] for s in servers], exclude_pool_name=name)
        if not ok:
            return False, message, {}
    except ValueError as error:
        return False, str(error), {}

    pool = dict(
        name=name,
        engine="dc6",
        transport="dc6",
        dc6_mtu=mtu,
        carrier_type=carrier,
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
            "DC6 pool ready"
            + ("; failures: " + "; ".join(failures) if failures else "")
            if ready
            else "; ".join(failures)
        ),
        pool,
    )


def _dc6_outer(server: dict, carrier: str) -> str:
    """Outer address used for the DC6 carrier for this endpoint.

    For IPv6-based carriers prefer the explicit `ipv6` field; `ip` may hold the
    IPv4 management address. For SIT, `ip` is used as-is (it must be IPv4).
    """
    if carrier == "sit":
        return str(server.get("ip") or "")
    ip6 = str(server.get("ipv6") or "").strip()
    if ip6:
        return ip6
    return str(server.get("ip") or "")


def _discover_global_ipv6(ssh) -> str:
    """Return the first global-scope IPv6 address found on the remote host."""
    code, out, _ = ssh.execute(
        "ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1"
    )
    if code:
        return ""
    return out.strip().splitlines()[0].strip() if out.strip() else ""


def _resolve_dc6_v6_endpoints(server: dict, kharej: dict, ir_ssh, kh_ssh, carrier: str):
    """Ensure both endpoints carry a usable global IPv6 in their `ipv6` field.

    Order of preference per endpoint: stored `ipv6`, `ip` if already IPv6,
    then SSH auto-discovery of a global-scope address. Mutates and returns the
    endpoint dicts; returns (None, None) when either side cannot be resolved.
    """
    resolved = []
    for endpoint, ssh in ((server, ir_ssh), (kharej, kh_ssh)):
        v6 = str(endpoint.get("ipv6") or "").strip()
        if not v6:
            ip = str(endpoint.get("ip") or "").strip()
            v6 = ip if ":" in ip else _discover_global_ipv6(ssh)
        try:
            endpoint["ipv6"] = validate_ipv6_address(v6)
        except (ValueError, TypeError):
            return None, None
        resolved.append(endpoint)
    return resolved[0], resolved[1]


@serialized
def add(pool_name: str, server: dict, callback=None) -> Tuple[bool, str]:
    import json
    from core.adapter_registry import get_adapter
    from core.storage import get_pools, atomic_update
    from core.ipv6_tunnel_tools import render_relay_service

    pool = get_pools().get(pool_name)
    if not pool:
        return False, "Pool not found"
    kharej = pool["kharej_server"]
    if any(node["ip"] == server["ip"] for node in pool.get("nodes", [])):
        return False, "Server already belongs to DC6 pool"
    from core.load_balancer import LoadBalancerManager
    ok, message = LoadBalancerManager.check_port_conflicts(pool['client_ports'], [server['ip']], exclude_pool_name=pool_name)
    if not ok:
        return False, message
    try:
        # For IPv6 carriers, `ip` may be IPv4 while a global IPv6 exists in `ipv6`
        # or discoverable over SSH — resolve inside the try block below.
        if pool["carrier_type"] == "sit":
            validate_outer(server.get("ip"), "sit")
            validate_outer(kharej.get("ip"), "sit")
        else:
            has_v6 = lambda s: ":" in str(s.get("ip") or "") or ":" in str(s.get("ipv6") or "")
            if not (has_v6(server) and has_v6(kharej)):
                pass  # discovery over SSH will resolve or produce a clear error
            else:
                validate_outer(_dc6_outer(server, pool["carrier_type"]), pool["carrier_type"])
                validate_outer(_dc6_outer(kharej, pool["carrier_type"]), pool["carrier_type"])
    except ValueError as e:
        return False, f"DC6 carrier address is invalid: {e}"

    adapter = get_adapter("dc6")
    if not adapter:
        return False, "DC6 adapter not found in registry"

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

        carrier = pool["carrier_type"]
        if carrier != "sit":
            server, kharej = _resolve_dc6_v6_endpoints(server, kharej, ir_ssh, kh_ssh, carrier)
            if not server or not kharej:
                return False, f"حامل {carrier} نیازمند IPv6 عمومی روی هر دو سرور است؛ IPv6 سرور را در فرم ثبت کنید یا روی سرور فعال کنید — یا حامل 'sit' را انتخاب کنید"

        ok_ir, msg_ir = adapter.install(ir_ssh, "iran", {"remote_ip": _dc6_outer(kharej, carrier), "carrier_type": carrier})
        if not ok_ir:
            return False, f"Iran prerequisite check failed: {msg_ir}"
        ok_kh, msg_kh = adapter.install(kh_ssh, "kharej", {"remote_ip": _dc6_outer(server, carrier), "carrier_type": carrier})
        if not ok_kh:
            return False, f"Kharej prerequisite check failed: {msg_kh}"

        conf = adapter.configure(iran_node=server, kharej_server=kharej, pool_config={"mtu": pool.get("dc6_mtu", 1280), "pool_name": pool_name, "carrier_type": carrier})
        iface = conf["interface"]
        svc = conf["service_name"]

        node = {
            "server_name": server.get("name", server["ip"]),
            "ip": server["ip"],
            "node_name": iface,
            "engine": "dc6",
            "transport": "dc6",
            "dc6": {
                "interface": iface,
                "mtu": conf["mtu"],
                "mss_clamp": conf["mss_clamp"],
                "outer_local": conf["local_ip"],
                "outer_remote": conf["remote_ip"],
                "local_private": (conf["private_addressing"]["iran_ipv4"] or conf["private_addressing"]["iran_ipv6"]),
                "remote_private": (conf["private_addressing"]["kharej_ipv4"] or conf["private_addressing"]["kharej_ipv6"]),
                "private_addressing": conf["private_addressing"],
                "configs": [conf],
                "carrier_type": pool["carrier_type"],
            },
            "status": "PROVISIONING",
            "provisioning": True,
        }
        def append_node(data):
            data["pools"][pool_name]["nodes"].append(node)
        atomic_update(append_node)

        publish(kh_ssh, conf["firewall_path"], json.dumps(conf["kharej_firewall"]))
        publish(ir_ssh, conf["firewall_path"], json.dumps(conf["iran_firewall"]))

        # Deploy on Kharej
        kh_ssh.execute("mkdir -p /etc/vxlb/dc6")
        publish(kh_ssh, f"/etc/systemd/system/{svc}", conf["kharej_service_unit"])
        publish(kh_ssh, conf["config_path"], json.dumps(conf, indent=2))
        ok_start_kh, msg_start_kh = adapter.start(kh_ssh, iface)
        if not ok_start_kh:
            raise RuntimeError(f"Failed starting DC6 on Kharej: {msg_start_kh}")

        # Deploy on Iran
        ir_ssh.execute("mkdir -p /etc/vxlb/dc6")
        publish(ir_ssh, f"/etc/systemd/system/{svc}", conf["iran_service_unit"])
        publish(ir_ssh, conf["config_path"], json.dumps(conf, indent=2))
        ok_start_ir, msg_start_ir = adapter.start(ir_ssh, iface)
        if not ok_start_ir:
            raise RuntimeError(f"Failed starting DC6 on Iran: {msg_start_ir}")

        # Deploy TCP/UDP relay on Iran for client ports
        ports = pool.get("client_ports", [])
        if ports:
            target_priv = (conf["private_addressing"]["kharej_ipv4"] or conf["private_addressing"]["kharej_ipv6"])
            relay_code, relay_unit = render_relay_service(f"vxlb-dc6-{iface}-relay.service", iface, target_priv, ports)
            publish(ir_ssh, f"/etc/vxlb/{iface}-relay.py", relay_code)
            publish(ir_ssh, f"/etc/systemd/system/vxlb-dc6-{iface}-relay.service", relay_unit)
            code, _, error = ir_ssh.execute(f"systemctl daemon-reload && systemctl enable --now vxlb-dc6-{iface}-relay.service")
            if code:
                raise RuntimeError("Native IPv6 relay startup failed: " + error)

        if ports:
            from core.kernel_relay_ports import verify_listeners
            verify_listeners(ir_ssh, f"vxlb-dc6-{iface}-relay.service", ports)
        from core.private_link_health import probe_pair
        result = probe_pair(ir_ssh, kh_ssh, node["dc6"]["local_private"], node["dc6"]["remote_private"], iface)
        def finalize(data):
            for entry in data["pools"][pool_name]["nodes"]:
                if entry["node_name"] == iface:
                    entry.update(provisioning=False, status="HEALTHY", reason="TCP/UDP private link verified", latency_ms=result["latency_ms"])
        atomic_update(finalize)
        return True, "DC6 node added successfully"
    except Exception as err:
        cleanup_errors = []
        if conf is not None:
            for ssh in sessions:
                try:
                    cleanup_endpoint(ssh, adapter, conf["interface"], "dc6")
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


@serialized
def remove(pool_name: str, ip: str, callback=None) -> Tuple[bool, str]:
    from core.adapter_registry import get_adapter
    from core.storage import get_pools, atomic_update

    pool = get_pools().get(pool_name, {})
    node = next((n for n in pool.get("nodes", []) if n["ip"] == ip), None)
    if not node:
        return False, "Node not found in pool"
    iface = node.get("node_name") or node.get("dc6", {}).get("interface", "")
    adapter = get_adapter("dc6")
    sessions = []
    try:
        from core.kernel_relay_ports import node_credentials
        ir_ssh = connect(node_credentials(node))
        sessions.append(ir_ssh)
        kh_ssh = connect(pool["kharej_server"])
        sessions.append(kh_ssh)

        from core.native_ipv6_lifecycle import cleanup_endpoint
        for ssh in (ir_ssh, kh_ssh):
            cleanup_endpoint(ssh, adapter, iface, "dc6")

        def discard(data):
            data["pools"][pool_name]["nodes"] = [n for n in data["pools"][pool_name]["nodes"] if n["ip"] != ip]
        atomic_update(discard)
        return True, "DC6 node removed successfully"
    except Exception as err:
        return False, str(err)
    finally:
        for s in sessions:
            s.close()


@serialized
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
    return True, f"DC6 pool '{name}' removed successfully"


def health(pool_name: str, node: dict, ports: list) -> Tuple[str, str, dict]:
    from core.private_link_health import health as check_health
    return check_health(pool_name, node, ports)


def pool_status(name: str) -> Tuple[bool, str, dict]:
    """Inspect live status of all DC6 nodes in the pool."""
    from core.adapter_registry import get_adapter
    from core.storage import get_pools

    pool = get_pools().get(name)
    if not pool:
        return False, "استخر یافت نشد", {}
    adapter = get_adapter("dc6")
    results = {}
    sessions = []
    try:
        for node in pool.get("nodes", []):
            iface = node.get("node_name") or node.get("dc6", {}).get("interface", "")
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
