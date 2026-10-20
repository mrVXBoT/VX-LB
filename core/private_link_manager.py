"""Private Link, Multi-Destination Topology, and Routing Manager for LD-BP.

Covers Sections 3 & 4 items:
- Port forwarding or engine chaining on any private link IP
- Standalone private links without forced port forwarding
- 4.1, 4.2, 4.3: Multi-destination topology (1:1, N:1, 1:M, N:M selected links)
- Link editing with diff preview
- Layered overhead calculation and Path MTU discovery
- Preservation of SSH management route
- Timed-rollback default route modification
- Preflight sysctl checks (ip_forward, rp_filter)
"""
import copy
import ipaddress
import time
import uuid
from typing import Dict, List, Optional, Tuple, Any
from core.storage import atomic_update, load_data
from core.resource_allocator import ResourceReservationManager
from core.capabilities import get_capability

STANDARD_ETHERNET_MTU = 1500

class PrivateLinkManager:
    """Manages independent Layer 2/3 private links across arbitrary Iran and Kharej endpoints."""

    @staticmethod
    def calculate_path_overhead(engine_id: str, underlying_engine: Optional[str] = None) -> int:
        """Calculates total header encapsulation overhead for single or layered hybrid tunnels."""
        cap = get_capability(engine_id)
        overhead = cap.overhead_bytes if cap else 60
        if underlying_engine:
            under_cap = get_capability(underlying_engine)
            if under_cap:
                overhead += under_cap.overhead_bytes
        return overhead

    @staticmethod
    def calculate_recommended_mtu(engine_id: str, underlying_engine: Optional[str] = None, base_mtu: int = STANDARD_ETHERNET_MTU) -> int:
        """Calculates recommended MTU considering full encapsulation stack."""
        overhead = PrivateLinkManager.calculate_path_overhead(engine_id, underlying_engine)
        return max(1200, base_mtu - overhead)

    @staticmethod
    def create_private_link(
        link_name: str,
        engine_id: str,
        iran_server: dict,
        kharej_server: dict,
        params: Optional[dict] = None,
        port_forwarding_rules: Optional[List[dict]] = None
    ) -> dict:
        """Creates an independent private link with optional port forwarding."""
        result = None
        def reserve(data):
            nonlocal result
            result = PrivateLinkManager._plan_in_data(data, link_name, engine_id, iran_server, kharej_server, params or {}, port_forwarding_rules)
        atomic_update(reserve)
        return result

    @staticmethod
    def validate_profile_ipv6_prerequisites(
        engine_id: str,
        iran_server: dict,
        kharej_server: dict,
        ssh_manager: Any = None
    ) -> Tuple[bool, Optional[str]]:
        """Validates Native IPv6 prerequisites for profiles requiring IPv6.
        
        Returns (True, None) if prerequisites met, or (False, persian_error_message).
        """
        cap = get_capability(engine_id)
        if not cap:
            return False, f"شناسه موتور '{engine_id}' نامعتبر است."

        try:
            ir_ip_obj = ipaddress.ip_address(iran_server.get("ip", ""))
            kh_ip_obj = ipaddress.ip_address(kharej_server.get("ip", ""))
        except ValueError as e:
            return False, f"آدرس IP نقطه پایانی نامعتبر است: {e}"

        # If engine requires native IPv6
        if cap.address_families == ["ipv6"]:
            if ir_ip_obj.version != 6:
                return False, (
                    f"پروفایل '{cap.display_name}' ({engine_id}) نیازمند آدرس Native IPv6 است، "
                    f"اما آدرس سرور ایران '{ir_ip_obj}' از نوع IPv4 می‌باشد."
                )
            if kh_ip_obj.version != 6:
                return False, (
                    f"پروفایل '{cap.display_name}' ({engine_id}) نیازمند آدرس Native IPv6 است، "
                    f"اما آدرس سرور خارج '{kh_ip_obj}' از نوع IPv4 می‌باشد."
                )
            if ssh_manager:
                code, out, _ = ssh_manager.execute("sysctl -n net.ipv6.conf.all.disable_ipv6")
                if code == 0 and out.strip() == "1":
                    return False, "پروتکل IPv6 در سطح کرنل سیستم‌عامل سرور غیرفعال (disable_ipv6=1) است."

        # If engine strictly requires IPv4
        elif cap.address_families == ["ipv4"]:
            if ir_ip_obj.version != 4:
                return False, (
                    f"پروفایل '{cap.display_name}' ({engine_id}) تنها از IPv4 پشتیبانی می‌کند، "
                    f"اما آدرس سرور ایران '{ir_ip_obj}' از نوع IPv6 است."
                )
            if kh_ip_obj.version != 4:
                return False, (
                    f"پروفایل '{cap.display_name}' ({engine_id}) تنها از IPv4 پشتیبانی می‌کند، "
                    f"اما آدرس سرور خارج '{kh_ip_obj}' از نوع IPv6 است."
                )

        return True, None

    @staticmethod
    def verify_bidirectional_routes(
        iran_ssh: Any,
        kharej_ssh: Any,
        iran_private_ip: str,
        kharej_private_ip: str,
        interface: Optional[str] = None
    ) -> Tuple[bool, dict]:
        """Verifies bidirectional routing between private link endpoints.
        
        Checks 'ip route get' on both hosts to confirm forward and reverse paths.
        """
        ir_code, ir_out, ir_err = iran_ssh.execute(f"ip route get {kharej_private_ip}")
        kh_code, kh_out, kh_err = kharej_ssh.execute(f"ip route get {iran_private_ip}")

        ir_ok = (ir_code == 0 and kharej_private_ip in ir_out and (interface is None or interface in ir_out))
        kh_ok = (kh_code == 0 and iran_private_ip in kh_out and (interface is None or interface in kh_out))

        details = {
            "iran_to_kharej": {
                "destination": kharej_private_ip,
                "success": ir_ok,
                "output": ir_out.strip() if ir_code == 0 else ir_err.strip()
            },
            "kharej_to_iran": {
                "destination": iran_private_ip,
                "success": kh_ok,
                "output": kh_out.strip() if kh_code == 0 else kh_err.strip()
            },
            "bidirectional_valid": ir_ok and kh_ok
        }
        return ir_ok and kh_ok, details

    @staticmethod
    def _plan_in_data(data, link_name, engine_id, iran_server, kharej_server, params, forwarding=None):
        from core.validation import validate_pool_name, validate_port
        link_name = validate_pool_name(link_name)
        if link_name in data.get('custom_links', {}):
            raise ValueError('Private link name already exists')
        capability = get_capability(engine_id)
        if capability is None:
            raise ValueError('Unknown link engine')

        # Validate IPv6 / IPv4 prerequisites
        ok_proto, proto_err = PrivateLinkManager.validate_profile_ipv6_prerequisites(engine_id, iran_server, kharej_server)
        if not ok_proto:
            raise ValueError(proto_err)

        iran_ip = str(ipaddress.ip_address(iran_server['ip']))
        outside_ip = str(ipaddress.ip_address(kharej_server['ip']))
        if iran_ip == outside_ip:
            raise ValueError('Private link endpoints must be different hosts')
        port = int(validate_port(params.get('tunnel_port', 51820)))
        iface = params.get('interface') or f'pl_{uuid.uuid4().hex[:8]}'
        overhead = PrivateLinkManager.calculate_path_overhead(engine_id, params.get('underlying_engine'))
        mtu = int(params.get('mtu') or STANDARD_ETHERNET_MTU - overhead)
        if not 576 <= mtu <= 9000:
            raise ValueError('Invalid private-link MTU')

        is_ipv6_only = capability.address_families == ["ipv6"]
        reservation = ResourceReservationManager.reserve_pool_resources(
            pool_name='link_'+link_name, engine_id=engine_id,
            host_ports={iran_ip: [port], outside_ip: [port]}, interface_names=[iface],
            needs_ipv4_subnet=not is_ipv6_only,
            needs_ipv6_subnet=is_ipv6_only,
            needs_vni=engine_id in ('vxlan', 'geneve', 'geneve_ipsec'),
            server_routes=params.get('server_routes'),
            _data=data)

        if is_ipv6_only:
            hosts = list(ipaddress.IPv6Network(reservation['ipv6_subnet']).hosts())
            subnet_val = reservation['ipv6_subnet']
        else:
            hosts = list(ipaddress.IPv4Network(reservation['ipv4_subnet']).hosts())
            subnet_val = reservation['ipv4_subnet']

        record = dict(link_id='link-'+uuid.uuid4().hex[:8], link_name=link_name, engine_id=engine_id,
                      status='planned', interface=iface, mtu=mtu, overhead_bytes=overhead,
                      iran_server=dict(ip=iran_ip, private_ip=str(hosts[0])),
                      kharej_server=dict(ip=outside_ip, private_ip=str(hosts[1])),
                      private_subnet=subnet_val, vni=reservation.get('vni'),
                      tunnel_port=port, reservation_owner='link_'+link_name,
                      port_forwarding_rules=forwarding or [], created_at=time.strftime('%Y-%m-%d %H:%M:%S'))
        data.setdefault('custom_links', {})[link_name] = record
        return record

    @staticmethod
    def provision_private_link(link_name):
        from core.private_link_runtime import provision
        return provision(link_name)

    @staticmethod
    def delete_private_link(link_name):
        from core.private_link_runtime import delete
        return delete(link_name)

    @staticmethod
    def preview_link_mutation(link_name: str, updates: dict) -> dict:
        """Generates a dry-run diff preview for updating link parameters."""
        data = load_data()
        link = data.get("custom_links", {}).get(link_name)
        if not link:
            raise ValueError(f"Link '{link_name}' not found")

        diff = {}
        for k, v in updates.items():
            current_val = link.get(k)
            if current_val != v:
                diff[k] = {"current": current_val, "proposed": v}
        return {
            "link_name": link_name,
            "has_changes": bool(diff),
            "diff": diff,
            "potential_downtime": "mtu" in diff or "engine_id" in diff
        }

    @staticmethod
    def estimate_mutation_impact(target_type: str, target_name: str, updates: dict) -> dict:
        """Estimates downtime, affected ports, and DNS impacts prior to execution."""
        data = load_data()
        breaking_changes: List[str] = []
        diff: Dict[str, dict] = {}
        affected_ports: List[int] = []

        if target_type == "link":
            link = data.get("custom_links", {}).get(target_name)
            if not link:
                raise ValueError(f"Link '{target_name}' not found")
            for k, v in updates.items():
                if link.get(k) != v:
                    diff[k] = {"current": link.get(k), "proposed": v}

            affected_ports.append(link.get("tunnel_port", 51820))
            for f in link.get("port_forwarding_rules", []):
                if "listen_port" in f:
                    affected_ports.append(f["listen_port"])

            if "engine_id" in diff or "iran_server" in diff or "kharej_server" in diff:
                downtime_risk = "disruptive"
                est_seconds = 20
                breaking_changes.append("تغییر پروتکل یا نودهای پایانی نیازمند بازسازی کامل اینترفیس است و نشست‌های فعال موقتاً قطع می‌شوند.")
            elif "tunnel_port" in diff:
                downtime_risk = "service_restart"
                est_seconds = 5
                breaking_changes.append("تغییر پورت تونل منجر به راه‌اندازی مجدد سوکت تونل خواهد شد.")
            elif "mtu" in diff:
                downtime_risk = "momentary_reconnect"
                est_seconds = 1
                breaking_changes.append("تغییر MTU با تنظیم دینامیک لینک اعمال می‌شود و احتمال وقفهٔ جزئی در پکت‌های بزرگ وجود دارد.")
            else:
                downtime_risk = "none"
                est_seconds = 0

            from core.firewall_lifecycle_manager import DependencyLifecycleManager
            dep_info = DependencyLifecycleManager.preview_dependent_resources(target_name)
            dependent_resources = dep_info.get("dependent_pools", []) + dep_info.get("dependent_forwardings", [])

            dns_impact = {
                "preserved": True,
                "details": "این عملیات روی لایهٔ شبکه مستقل اجرا می‌شود و رکوردهای DNS عمومی دست‌نخورده باقی می‌مانند."
            }

        elif target_type == "pool":
            pool = data.get("pools", {}).get(target_name)
            if not pool:
                raise ValueError(f"Pool '{target_name}' not found")
            for k, v in updates.items():
                if pool.get(k) != v:
                    diff[k] = {"current": pool.get(k), "proposed": v}

            affected_ports = list(pool.get("ports", []))
            if "transport" in diff or "engine_id" in diff:
                downtime_risk = "service_restart"
                est_seconds = 8
                breaking_changes.append("تغییر ترنسپورت استخر نیازمند بستن کانکشن‌های قدیمی و بازگشایی لیسنر با پروتکل جدید است.")
            elif "sni" in diff or "cert" in diff:
                downtime_risk = "momentary_reconnect"
                est_seconds = 3
                breaking_changes.append("تغییر گواهی و SNI نیازمند هندشیک جدید کلاینت‌ها خواهد بود.")
            else:
                downtime_risk = "none"
                est_seconds = 0

            dependent_resources = [f"node:{n.get('name', 'unknown')}" for n in pool.get("nodes", [])]
            dns_impact = {
                "preserved": True,
                "details": "رکوردهای Cloudflare و تنظیمات DNS دامنه‌های متصل حفظ می‌شوند و حذف نخواهند شد."
            }
        else:
            raise ValueError(f"Unsupported target_type '{target_type}'. Must be 'link' or 'pool'.")

        return {
            "target_type": target_type,
            "target_name": target_name,
            "has_changes": bool(diff),
            "diff": diff,
            "downtime_risk": downtime_risk,
            "estimated_downtime_seconds": est_seconds,
            "affected_ports": affected_ports,
            "dns_impact": dns_impact,
            "dependent_resources": dependent_resources,
            "breaking_changes": breaking_changes
        }

    @staticmethod
    def apply_link_mutation(link_name: str, updates: dict) -> dict:
        """Applies validated parameters to a private link."""
        updated = None

        def _update(data: dict):
            nonlocal updated
            links = data.setdefault("custom_links", {})
            if link_name not in links:
                raise ValueError(f"Link '{link_name}' not found")
            link = links[link_name]
            if set(updates) - {'mtu', 'description'}:
                raise ValueError('Endpoint/resource changes require a runtime transaction; metadata was not changed')
            if 'mtu' in updates:
                if link.get('status') != 'planned':
                    raise ValueError('An installed link requires a verified remote MTU update')
                mtu = int(updates['mtu'])
                if not 576 <= mtu <= 9000:
                    raise ValueError('Invalid link MTU')
                link['mtu'] = mtu
            if 'description' in updates:
                link['description'] = str(updates['description'])
            link["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            updated = dict(link)

        atomic_update(_update)
        return updated

    @staticmethod
    def create_timed_default_route_switch(ssh_manager: Any, gateway_ip: str, timeout_seconds: int = 60, execute: bool = False, dev: Optional[str] = None) -> dict:
        """Initiates a default route switch with timed watchdog rollback.

        If execute=True, executes the switch with an active systemd watchdog timer.
        If execute=False (default), generates a staged preview.
        """
        gateway_ip = str(ipaddress.IPv4Address(gateway_ip))
        timeout_seconds = int(timeout_seconds)
        if not 5 <= timeout_seconds <= 600:
            raise ValueError('Route rollback timeout must be 5..600 seconds')

        if execute:
            from core.timed_route_switch import execute_timed_route_switch
            return execute_timed_route_switch(ssh_manager, gateway_ip, timeout_seconds, dev)

        revert_script = f"""
ORIG_GW=$(ip route show default | awk '/default/ {{print $3}}' | head -n1)
ip route replace default via {gateway_ip}
(sleep {timeout_seconds} && ip route replace default via $ORIG_GW) &
"""
        return {
            "status": "staged",
            "executed": False,
            "gateway_ip": gateway_ip,
            "timeout_seconds": timeout_seconds,
            "script": revert_script.strip()
        }

    @staticmethod
    def confirm_timed_default_route_switch(ssh_manager: Any) -> Tuple[bool, str]:
        """Confirms default route switch and disarms watchdog timer."""
        from core.timed_route_switch import confirm_route_switch
        return confirm_route_switch(ssh_manager)

    @staticmethod
    def rollback_timed_default_route_switch(ssh_manager: Any) -> Tuple[bool, str]:
        """Triggers immediate rollback of default route."""
        from core.timed_route_switch import rollback_route_switch
        return rollback_route_switch(ssh_manager)


    @staticmethod
    def verify_preflight_sysctl(ssh_manager: Any) -> Tuple[bool, dict]:
        """Preflight checks for IP forwarding and reverse path filtering."""
        ok, out, _ = ssh_manager.execute("sysctl net.ipv4.ip_forward net.ipv4.conf.all.rp_filter")
        details = {}
        passed = False
        if ok == 0:
            for line in out.strip().split("\n"):
                if "=" in line:
                    k, v = [x.strip() for x in line.split("=", 1)]
                    details[k] = v
            passed = details.get('net.ipv4.ip_forward') == '1' and details.get('net.ipv4.conf.all.rp_filter') in ('0', '2')
        return passed, details

    @staticmethod
    def create_matrix_topology(
        iran_servers: List[dict],
        kharej_servers: List[dict],
        engine_id: str,
        selected_pairs: Optional[List[Tuple[str, str]]] = None,
        allow_full_mesh: bool = False,
        params: Optional[dict] = None,
        _data: Optional[dict] = None,
    ) -> List[dict]:
        """Creates selective multi-server topology.

        Supports 1:1, N:1, 1:M, and selective N:M links.
        Prevents accidental full-mesh link explosion (>10 links) unless allow_full_mesh=True.
        """
        params = params or {}
        ir_map = {s["ip"]: s for s in iran_servers}
        kh_map = {s["ip"]: s for s in kharej_servers}

        pairs_to_create: List[Tuple[dict, dict]] = []

        if selected_pairs is not None:
            for ir_ip, kh_ip in selected_pairs:
                if ir_ip not in ir_map:
                    raise ValueError(f"Iran server '{ir_ip}' not found in inventory")
                if kh_ip not in kh_map:
                    raise ValueError(f"Kharej server '{kh_ip}' not found in inventory")
                pairs_to_create.append((ir_map[ir_ip], kh_map[kh_ip]))
        else:
            total_potential_links = len(iran_servers) * len(kharej_servers)
            if total_potential_links > 10 and not allow_full_mesh:
                raise ValueError(
                    f"Full mesh would create {total_potential_links} links. "
                    f"Accidental full mesh explosion is blocked; "
                    f"specify 'selected_pairs' or set allow_full_mesh=True."
                )
            for ir in iran_servers:
                for kh in kharej_servers:
                    pairs_to_create.append((ir, kh))

        identities = [(ir['ip'], kh['ip']) for ir, kh in pairs_to_create]
        if len(identities) != len(set(identities)):
            raise ValueError('Duplicate matrix pair')
        if not identities:
            raise ValueError('Select at least one link pair')
        created_links = []
        base_port = int(params.get('tunnel_port', 51820))
        def reserve_all(data):
            # Build on an isolated candidate so a late collision cannot leave
            # an earlier pair or reservation behind, even for in-memory callers.
            candidate = copy.deepcopy(data)
            batch = uuid.uuid4().hex[:8]
            for index, (iran, outside) in enumerate(pairs_to_create):
                name = f'mesh_{engine_id}_{batch}_{index}'
                link = PrivateLinkManager._plan_in_data(candidate, name, engine_id, iran, outside,
                    {**params, 'tunnel_port': base_port + index})
                created_links.append(link)
            data.clear()
            data.update(candidate)
        if _data is None:
            atomic_update(reserve_all)
        else:
            reserve_all(_data)
        return created_links

    @staticmethod
    def apply_port_forwarding(link_name: str, rules: List[dict]) -> Tuple[bool, str]:
        """Applies TCP/UDP port forwarding rules across an active private link."""
        from core.private_link_forwarding import apply_forwarding_rules
        return apply_forwarding_rules(link_name, rules)

    @staticmethod
    def remove_port_forwarding(link_name: str) -> Tuple[bool, str]:
        """Stops and cleanly removes port forwarding relay from a private link."""
        from core.private_link_forwarding import remove_forwarding_rules
        return remove_forwarding_rules(link_name)
