import time
import copy
import uuid
from typing import Dict, List, Tuple, Callable, Optional
from core.ssh_client import SSHManager
from core.tunnel import (
    generate_token,
    setup_tunnel_node,
    stop_and_remove_tunnel,
    build_iran_config,
    SUPPORTED_TRANSPORTS,
)
from core.validation import (
    validate_pool_name,
    validate_port,
    validate_ports,
    validate_transport,
    shquote,
)
from core.storage import load_data, atomic_update, save_pool, get_pools, delete_pool as storage_delete_pool

class LoadBalancerManager:
    @staticmethod
    def check_port_conflicts(
        requested_ports: List[str],
        target_iran_ips: List[str],
        exclude_pool_name: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Ensures that requested client ports do not conflict with existing pools on overlapping Iran servers."""
        pools = get_pools()
        req_ports_set = set(str(p).strip() for p in requested_ports if str(p).strip())
        target_ips_set = set(str(ip).strip() for ip in target_iran_ips)

        for p_name, p_data in pools.items():
            if exclude_pool_name and p_name == exclude_pool_name:
                continue
            pool_nodes = p_data.get("nodes", [])
            pool_ips = set(n["ip"] for n in pool_nodes)
            shared_ips = target_ips_set.intersection(pool_ips)

            if shared_ips:
                existing_ports = set(str(p).strip() for p in p_data.get("client_ports", []))
                conflict_ports = req_ports_set.intersection(existing_ports)
                if conflict_ports:
                    return False, f"Port collision: Port(s) {', '.join(sorted(conflict_ports))} already used by pool '{p_name}' on shared Iran server(s) {', '.join(sorted(shared_ips))}!"
        return True, ""

    @staticmethod
    def set_pool_cloudflare(
        pool_name: str,
        api_token: str,
        zone_id: str,
        subdomain: str,
        enabled: bool = True,
        scope: str = "single"
    ) -> Tuple[bool, str]:
        """Configures independent Cloudflare credentials and subdomain for a specific pool."""
        pools = get_pools()
        if pool_name not in pools:
            return False, "Load balancer pool not found"
        if scope not in ('single','all_subdomains'): return False, 'Invalid DNS scope'
        if scope == 'all_subdomains': subdomain = subdomain.strip().lower().removeprefix('*.').rstrip('.')
        from core.dns_routing import scope_conflict
        conflict = scope_conflict(load_data(), pool_name, {'zone_id':zone_id.strip(),'subdomain':subdomain.strip().lower(),'scope':scope})
        if conflict: return False, f'DNS scope overlaps pool {conflict}'
        pools[pool_name]["cloudflare"] = {
            "api_token": api_token.strip(),
            "zone_id": zone_id.strip(),
            "subdomain": subdomain.strip().lower(),
            "enabled": enabled,
            "scope": scope
        }
        save_pool(pool_name, pools[pool_name])
        return True, f"Cloudflare DNS for pool '{pool_name}' set to '{subdomain}'"

    @staticmethod
    def create_pool(
        pool_name: str,
        kharej_server: dict,
        iran_servers: List[dict],
        transport: str,
        client_ports: List[str],
        callback: Optional[Callable[[str], None]] = None,
        gre_mtu: int = 1280,
        camouflage: Optional[dict] = None,
        **kwargs
    ) -> Tuple[bool, str, dict]:
        """
        Creates a new multi-Iran to 1-Kharej load balancing pool.
        """
        from core.capabilities import validate_production_readiness
        from core.transport_change import _coerce_engine
        engine = _coerce_engine(kwargs.get('engine'), transport)
        import os
        is_prod = bool(kwargs.get('is_production', False) or os.environ.get("VX_LB_PRODUCTION", "").lower() in ("1", "true", "yes"))
        allow_exp = bool(kwargs.get('allow_experimental', False))
        ok_gate, gate_msg = validate_production_readiness(engine, is_production=is_prod, allow_experimental=allow_exp)
        if not ok_gate:
            return False, gate_msg, {}

        if transport in {'http', 'https'}:
            from core.http_transport import create
            return create(pool_name, kharej_server, iran_servers, client_ports, transport=transport, callback=callback)
        if transport in {'xhttp', 'xhttps', 'gre_xhttp', 'reality', 'nova'}:
            from core.https_tunnel import create
            return create(pool_name, kharej_server, iran_servers, transport, client_ports, camouflage, callback)
        if transport in {'quantum', 'quantum+', 'quantum-gaming', 'paqet'}:
            from core.paqet_adapter import create
            settings = dict(camouflage or {})
            settings["transport"] = transport
            if kwargs.get("fec_datashard"):
                settings["fec_datashard"] = kwargs.get("fec_datashard")
            if kwargs.get("fec_parityshard"):
                settings["fec_parityshard"] = kwargs.get("fec_parityshard")
            return create(pool_name, kharej_server, iran_servers, client_ports, settings, callback)
        if transport == 'tun':
            from core.tun_adapter import create
            t_mtu = int(kwargs.get("tun_mtu") or kwargs.get("mtu") or 1280)
            return create(pool_name, kharej_server, iran_servers, client_ports, mtu=t_mtu, callback=callback)
        if transport == 'dc6':
            from core.dc6_adapter import create
            d_mtu = int(kwargs.get("dc6_mtu") or kwargs.get("mtu") or 1280)
            carrier = kwargs.get("carrier") or kwargs.get("carrier_type")
            if not carrier:
                kh_ip = str(kharej_server.get("ip", ""))
                carrier = "sit" if ("." in kh_ip and ":" not in kh_ip) else "ip6gre"
            return create(pool_name, kharej_server, iran_servers, client_ports, mtu=d_mtu, carrier=carrier, callback=callback)
        if transport == 'gre':
            from core.gre import create
            return create(pool_name, kharej_server, iran_servers, client_ports, gre_mtu, callback)
        if transport in {'geneve', 'geneve_ipsec'}:
            from core.geneve import create
            g_mtu = int(kwargs.get("geneve_mtu") or 1280)
            return create(pool_name, kharej_server, iran_servers, client_ports, mtu=g_mtu, vni=kwargs.get("vni"), callback=callback)
        if transport == 'waterwall':
            from core.waterwall import create
            return create(pool_name, kharej_server, iran_servers, client_ports, camouflage, callback)
        if transport == 'vxlan_ipsec':
            from core.vxlan_ipsec import create
            return create(
                name=pool_name,
                kharej=kharej_server,
                servers=iran_servers,
                ports=client_ports,
                mtu=int(kwargs.get("vxsec_mtu") or kwargs.get("mtu") or 1280),
                vni=kwargs.get("vni"),
                dst_port=kwargs.get("dst_port") or kwargs.get("tunnel_port") or 4789,
                callback=callback,
            )
        if transport == 'vxlan':
            from core.vxlan_adapter import create
            return create(
                name=pool_name,
                kharej=kharej_server,
                servers=iran_servers,
                ports=client_ports,
                vni=kwargs.get("vni"),
                vxlan_method=kwargs.get("vxlan_method") or kwargs.get("method") or "p2p",
                dst_port=kwargs.get("dst_port") or kwargs.get("tunnel_port") or 4789,
                mtu=kwargs.get("vxlan_mtu") or kwargs.get("mtu") or 1280,
                bridge_name=kwargs.get("bridge_name"),
                underlay_dev=kwargs.get("underlay_dev"),
                callback=callback,
            )
        if transport == 'gre6':
            from core.gre6 import create
            g6_mtu = int(kwargs.get("gre6_mtu") or kwargs.get("mtu") or 1280)
            return create(pool_name, kharej_server, iran_servers, client_ports, mtu=g6_mtu, callback=callback)
        if transport == 'ip6ip6':
            from core.ip6ip6 import create
            ip6_mtu = int(kwargs.get("ip6ip6_mtu") or kwargs.get("mtu") or 1280)
            return create(pool_name, kharej_server, iran_servers, client_ports, mtu=ip6_mtu, callback=callback)
        if transport == 'wireguard':
            from core.wireguard_adapter import create
            return create(
                name=pool_name,
                kharej=kharej_server,
                servers=iran_servers,
                ports=client_ports,
                settings={
                    "tunnel_port": kwargs.get("tunnel_port") or kwargs.get("wireguard_port") or 51820,
                    "mtu": kwargs.get("mtu") or kwargs.get("wireguard_mtu") or 1280,
                    "enable_psk": kwargs.get("enable_psk", False),
                    "ipv4_subnet": kwargs.get("ipv4_subnet", "10.100.2.0/30"),
                },
                callback=callback,
            )
        if transport == 'slipstream':
            from core.slipstream_adapter import create
            return create(
                name=pool_name,
                kharej=kharej_server,
                servers=iran_servers,
                ports=client_ports,
                domain=kwargs.get("domain") or (camouflage or {}).get("domain"),
                resolvers=kwargs.get("resolvers") or (camouflage or {}).get("resolvers"),
                dns_port=kwargs.get("dns_port") or (camouflage or {}).get("dns_port") or kwargs.get("tunnel_port") or 53,
                rate_limit=kwargs.get("rate_limit", 1000),
                mtu=kwargs.get("mtu", 1200),
                callback=callback,
            )
        from core.spoof_adapter import SPOOF_TRANSPORTS as _SPOOF_TRANSPORTS, create as spoof_create
        if transport in _SPOOF_TRANSPORTS or kwargs.get("engine") == "spoof":
            extra=dict(kwargs)
            fake_sni=extra.pop("fake_sni",None) or (camouflage or {}).get("server_name") or "www.shaparak.ir"
            return spoof_create(
                pool_name=pool_name,
                kharej_server=kharej_server,
                iran_servers=iran_servers,
                client_ports=client_ports,
                transport=transport,
                fake_sni=fake_sni,
                callback=callback,
                **extra
            )

        def log(msg: str):
            if callback:
                callback(msg)

        # Security: validate all operator input centrally BEFORE touching the network.
        # This closes the shell/config injection chain for every caller (CLI and web).
        try:
            pool_name = validate_pool_name(pool_name)
            transport = validate_transport(transport, SUPPORTED_TRANSPORTS)
            client_ports = validate_ports(client_ports)
        except ValueError as e:
            return False, str(e), {}

        # Check port collision before provisioning
        iran_ips = [s["ip"] for s in iran_servers]
        ok_conflict, err_conflict = LoadBalancerManager.check_port_conflicts(client_ports, iran_ips)
        if not ok_conflict:
            return False, err_conflict, {}

        log(f"Connecting to Kharej server ({kharej_server['ip']})...")
        kh_ssh = SSHManager(
            kharej_server["ip"],
            int(kharej_server.get("port") or 22),
            kharej_server.get("username", "root"),
            kharej_server.get("password"),
            key_path=kharej_server.get("key_path"),
            private_key=kharej_server.get("private_key")
        )
        ok, msg = kh_ssh.connect()
        if not ok:
            return False, f"Failed to connect to Kharej server: {msg}", {}

        # Ensure BackPack on Kharej
        log("Checking BackPack installation on Kharej server...")
        ok, msg = kh_ssh.ensure_backpack_installed()
        if not ok:
            kh_ssh.close()
            return False, f"Failed to install BackPack on Kharej server: {msg}", {}

        nodes = []
        failures = []
        clean_name = pool_name  # already validated + canonicalized above

        for idx, ir_srv in enumerate(iran_servers, start=1):
            node_name = f"{clean_name}_ir{idx}"
            log(f"[{idx}/{len(iran_servers)}] Preparing Iran server: {ir_srv['name']} ({ir_srv['ip']})...")

            ir_ssh = SSHManager(
                ir_srv["ip"],
                int(ir_srv.get("port") or 22),
                ir_srv.get("username", "root"),
                ir_srv.get("password"),
                key_path=ir_srv.get("key_path"),
                private_key=ir_srv.get("private_key")
            )
            ok, msg = ir_ssh.connect()
            if not ok:
                log(f"⚠️ Warning: Connection to Iran server {ir_srv['ip']} failed: {msg} - Skipping.")
                failures.append(f"{ir_srv['ip']}: {msg}")
                continue

            # Ensure BackPack on Iran
            log(f"Checking BackPack installation on Iran server {ir_srv['ip']}...")
            ok_inst, install_error = ir_ssh.ensure_backpack_installed()
            if not ok_inst:
                log(f"⚠️ Failed to install BackPack on Iran server {ir_srv['ip']} - Skipping.")
                failures.append(f"{ir_srv['ip']}: {install_error}")
                ir_ssh.close()
                continue

            # Ensure connection monitor daemon on Iran node
            log(f"Ensuring connection monitor daemon on Iran server {ir_srv['ip']}...")
            ok_mon, msg_mon = ir_ssh.ensure_conn_monitor_installed()
            if ok_mon:
                log(f"✅ Connection monitor active on {ir_srv['ip']}")
            else:
                log(f"⚠️ Connection monitor notice on {ir_srv['ip']}: {msg_mon}")

            # Auto find free port
            log("Auto-detecting available tunnel port on Iran server...")
            free_port = ir_ssh.find_free_port()
            log(f"Allocated tunnel port: {free_port}")

            token = generate_token()

            log(f"Deploying tunnel {node_name} on both servers...")
            ok_tun, err_tun = setup_tunnel_node(
                iran_ssh=ir_ssh,
                kharej_ssh=kh_ssh,
                tunnel_name=node_name,
                transport=transport,
                tunnel_port=free_port,
                client_ports=client_ports,
                token=token
            )

            if ok_tun:
                # Wait 2 seconds and check status
                time.sleep(2)
                _, out_ir, _ = ir_ssh.execute(f"systemctl is-active {shquote(f'backpack-{node_name}.service')}")
                _, out_kh, _ = kh_ssh.execute(f"systemctl is-active {shquote(f'backpack-{node_name}.service')}")
                is_active = (out_ir.strip() == "active" and out_kh.strip() == "active")
                
                nodes.append({
                    "node_name": node_name,
                    "server_name": ir_srv["name"],
                    "ip": ir_srv["ip"],
                    "port": ir_srv.get("port", 22),
                    "username": ir_srv.get("username", "root"),
                    "password": ir_srv.get("password"),
                    "tunnel_port": free_port,
                    "token": token,
                    "status": "active" if is_active else "warning"
                })
                log(f"✅ Node {ir_srv['name']} ({ir_srv['ip']}) connected successfully to load balancer!")
            else:
                log(f"❌ Error creating tunnel for server {ir_srv['ip']}: {err_tun}")
                failures.append(f"{ir_srv['ip']}: {err_tun}")

            ir_ssh.close()

        kh_ssh.close()

        if not nodes:
            return False, "None of the Iran servers could be successfully connected. " + "; ".join(failures), {}

        pool_data = {
            "name": pool_name,
            "transport": transport,
            "client_ports": client_ports,
            "kharej_server": kharej_server,
            "nodes": nodes,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        save_pool(pool_name, pool_data)
        return True, "Load balancer pool created successfully", pool_data

    @staticmethod
    def add_node(pool_name: str, new_iran_server: dict, callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
        """Adds a single Iran server to an existing pool without downtime."""
        def log(msg: str):
            if callback:
                callback(msg)

        pools = get_pools()
        if pool_name not in pools:
            return False, "Load balancer pool not found"

        pool = pools[pool_name]
        if pool.get('engine') == 'spoof' and pool.get('spoof_runtime_version') == 1:
            from core.spoof_transport import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') in ('http', 'https'):
            from core.http_transport import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') in ('geneve', 'geneve_ipsec') or pool.get('transport') in ('geneve', 'geneve_ipsec'):
            from core.geneve import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'vxlan_ipsec' or pool.get('transport') == 'vxlan_ipsec':
            from core.vxlan_ipsec import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'vxlan' or pool.get('transport') == 'vxlan':
            from core.vxlan_adapter import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'gre6' or pool.get('transport') == 'gre6':
            from core.gre6 import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'ip6ip6' or pool.get('transport') == 'ip6ip6':
            from core.ip6ip6 import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'wireguard' or pool.get('transport') == 'wireguard':
            from core.wireguard_adapter import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'slipstream' or pool.get('transport') == 'slipstream':
            from core.slipstream_adapter import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'waterwall':
            from core.waterwall import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'paqet':
            from core.paqet_adapter import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'xray':
            from core.https_tunnel import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('transport') == 'gre':
            from core.gre import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'tun' or pool.get('transport') == 'tun':
            from core.tun_runtime import add
            return add(pool_name, new_iran_server, callback)
        if pool.get('engine') == 'dc6' or pool.get('transport') == 'dc6':
            from core.dc6_runtime import add
            return add(pool_name, new_iran_server, callback)
        kh_srv = pool["kharej_server"]
        transport = pool["transport"]
        client_ports = pool["client_ports"]
        # Pool names created before validation existed may contain characters
        # outside the whitelist. Sanitize defensively for the derived node_name
        # (new pools are strictly validated at creation); never raise here, or
        # legacy pools could never gain new nodes.
        raw_pool = str(pool.get("name", pool_name))
        safe_pool = "".join(c if (c.isalnum() or c in "-_") else "_" for c in raw_pool.strip().replace(" ", "_").lower()) or "pool"
        safe_pool = safe_pool[:64]

        # Check if IP already exists
        for n in pool["nodes"]:
            if n["ip"] == new_iran_server["ip"]:
                return False, "This server IP already exists in the load balancer pool"

        # Check port collision with other pools on this server
        ok_conflict, err_conflict = LoadBalancerManager.check_port_conflicts(client_ports, [new_iran_server["ip"]], exclude_pool_name=pool_name)
        if not ok_conflict:
            return False, err_conflict

        log(f"Connecting to Kharej server ({kh_srv['ip']})...")
        kh_ssh = SSHManager(
            kh_srv["ip"],
            int(kh_srv.get("port") or 22),
            kh_srv.get("username", "root"),
            kh_srv.get("password"),
            key_path=kh_srv.get("key_path"),
            private_key=kh_srv.get("private_key")
        )
        ok, msg = kh_ssh.connect()
        if not ok:
            return False, f"Failed to connect to Kharej server: {msg}"

        log(f"Connecting to new Iran server ({new_iran_server['ip']})...")
        ir_ssh = SSHManager(
            new_iran_server["ip"],
            int(new_iran_server.get("port") or 22),
            new_iran_server.get("username", "root"),
            new_iran_server.get("password"),
            key_path=new_iran_server.get("key_path"),
            private_key=new_iran_server.get("private_key")
        )
        ok, msg = ir_ssh.connect()
        if not ok:
            kh_ssh.close()
            return False, f"Failed to connect to new Iran server: {msg}"

        ir_ssh.ensure_backpack_installed()
        log(f"Ensuring connection monitor daemon on new Iran server {new_iran_server['ip']}...")
        ok_mon, msg_mon = ir_ssh.ensure_conn_monitor_installed()
        if ok_mon:
            log(f"✅ Connection monitor active on {new_iran_server['ip']}")
        else:
            log(f"⚠️ Connection monitor notice on {new_iran_server['ip']}: {msg_mon}")

        free_port = ir_ssh.find_free_port()
        token = generate_token()
        node_name = f"{safe_pool}_ir{len(pool['nodes']) + 1}_{int(time.time()) % 1000}"

        log(f"Deploying tunnel for new node with tunnel port {free_port}...")
        ok_tun, err_tun = setup_tunnel_node(
            iran_ssh=ir_ssh,
            kharej_ssh=kh_ssh,
            tunnel_name=node_name,
            transport=transport,
            tunnel_port=free_port,
            client_ports=client_ports,
            token=token
        )

        ir_ssh.close()
        kh_ssh.close()

        if not ok_tun:
            return False, f"Failed to establish tunnel: {err_tun}"

        pool["nodes"].append({
            "node_name": node_name,
            "server_name": new_iran_server["name"],
            "ip": new_iran_server["ip"],
            "port": new_iran_server.get("port", 22),
            "username": new_iran_server.get("username", "root"),
            "password": new_iran_server.get("password"),
            "tunnel_port": free_port,
            "token": token,
            "status": "active"
        })

        # Preserve progress written by the background worker and fresh telemetry.
        new_node = pool['nodes'][-1]
        def append_node(data):
            data['pools'][pool_name]['nodes'].append(new_node)
        atomic_update(append_node)
        return True, f"Server {new_iran_server['name']} ({new_iran_server['ip']}) added successfully to load balancer!"

    @staticmethod
    def forget_node(pool_name: str, iran_ip: str) -> Tuple[bool, str]:
        """Remove only inventory membership, retaining unverified cleanup details.

        This explicit action makes no SSH or DNS calls and works for every engine.
        Resource reservations are retained because remote resources may still exist.
        """
        removed = [False]
        def forget(data):
            pool = data.get('pools', {}).get(pool_name)
            if not pool:
                return
            node = next((n for n in pool.get('nodes', []) if n.get('ip') == iran_ip), None)
            if node is None:
                return
            data.setdefault('pending_node_cleanup', {})[uuid.uuid4().hex] = {
                'pool': pool_name, 'ip': iran_ip, 'status': 'unverified',
                'recorded_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'node': copy.deepcopy(node),
                'kharej_server': copy.deepcopy(pool.get('kharej_server', {})),
                'engine': pool.get('engine', 'backpack'),
                'transport': pool.get('transport'),
                'client_ports': copy.deepcopy(pool.get('client_ports', [])),
            }
            pool['nodes'] = [n for n in pool['nodes'] if n.get('ip') != iran_ip]
            data.get('node_telemetry', {}).pop(f'{pool_name}:{iran_ip}', None)
            data.get('watchdog_status', {}).get('pool_reports', {}).pop(pool_name, None)
            removed[0] = True
        atomic_update(forget)
        if not removed[0]:
            return False, 'نود در این استخر یافت نشد'
        return True, 'نود از پنل حذف شد؛ پاک‌سازی سرویس‌ها و DNS تأیید نشده است. اطلاعات لازم برای پیگیری روی سرور نگه داشته شد.'

    @staticmethod
    def remove_node(pool_name: str, iran_ip: str, callback: Optional[Callable[[str], None]] = None, force: bool = False) -> Tuple[bool, str]:
        """Removes a single Iran server from a pool."""
        def log(msg: str):
            if callback:
                callback(msg)

        pools = get_pools()
        if pool_name not in pools:
            return False, "Load balancer pool not found"

        pool = pools[pool_name]
        if pool.get('engine') == 'spoof' and pool.get('spoof_runtime_version') == 1:
            from core.spoof_transport import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') in ('http', 'https'):
            from core.http_transport import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') in ('geneve', 'geneve_ipsec') or pool.get('transport') in ('geneve', 'geneve_ipsec'):
            from core.geneve import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'vxlan_ipsec' or pool.get('transport') == 'vxlan_ipsec':
            from core.vxlan_ipsec import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'vxlan' or pool.get('transport') == 'vxlan':
            from core.vxlan_adapter import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'gre6' or pool.get('transport') == 'gre6':
            from core.gre6 import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'ip6ip6' or pool.get('transport') == 'ip6ip6':
            from core.ip6ip6 import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'wireguard' or pool.get('transport') == 'wireguard':
            from core.wireguard_adapter import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'slipstream' or pool.get('transport') == 'slipstream':
            from core.slipstream_adapter import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'waterwall':
            from core.waterwall import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'paqet':
            from core.paqet_adapter import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'xray':
            from core.https_tunnel import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('transport') == 'gre':
            from core.gre import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'tun' or pool.get('transport') == 'tun':
            from core.tun_runtime import remove
            return remove(pool_name, iran_ip, callback)
        if pool.get('engine') == 'dc6' or pool.get('transport') == 'dc6':
            from core.dc6_runtime import remove
            return remove(pool_name, iran_ip, callback)
        target_node = None
        for n in pool["nodes"]:
            if n["ip"] == iran_ip:
                target_node = n
                break

        if not target_node:
            return False, "Server not found in this load balancer pool"

        node_name = target_node["node_name"]
        kh_srv = pool["kharej_server"]

        log("Tearing down tunnel from Kharej server...")
        kh_ssh = SSHManager(
            kh_srv["ip"],
            int(kh_srv.get("port") or 22),
            kh_srv.get("username", "root"),
            kh_srv.get("password"),
            key_path=kh_srv.get("key_path"),
            private_key=kh_srv.get("private_key")
        )
        kh_ok, kh_err = kh_ssh.connect()
        if kh_ok:
            stop_and_remove_tunnel(kh_ssh, node_name)
            kh_ssh.close()
        elif not force:
            return False, f"Failed to connect to Kharej server ({kh_err}); cleanup aborted to avoid orphaned tunnel. Use force=True to remove anyway."

        log("Tearing down tunnel from Iran server...")
        ir_ssh = SSHManager(
            target_node["ip"],
            int(target_node.get("port") or 22),
            target_node.get("username", "root"),
            target_node.get("password"),
            key_path=target_node.get("key_path"),
            private_key=target_node.get("private_key")
        )
        ir_ok, ir_err = ir_ssh.connect()
        if ir_ok:
            stop_and_remove_tunnel(ir_ssh, node_name)
            ir_ssh.close()
        elif not force:
            return False, f"Failed to connect to Iran server ({ir_err}); cleanup aborted to avoid orphaned tunnel. Use force=True to remove anyway."

        def remove_member(data):
            current = data['pools'][pool_name]
            current['nodes'] = [n for n in current['nodes'] if n['ip'] != iran_ip]
        atomic_update(remove_member)
        return True, f"Server {iran_ip} removed successfully from load balancer"

    @staticmethod
    def delete_entire_pool(pool_name: str, callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
        """Tears down all tunnels in a pool and deletes it."""
        pools = get_pools()
        if pool_name not in pools:
            return False, "Load balancer pool not found"

        pool = pools[pool_name]
        if pool.get('engine') == 'spoof' and pool.get('spoof_runtime_version') == 1:
            from core.spoof_transport import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') in ('http', 'https'):
            from core.http_transport import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') in ('geneve', 'geneve_ipsec') or pool.get('transport') in ('geneve', 'geneve_ipsec'):
            from core.geneve import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') == 'vxlan_ipsec' or pool.get('transport') == 'vxlan_ipsec':
            from core.vxlan_ipsec import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') == 'vxlan' or pool.get('transport') == 'vxlan':
            from core.vxlan_adapter import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') == 'gre6' or pool.get('transport') == 'gre6':
            from core.gre6 import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') == 'ip6ip6' or pool.get('transport') == 'ip6ip6':
            from core.ip6ip6 import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') == 'wireguard' or pool.get('transport') == 'wireguard':
            from core.wireguard_adapter import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') == 'slipstream' or pool.get('transport') == 'slipstream':
            from core.slipstream_adapter import delete_pool
            return delete_pool(pool_name, callback)
        if pool.get('engine') == 'paqet':
            from core.paqet_adapter import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') == 'waterwall':
            from core.waterwall import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') == 'xray':
            from core.https_tunnel import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('transport') == 'gre':
            from core.gre import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') == 'tun' or pool.get('transport') == 'tun':
            from core.tun_runtime import remove_pool
            return remove_pool(pool_name, callback)
        if pool.get('engine') == 'dc6' or pool.get('transport') == 'dc6':
            from core.dc6_runtime import remove_pool
            return remove_pool(pool_name, callback)
        kh_srv = pool["kharej_server"]
        kh_ssh = SSHManager(
            kh_srv["ip"],
            int(kh_srv.get("port") or 22),
            kh_srv.get("username", "root"),
            kh_srv.get("password"),
            key_path=kh_srv.get("key_path"),
            private_key=kh_srv.get("private_key")
        )
        failures = []
        try:
            kh_connected = kh_ssh.connect()[0]
            if not kh_connected:
                return False, "اتصال به مقصد خارج برقرار نشد؛ استخر حذف نشد"
            for node in pool["nodes"]:
                node_name = node["node_name"]
                if callback:
                    callback("Removing tunnel " + node_name)
                if not stop_and_remove_tunnel(kh_ssh, node_name):
                    failures.append(kh_srv["ip"])
                ir_ssh = SSHManager(
                    node["ip"],
                    int(node.get("port") or 22),
                    node.get("username", "root"),
                    node.get("password"),
                    key_path=node.get("key_path"),
                    private_key=node.get("private_key")
                )
                try:
                    if not ir_ssh.connect()[0] or not stop_and_remove_tunnel(ir_ssh, node_name):
                        failures.append(node["ip"])
                finally:
                    ir_ssh.close()
        finally:
            kh_ssh.close()
        if failures:
            return False, "پاک‌سازی کامل نشد؛ استخر برای تلاش مجدد حفظ شد: " + ", ".join(sorted(set(failures)))
        storage_delete_pool(pool_name)
        return True, "All tunnels and services in this load balancer have been stopped and deleted"

    @staticmethod
    def add_client_ports(pool_name: str, new_ports: List[str], callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
        """Adds one or more forwarded client ports to all nodes in the pool."""
        def log(msg: str):
            if callback:
                callback(msg)

        pools = get_pools()
        if pool_name not in pools:
            return False, "Load balancer pool not found"

        pool = pools[pool_name]
        engine = pool.get('engine') or pool.get('transport')
        if engine == 'spoof' and pool.get('spoof_runtime_version') == 1:
            from core.spoof_transport import change_ports
            try:ports=[*pool.get('client_ports',[]),*validate_ports(new_ports)]
            except ValueError as error:return False,str(error)
            return change_ports(pool_name,ports)
        if engine in ('http', 'https'):
            from core.http_transport import change_ports
            try:
                ports = [*pool.get('client_ports', []), *validate_ports(new_ports)]
            except ValueError as error:
                return False, str(error)
            return change_ports(pool_name, ports)
        if engine == 'slipstream':
            from core.slipstream_update import change
            try:
                ports = [*pool.get('client_ports', []), *validate_ports(new_ports)]
            except ValueError as error:
                return False, str(error)
            return change(pool_name, {'client_ports': ports})
        if engine in ('wireguard', 'vxlan', 'gre6', 'ip6ip6', 'tun', 'dc6'):
            from core.kernel_relay_ports import change_ports
            try:
                ports = [*pool.get('client_ports', []), *validate_ports(new_ports)]
            except ValueError as error:
                return False, str(error)
            return change_ports(pool_name, ports)
        if engine == 'vxlan_ipsec' or pool.get('transport') == 'vxlan_ipsec':
            from core.vxlan_ipsec import change_ports
            try:
                ports = [*pool.get('client_ports', []), *validate_ports(new_ports)]
            except ValueError as error:
                return False, str(error)
            if not ports:
                return False, 'Cannot remove the only forwarded port'
            if set(map(str, ports)) == set(map(str, pool.get('client_ports', []))):
                return False, 'No port change was requested'
            return change_ports(pool_name, ports)
        if engine in ('geneve', 'geneve_ipsec') or pool.get('transport') in ('geneve', 'geneve_ipsec'):
            from core.geneve import change_ports
            try:
                ports = [*pool.get('client_ports', []), *validate_ports(new_ports)]
            except ValueError as error:
                return False, str(error)
            if not ports:
                return False, 'Cannot remove the only forwarded port'
            if set(map(str, ports)) == set(map(str, pool.get('client_ports', []))):
                return False, 'No port change was requested'
            return change_ports(pool_name, ports)
        if pool.get('transport') == 'gre' or pool.get('engine') in ('xray', 'waterwall', 'paqet'):
            if pool.get('engine') == 'paqet':
                from core.paqet_adapter import change_ports
            elif pool.get('engine') == 'waterwall':
                from core.waterwall import change_ports
            elif pool.get('engine') == 'xray':
                from core.https_tunnel import change_ports
            else:
                from core.gre import change_ports
            try: ports = [*pool.get('client_ports', []), *validate_ports(new_ports)]
            except ValueError as error: return False, str(error)
            if not ports: return False, 'Cannot remove the only forwarded port'
            if set(map(str,ports)) == set(map(str,pool.get('client_ports',[]))): return False, 'No port change was requested'
            return change_ports(pool_name, ports)

        current_ports = pool.get("client_ports", [])

        # Security: reject non-numeric / out-of-range ports before they reach shell.
        try:
            new_ports = validate_ports(new_ports)
        except ValueError as e:
            return False, str(e)

        added = []
        for p_clean in new_ports:
            if p_clean not in current_ports:
                current_ports.append(p_clean)
                added.append(p_clean)

        if not added:
            return False, "All specified ports already exist in the pool"

        # Check port collision with other pools on the nodes in this pool
        node_ips = [n["ip"] for n in pool.get("nodes", [])]
        ok_conflict, err_conflict = LoadBalancerManager.check_port_conflicts(added, node_ips, exclude_pool_name=pool_name)
        if not ok_conflict:
            return False, err_conflict

        pool["client_ports"] = current_ports
        transport = pool.get("transport", "pck")

        log(f"Applying updated port list ({', '.join(str(p) for p in current_ports)}) to all nodes in pool...")
        nodes_updated = 0
        for node in pool.get("nodes", []):
            node_name = node["node_name"]
            ip = node["ip"]
            log(f"Updating configuration on {node['server_name']} ({ip})...")
            ir_ssh = SSHManager(
                ip,
                int(node.get("port") or 22),
                node.get("username", "root"),
                node.get("password"),
                key_path=node.get("key_path"),
                private_key=node.get("private_key")
            )
            ok, msg = ir_ssh.connect()
            if not ok:
                log(f"  ❌ Warning: Could not connect to {ip}: {msg}")
                continue
            
            cfg_content = build_iran_config(
                tunnel_port=node["tunnel_port"],
                transport=node.get("transport", transport),
                token=node["token"],
                client_ports=current_ports
            )
            written = ir_ssh.write_file(f"/etc/backpack/{node_name}.toml", cfg_content)
            if not written:
                log(f"  ❌ Error: Failed to write config to /etc/backpack/{node_name}.toml on {ip}")
                ir_ssh.close()
                continue

            # Configure and verify firewall
            fw_warnings = []
            for p in added:
                c1, out1, err1 = ir_ssh.execute(f"iptables -I INPUT -p tcp --dport {shquote(p)} -j ACCEPT")
                if c1 != 0:
                    fw_warnings.append(f"iptables port {p}: {err1.strip() or out1.strip()}")
                c2, out2, err2 = ir_ssh.execute(f"which ufw >/dev/null 2>&1 && ufw allow {shquote(p)}/tcp")
                if c2 != 0 and "not found" not in err2.lower():
                    fw_warnings.append(f"ufw port {p}: {err2.strip() or out2.strip()}")

            if fw_warnings:
                log(f"  ⚠️ Firewall warnings on {ip}: {'; '.join(fw_warnings)}")

            # Restart BackPack and verify running state
            c_rst, out_rst, err_rst = ir_ssh.execute(f"systemctl restart {shquote(f'backpack-{node_name}.service')}")
            if c_rst != 0:
                log(f"  ❌ Failed to restart backpack-{node_name}.service on {ip}: {err_rst.strip()}")
                ir_ssh.close()
                continue

            time.sleep(1)
            _, out_act, _ = ir_ssh.execute(f"systemctl is-active {shquote(f'backpack-{node_name}.service')}")
            if out_act.strip() != "active":
                log(f"  ❌ backpack-{node_name}.service on {ip} is not active! Status: {out_act.strip()}")
                ir_ssh.close()
                continue

            nodes_updated += 1
            ir_ssh.close()
            log(f"  ✅ Node {ip} updated, verified active, and firewall opened for port(s) {', '.join(added)}!")

        save_pool(pool_name, pool)
        if nodes_updated == 0:
            return False, f"Failed to update port configuration across load balancer nodes."
        return True, f"Port(s) {', '.join(added)} added and verified active on {nodes_updated}/{len(pool.get('nodes', []))} nodes"

    @staticmethod
    def remove_client_port(pool_name: str, port_to_remove: str, callback: Optional[Callable[[str], None]] = None) -> Tuple[bool, str]:
        """Removes a forwarded client port from all nodes in the pool."""
        def log(msg: str):
            if callback:
                callback(msg)

        pools = get_pools()
        if pool_name not in pools:
            return False, "Load balancer pool not found"

        pool = pools[pool_name]
        engine = pool.get('engine') or pool.get('transport')
        if engine == 'spoof' and pool.get('spoof_runtime_version') == 1:
            from core.spoof_transport import change_ports
            try:ports=[p for p in pool.get('client_ports',[]) if str(p)!=validate_port(port_to_remove)]
            except ValueError as error:return False,str(error)
            return change_ports(pool_name,ports)
        if engine in ('http', 'https'):
            from core.http_transport import change_ports
            try:
                ports = [p for p in pool.get('client_ports', []) if str(p) != validate_port(port_to_remove)]
            except ValueError as error:
                return False, str(error)
            return change_ports(pool_name, ports)
        if engine == 'slipstream':
            from core.slipstream_update import change
            try:
                ports = [port for port in pool.get('client_ports', []) if str(port) != validate_port(port_to_remove)]
            except ValueError as error:
                return False, str(error)
            return change(pool_name, {'client_ports': ports})
        if engine in ('wireguard', 'vxlan', 'gre6', 'ip6ip6', 'tun', 'dc6'):
            from core.kernel_relay_ports import change_ports
            try:
                ports = [p for p in pool.get('client_ports', []) if str(p) != validate_port(port_to_remove)]
            except ValueError as error:
                return False, str(error)
            return change_ports(pool_name, ports)
        if engine == 'vxlan_ipsec' or pool.get('transport') == 'vxlan_ipsec':
            from core.vxlan_ipsec import change_ports
            try:
                ports = [p for p in pool.get('client_ports', []) if str(p) != validate_port(port_to_remove)]
            except ValueError as error:
                return False, str(error)
            if not ports:
                return False, 'Cannot remove the only forwarded port'
            if set(map(str, ports)) == set(map(str, pool.get('client_ports', []))):
                return False, 'No port change was requested'
            return change_ports(pool_name, ports)
        if engine in ('geneve', 'geneve_ipsec') or pool.get('transport') in ('geneve', 'geneve_ipsec'):
            from core.geneve import change_ports
            try:
                ports = [p for p in pool.get('client_ports', []) if str(p) != validate_port(port_to_remove)]
            except ValueError as error:
                return False, str(error)
            if not ports:
                return False, 'Cannot remove the only forwarded port'
            if set(map(str, ports)) == set(map(str, pool.get('client_ports', []))):
                return False, 'No port change was requested'
            return change_ports(pool_name, ports)
        if pool.get('transport') == 'gre' or pool.get('engine') in ('xray', 'waterwall', 'paqet'):
            if pool.get('engine') == 'paqet':
                from core.paqet_adapter import change_ports
            elif pool.get('engine') == 'waterwall':
                from core.waterwall import change_ports
            elif pool.get('engine') == 'xray':
                from core.https_tunnel import change_ports
            else:
                from core.gre import change_ports
            try: ports = [p for p in pool.get('client_ports', []) if str(p) != validate_port(port_to_remove)]
            except ValueError as error: return False, str(error)
            if not ports: return False, 'Cannot remove the only forwarded port'
            if set(map(str,ports)) == set(map(str,pool.get('client_ports',[]))): return False, 'No port change was requested'
            return change_ports(pool_name, ports)

        current_ports = pool.get("client_ports", [])
        try:
            port_to_remove = validate_port(port_to_remove)
        except ValueError as e:
            return False, str(e)

        if int(port_to_remove) not in [int(p) for p in current_ports]:
            return False, f"Port {port_to_remove} is not configured in this pool"

        if len(current_ports) <= 1:
            return False, "Cannot remove the only remaining forwarded port! A load balancer must have at least one active port."

        current_ports = [p for p in current_ports if int(p) != int(port_to_remove)]
        pool["client_ports"] = current_ports
        transport = pool.get("transport", "pck")

        log(f"Applying updated port list ({', '.join(str(p) for p in current_ports)}) to all nodes in pool...")
        nodes_updated = 0
        for node in pool.get("nodes", []):
            node_name = node["node_name"]
            ip = node["ip"]
            ir_ssh = SSHManager(
                ip,
                int(node.get("port") or 22),
                node.get("username", "root"),
                node.get("password"),
                key_path=node.get("key_path"),
                private_key=node.get("private_key")
            )
            ok, msg = ir_ssh.connect()
            if not ok:
                log(f"  ❌ Warning: Could not connect to {ip}: {msg}")
                continue
            
            cfg_content = build_iran_config(
                tunnel_port=node["tunnel_port"],
                transport=node.get("transport", transport),
                token=node["token"],
                client_ports=current_ports
            )
            written = ir_ssh.write_file(f"/etc/backpack/{node_name}.toml", cfg_content)
            if not written:
                log(f"  ❌ Error: Failed to write config on {ip}")
                ir_ssh.close()
                continue

            ir_ssh.execute(f"iptables -D INPUT -p tcp --dport {shquote(port_to_remove)} -j ACCEPT 2>/dev/null || true")
            ir_ssh.execute(f"which ufw >/dev/null 2>&1 && ufw delete allow {shquote(port_to_remove)}/tcp 2>/dev/null || true")

            c_rst, out_rst, err_rst = ir_ssh.execute(f"systemctl restart {shquote(f'backpack-{node_name}.service')}")
            if c_rst != 0:
                log(f"  ❌ Failed to restart backpack-{node_name}.service on {ip}: {err_rst.strip()}")
                ir_ssh.close()
                continue

            time.sleep(1)
            _, out_act, _ = ir_ssh.execute(f"systemctl is-active {shquote(f'backpack-{node_name}.service')}")
            if out_act.strip() != "active":
                log(f"  ❌ backpack-{node_name}.service on {ip} is not active! Status: {out_act.strip()}")
                ir_ssh.close()
                continue

            nodes_updated += 1
            ir_ssh.close()
            log(f"  ✅ Node {ip} updated, verified active, and firewall rule removed for port {port_to_remove}!")

        save_pool(pool_name, pool)
        return True, f"Port {port_to_remove} removed successfully from all load balancer nodes"
