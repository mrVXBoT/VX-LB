"""Central resource allocator and reservation manager for LD-BP multi-tunnel platform.

Unified transactional reservation and conflict detection across all
engines for:
- Host TCP/UDP ports
- Private IP subnets (IPv4 /30, IPv6 /126)
- Virtual Network Identifiers (VNI) for VXLAN & Geneve
- Network interface names
- Routing table identifiers
"""
import ipaddress
import re
from typing import Dict, List, Optional, Tuple, Set, Any
from core.storage import atomic_update, load_data

IPV4_POOL_START = ipaddress.IPv4Network("10.100.0.0/16")
IPV6_POOL_START = ipaddress.IPv6Network("fd00:1db9::/48")

def _allocate_subnet(pool, existing_subnets, prefix):
    size = 1 << (pool.max_prefixlen - prefix)
    candidate = int(pool.network_address)
    networks = sorted((ipaddress.ip_network(value, strict=False) for value in existing_subnets if value), key=lambda network: int(network.network_address))
    for network in networks:
        if network.version != pool.version:
            raise ValueError('Private subnet address family mismatch')
        low, high = int(network.network_address), int(network.broadcast_address)
        if high < candidate:
            continue
        if low > candidate + size - 1:
            break
        candidate = ((high + 1 + size - 1) // size) * size
    if candidate + size - 1 > int(pool.broadcast_address):
        raise RuntimeError(f'IPv{pool.version} private address pool exhausted')
    return str(ipaddress.ip_network((ipaddress.ip_address(candidate), prefix)))


def check_server_routes_collision(candidate_subnet: str, server_routes: List[str]) -> Tuple[bool, Optional[str]]:
    """Checks if a candidate private subnet overlaps with any existing host routes or LANs.
    
    Returns (True, error_message) on collision, or (False, None) if clean.
    """
    try:
        cand_net = ipaddress.ip_network(candidate_subnet, strict=False)
    except Exception as e:
        return True, f"ساب‌نت نامعتبر: {e}"

    for r in server_routes:
        if not r or not str(r).strip():
            continue
        line = str(r).strip()
        tokens = line.split()
        if not tokens:
            continue
        dest = tokens[0]
        if dest == "default":
            continue
        try:
            route_net = ipaddress.ip_network(dest, strict=False)
            if cand_net.version == route_net.version and cand_net.overlaps(route_net):
                return True, f"تداخل روت: ساب‌نت انتخابی {candidate_subnet} با روت موجود {dest} در سرور هم‌پوشانی دارد."
        except ValueError:
            continue
    return False, None


def allocate_private_ipv4_subnet(existing_subnets: List[str], server_routes: Optional[List[str]] = None) -> str:
    combined = list(existing_subnets)
    if server_routes:
        for r in server_routes:
            tokens = str(r).strip().split()
            if tokens and tokens[0] != "default":
                try:
                    net = ipaddress.ip_network(tokens[0], strict=False)
                    if net.version == 4:
                        combined.append(str(net))
                except ValueError:
                    pass
    return _allocate_subnet(IPV4_POOL_START, combined, 30)


def allocate_private_ipv6_subnet(existing_subnets: List[str], server_routes: Optional[List[str]] = None) -> str:
    combined = list(existing_subnets)
    if server_routes:
        for r in server_routes:
            tokens = str(r).strip().split()
            if tokens and tokens[0] != "default":
                try:
                    net = ipaddress.ip_network(tokens[0], strict=False)
                    if net.version == 6:
                        combined.append(str(net))
                except ValueError:
                    pass
    return _allocate_subnet(IPV6_POOL_START, combined, 126)


def allocate_vni(existing_vnis: List[int], start_vni: int = 1000) -> int:
    """Finds next available Virtual Network Identifier (VNI) for VXLAN or Geneve."""
    used = set(existing_vnis)
    candidate = start_vni
    while candidate in used:
        candidate += 1
        if candidate > 16777215:
            raise RuntimeError("VNI space exhausted (max 24-bit 16777215 reached)")
    return candidate

def allocate_route_table_id(existing_table_ids: List[int], start_table: int = 100) -> int:
    """Finds next available routing table ID."""
    used = set(existing_table_ids)
    candidate = start_table
    while candidate in used:
        candidate += 1
        if candidate > 250:
            raise RuntimeError("Routing table space exhausted")
    return candidate

class ResourceReservationManager:
    """Manages transactional allocation and release of system network resources."""

    @staticmethod
    def get_all_reserved_resources() -> dict:
        data = load_data()
        return data.get("resource_reservations", {})

    @staticmethod
    def reserve_pool_resources(
        pool_name: str,
        engine_id: str,
        host_ports: Dict[str, List[int]],  # host_ip -> list of ports
        interface_names: List[str],
        needs_ipv4_subnet: bool = False,
        needs_ipv6_subnet: bool = False,
        needs_vni: bool = False,
        needs_route_table: bool = False,
        _data: Optional[dict] = None,
        server_routes: Optional[List[str]] = None,
    ) -> dict:
        """Atomically validates conflicts and reserves all required resources for a pool.
        
        Raises RuntimeError on any collision.
        """
        allocated_record = {}

        def _update(data: dict):
            nonlocal allocated_record
            reservations = data.setdefault("resource_reservations", {})
            
            normalized_ports = {str(ipaddress.ip_address(host)): sorted(set(int(port) for port in ports)) for host, ports in host_ports.items()}
            if any(not 1 <= port <= 65535 for ports in normalized_ports.values() for port in ports):
                raise ValueError('Reserved port must be between 1 and 65535')
            if any(not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', interface) for interface in interface_names):
                raise ValueError('Invalid reserved interface name')
            previous = reservations.get(pool_name)
            if previous is not None:
                if previous.get('engine_id') != engine_id or previous.get('host_ports') != normalized_ports or previous.get('interfaces') != list(interface_names) or any(bool(previous.get(field)) != needed for field, needed in (('ipv4_subnet', needs_ipv4_subnet), ('ipv6_subnet', needs_ipv6_subnet), ('vni', needs_vni), ('route_table', needs_route_table))):
                    raise RuntimeError('Existing reservation must be explicitly released before changing its resources')
                allocated_record = dict(previous)
                return

            # Check for port collisions
            for host_ip, ports in host_ports.items():
                for p in ports:
                    p_int = int(p)
                    for other_pool, res in reservations.items():
                        if other_pool == pool_name:
                            continue
                        other_ports = res.get("host_ports", {}).get(host_ip, [])
                        if p_int in other_ports:
                            raise RuntimeError(f"Port collision: Port {p_int} on host {host_ip} already reserved by pool '{other_pool}'")

            # Check interface name collisions
            for iface in interface_names:
                for other_pool, res in reservations.items():
                    if other_pool == pool_name:
                        continue
                    if iface in res.get("interfaces", []):
                        raise RuntimeError(f"Interface collision: Interface '{iface}' already reserved by pool '{other_pool}'")

            # Allocate IP subnets
            existing_v4 = [res.get("ipv4_subnet") for res in reservations.values() if res.get("ipv4_subnet")]
            ipv4_subnet = allocate_private_ipv4_subnet(existing_v4, server_routes) if needs_ipv4_subnet else None

            existing_v6 = [res.get("ipv6_subnet") for res in reservations.values() if res.get("ipv6_subnet")]
            ipv6_subnet = allocate_private_ipv6_subnet(existing_v6, server_routes) if needs_ipv6_subnet else None

            # Allocate VNI
            existing_vnis = [res.get("vni") for res in reservations.values() if res.get("vni") is not None]
            vni = allocate_vni(existing_vnis) if needs_vni else None

            # Allocate Route Table
            existing_tables = [res.get("route_table") for res in reservations.values() if res.get("route_table") is not None]
            route_table = allocate_route_table_id(existing_tables) if needs_route_table else None

            allocated_record = {
                "pool_name": pool_name,
                "engine_id": engine_id,
                "host_ports": normalized_ports,
                "interfaces": list(interface_names),
                "ipv4_subnet": ipv4_subnet,
                "ipv6_subnet": ipv6_subnet,
                "vni": vni,
                "route_table": route_table,
            }
            reservations[pool_name] = allocated_record

        if _data is None:
            atomic_update(_update)
        else:
            _update(_data)
        return allocated_record

    @staticmethod
    def release_pool_resources(pool_name: str) -> bool:
        """Atomically releases all resources reserved for a pool."""
        released = False

        def _update(data: dict):
            nonlocal released
            reservations = data.setdefault("resource_reservations", {})
            if pool_name in reservations:
                del reservations[pool_name]
                released = True

        atomic_update(_update)
        return released
