"""Shared admission, readiness and reconstruction rules for pool workflows."""
import copy
import ipaddress
from functools import wraps

from core.validation import validate_pool_name, validate_ports, validate_port, validate_transport


def serialized_creation(function):
    @wraps(function)
    def run(*args, **kwargs):
        from core.transport_change import mutation_lock
        with mutation_lock():
            return function(*args, **kwargs)
    return run


def validate_engine_target(transport, engine):
    from core.transport_change import get_engine_for_transport
    aliases = {'gre_ipv4': 'gre', 'geneve_ipsec': 'geneve'}
    expected = get_engine_for_transport(transport)
    if aliases.get(engine, engine) != expected:
        raise ValueError(f'Engine {engine!r} does not match transport {transport!r}')


def validate_options(transport, options):
    """Validate supplied options before any remote service can be removed."""
    from core.tunnel import SUPPORTED_TRANSPORTS
    validate_transport(transport, SUPPORTED_TRANSPORTS)
    from core.spoof_adapter import SPOOF_TRANSPORTS
    from core.nfqws2_profiles import MODES
    if transport in SPOOF_TRANSPORTS and transport not in MODES:
        raise ValueError('This packet profile is unavailable in this release')
    for key in ('is_production', 'allow_experimental', 'enable_psk'):
        if key in options and not isinstance(options[key], bool):
            raise ValueError(f'{key} must be a boolean')
    camouflage = options.get('camouflage')
    if camouflage is not None and not isinstance(camouflage, dict):
        raise ValueError('camouflage must be an object')
    camouflage = camouflage or {}
    choices = {
        'waterwall': ('mode', ('trojan', 'reality', 'reverse', 'halfduplex', 'bgp4')),
        'gost': ('profile', ('shadowsocks-tcp', 'shadowsocks-udp', 'shadowsocks-tls', 'shadowsocks-ws',
                             'obfs4', 'obfs4-tls', 'grpc', 'grpc-tls', 'ssh', 'kcp-obfs4',
                             'web-tunnel', 'gaming-socks5-kcp', 'quic-socks5')),
        'frp': ('mode', ('tcp', 'udp', 'dual')),
        'hedioum': ('mode', ('socks', 'tun', 'gateway')),
        'rathole': ('transport', ('tcp', 'tls', 'noise', 'websocket')),
    }
    if transport in choices:
        key, allowed = choices[transport]
        if key in camouflage and camouflage[key] not in allowed:
            raise ValueError(f'Invalid {transport} {key}')
    for key in ('port', 'socks_port'):
        if camouflage.get(key) is not None:
            validate_port(camouflage[key])
    if transport == 'gost' and 'password' in camouflage:
        if not isinstance(camouflage['password'], str) or len(camouflage['password']) < 8:
            raise ValueError('GOST password must contain at least 8 characters')
    if transport in {'frp', 'rathole'} and 'token' in camouflage:
        if not isinstance(camouflage['token'], str) or len(camouflage['token']) < 8:
            raise ValueError('Tunnel token must contain at least 8 characters')
    if transport == 'rathole' and camouflage.get('transport') == 'tls':
        if not camouflage.get('pkcs12') or not camouflage.get('pkcs12_password'):
            raise ValueError('Rathole TLS requires a PKCS#12 path and password')
    if transport == 'candy-spoof':
        if 'client_spoofed_ip' in camouflage and camouflage['client_spoofed_ip'] is not None:
            ipaddress.IPv4Address(str(camouflage['client_spoofed_ip']))
        if 'server_spoofed_ip' in camouflage and camouflage['server_spoofed_ip'] is not None:
            ipaddress.IPv4Address(str(camouflage['server_spoofed_ip']))
        for key in ('data_port', 'socks5_port'):
            if key in camouflage and camouflage[key] is not None:
                validate_port(camouflage[key])
        if 'icmp_id' in camouflage and camouflage['icmp_id'] is not None:
            if not 0 <= int(camouflage['icmp_id']) <= 65535:
                raise ValueError('ICMP identifier must be a 16-bit value (0-65535)')
        if 'pre_shared_key' in camouflage and isinstance(camouflage['pre_shared_key'], str):
            if len(camouflage['pre_shared_key']) < 16:
                raise ValueError('Candy-Spoof pre-shared key must contain at least 16 characters')
    if transport == 'parsaksh':
        for key in ('data_port', 'recv_port', 'spoof_port'):
            if key in camouflage and camouflage[key] is not None:
                validate_port(camouflage[key])
        if 'transport' in camouflage and camouflage['transport'] is not None:
            if str(camouflage['transport']) not in ('udp', 'icmp', 'icmpv6', 'tcp'):
                raise ValueError('Invalid ParsaKSH transport')
        for key in ('spoof_ip', 'server_spoof_ip'):
            if key in camouflage and camouflage[key] is not None:
                ipaddress.IPv4Address(str(camouflage[key]))
        if 'forward_target' in camouflage and camouflage['forward_target']:
            if ':' not in str(camouflage['forward_target']):
                raise ValueError('forward_target must be host:port')
    if transport == 'wattunnel':
        if 'reverse' in camouflage and not isinstance(camouflage['reverse'], bool):
            raise ValueError('WatTunnel reverse must be a boolean')
        from core.wattunnel import normalize_settings
        probe = dict(camouflage)
        probe.setdefault('profile', 'tcp')
        probe.setdefault('key', '0' * 16)
        normalize_settings(probe)
    if transport == 'waterwall' and camouflage.get('tls'):
        if not camouflage.get('certificate') or not camouflage.get('key'):
            raise ValueError('WaterWall TLS requires certificate and key paths')
    for key in ('mtu', 'gre_mtu', 'gre6_mtu', 'ip6ip6_mtu', 'geneve_mtu', 'tun_mtu',
                'dc6_mtu', 'vxlan_mtu', 'vxsec_mtu'):
        if key in options:
            value = options[key]
            if isinstance(value, bool) or not str(value).isdigit() or not 576 <= int(value) <= 9000:
                raise ValueError(f'Invalid {key}: use an integer from 576 to 9000')
    for key in ('tunnel_port', 'wireguard_port', 'dst_port', 'dns_port'):
        if options.get(key) is not None:
            validate_port(options[key])
    if options.get('vni') is not None:
        if not str(options['vni']).isdigit() or not 1 <= int(options['vni']) <= 16777215:
            raise ValueError('Invalid VNI')
    if transport == 'dc6':
        carrier = options.get('carrier') or options.get('carrier_type')
        if carrier and carrier not in {'sit', 'ip6gre', 'ip6ip6'}:
            raise ValueError('Invalid DC6 carrier')


def normalize_creation(arguments):
    if not isinstance(arguments, dict):
        raise ValueError('Pool creation arguments must be an object')
    result = copy.deepcopy(arguments)
    if not isinstance(result.get('pool_name'), str):
        raise ValueError('Pool name must be a string')
    result['pool_name'] = validate_pool_name(result.get('pool_name', ''))
    result['transport'] = str(result.get('transport', 'pck')).strip()
    result['client_ports'] = validate_ports(result.get('client_ports'))
    target = result.get('kharej_server')
    servers = result.get('iran_servers')
    if not isinstance(target, dict) or not isinstance(target.get('ip'), str) or not target['ip'].strip():
        raise ValueError('A destination server is required')
    if not isinstance(servers, list) or not servers:
        raise ValueError('At least one Iran server is required')
    seen = set()
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get('ip'), str) or not server['ip'].strip():
            raise ValueError('Invalid Iran server')
        if server['ip'] in seen or server['ip'] == target['ip']:
            raise ValueError('Tunnel endpoints must be distinct and Iran servers must be unique')
        seen.add(server['ip'])
    validate_options(result['transport'], result)
    return result


def operation_options(body, transport):
    """Use the same option names/types for the create and migration APIs."""
    keys = ('engine', 'camouflage', 'mtu', 'gre_mtu', 'gre6_mtu', 'ip6ip6_mtu', 'geneve_mtu',
            'tun_mtu', 'dc6_mtu', 'carrier', 'carrier_type', 'vxlan_mtu', 'vxlan_method',
            'vni', 'dst_port', 'vxsec_mtu', 'bridge_name', 'underlay_dev', 'wireguard_mtu',
            'wireguard_port', 'tunnel_port', 'enable_psk', 'ipv4_subnet', 'domain', 'resolvers',
            'dns_port', 'rate_limit', 'is_production', 'allow_experimental', 'fake_sni',
            'auto_ttl_delta', 'spoof_ips', 'peer_spoof_ip', 'dns_resolvers', 'send_domains',
            'fake_send_ip', 'fake_send_port', 'info_encryption_pass', 'knock_key', 'mode',
            'data_port', 'icmp_id', 'pre_shared_key', 'tunnel_count', 'initial_cwnd',
            'interface', 'client_spoofed_ip', 'server_spoofed_ip', 'spoofed_ip_pool',
            'recv_port', 'spoof_port', 'forward_target')
    result = {key: copy.deepcopy(body[key]) for key in keys if key in body}
    for source, target in (('server_name', 'server_name'), ('port', 'port')):
        if source in body:
            if 'camouflage' in result and not isinstance(result['camouflage'], dict):
                raise ValueError('camouflage must be an object')
            result.setdefault('camouflage', {})[target] = body[source]
    validate_options(transport, result)
    return result


def pool_ready(pool, servers):
    """Require all requested members, rejecting explicit failed/unready nodes."""
    expected = {server['ip'] for server in servers}
    nodes = pool.get('nodes', []) if isinstance(pool, dict) else []
    ready_states = {'', 'HEALTHY', 'ACTIVE', 'VERIFIED', 'UP', 'OK'}
    ready = [node.get('ip') for node in nodes if not node.get('provisioning')
             and str(node.get('status', '')).upper() in ready_states]
    return bool(expected) and set(ready) == expected and len(ready) == len(expected) == len(nodes)


def creation_options(pool):
    """Reconstruct the original engine's options for a verified rollback."""
    fields = ('camouflage', 'gre_mtu', 'gre6_mtu', 'ip6ip6_mtu', 'geneve_mtu', 'tun_mtu',
              'dc6_mtu', 'carrier', 'carrier_type', 'vxlan_mtu', 'vxlan_method', 'vni',
              'dst_port', 'vxsec_mtu', 'bridge_name', 'underlay_dev', 'wireguard_mtu',
              'wireguard_port', 'tunnel_port', 'enable_psk', 'ipv4_subnet', 'domain',
              'resolvers', 'dns_port', 'rate_limit', 'mtu', 'is_production', 'allow_experimental')
    result = {key: copy.deepcopy(pool[key]) for key in fields if key in pool}
    if 'vxsec_dst_port' in pool:
        result['dst_port'] = pool['vxsec_dst_port']
    if pool.get('fake_sni'):
        result['fake_sni'] = copy.deepcopy(pool['fake_sni'])
    if pool.get('transport') == 'hop-ttl-injection' and pool.get('ttl_delta') is not None:
        result['auto_ttl_delta'] = copy.deepcopy(pool['ttl_delta'])
    return result


def preserve_settings(pool, original):
    for key in ('name', 'created_at', 'client_ports', 'kharej_server', 'subdomain', 'dns_routing',
                'dns_policy', 'cloudflare', 'standby_ip', 'rotation', 'dns_schedule'):
        if key in original:
            pool[key] = copy.deepcopy(original[key])


def public_change_job(job, inventory=None):
    """Runtime arguments/backups can contain credentials; never publish them."""
    if not job:
        return job
    result = {key: copy.deepcopy(job[key]) for key in (
        'id', 'status', 'from', 'to', 'from_engine', 'to_engine', 'completed', 'total',
        'message', 'error', 'updated_at', 'failed_nodes', 'kind', 'name', 'ip',
        'cleanup_pending', 'phase', 'current_node', 'started_at', 'created_at') if key in job}
    secrets = []
    def collect(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (key.lower() in {'key', 'knock_key'} or any(word in key.lower() for word in ('password', 'token', 'secret', 'private_key'))) and isinstance(item, str) and item:
                    secrets.append(item)
                else:
                    collect(item)
        elif isinstance(value, list):
            for item in value:
                collect(item)
    collect(inventory or job)
    for key in ('message', 'error'):
        if key in result:
            text = str(result[key])
            for secret in sorted(secrets, key=len, reverse=True):
                text = text.replace(secret, '[REDACTED]')
            result[key] = text
    return result
