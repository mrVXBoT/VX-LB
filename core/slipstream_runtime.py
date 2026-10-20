"""Commands supported by the pinned upstream Slipstream v0.1.1 binaries.

One upstream server forwards TCP to one target. UDP application forwarding,
PSK authentication and TOML configuration are not upstream CLI capabilities.
"""
import ipaddress
import re
from core.validation import validate_port


def domain_name(value):
    name = str(value or '').strip().rstrip('.').lower()
    if len(name) > 253 or '.' not in name or not all(
        re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in name.split('.')
    ):
        raise ValueError('Slipstream requires an explicit valid delegated domain')
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError('Slipstream domain must be a DNS name, not an IP address')


def resolver_address(value):
    value = str(value).strip()
    if value.startswith('['):
        match = re.fullmatch(r'\[([^]]+)\]:(\d+)', value)
        if not match:
            raise ValueError('IPv6 resolver must use [address]:port')
        host, port = match.groups()
        address = ipaddress.IPv6Address(host)
        return f'[{address}]:{validate_port(port)}'
    host, separator, port = value.partition(':')
    address = ipaddress.IPv4Address(host)
    return f'{address}:{validate_port(port if separator else 53)}'


def server_argv(binary, *, domain, dns_port, target_ip, target_port, cert, key):
    address = ipaddress.ip_address(target_ip)
    target = f'[{address}]' if address.version == 6 else str(address)
    return [str(binary), '--domain', domain_name(domain), '--dns-listen-port',
            validate_port(dns_port), '--target-address', f'{target}:{validate_port(target_port)}',
            '--cert', str(cert), '--key', str(key)]


def client_argv(binary, *, domain, listen_port, resolvers, congestion='dcubic'):
    if congestion not in ('dcubic', 'bbr'):
        raise ValueError('Unsupported Slipstream congestion controller')
    if not isinstance(resolvers, (list, tuple)) or not resolvers:
        raise ValueError('Slipstream requires at least one resolver')
    argv = [str(binary), '--domain', domain_name(domain), '--tcp-listen-port',
            validate_port(listen_port), '--congestion-control', congestion]
    for resolver in dict.fromkeys(resolvers):
        argv += ['--resolver', resolver_address(resolver)]
    return argv
