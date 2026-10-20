"""Exact, owned firewall/MSS rules for a cleartext DC6 private link."""
import ipaddress
import json
import re
import shlex
import subprocess
import sys


def command(tool, *args, allowed=(0,)):
    result = subprocess.run([tool, '-w', '5', *args], capture_output=True, text=True, timeout=15)
    if result.returncode not in allowed:
        raise RuntimeError(result.stderr.strip() or 'DC6 firewall command failed')
    return result


def identity(config):
    iface = config['interface']
    if not re.fullmatch(r'dc6-[0-9a-f]{10}', iface):
        raise ValueError('Invalid owned DC6 interface')
    return iface, 'ldbp-dc6:' + iface


def rules(config):
    iface, tag = identity(config)
    remote = ipaddress.ip_address(config['remote_ip'])
    mtu = int(config['mtu'])
    if not 1280 <= mtu <= 1440 or config['carrier_type'] not in ['ip6gre', 'ip6ip6', 'sit']:
        raise ValueError('Invalid DC6 MTU/carrier')
    tool = 'iptables' if remote.version == 4 else 'ip6tables'
    comment = ['-m', 'comment', '--comment', tag]
    yield tool, 'filter', 'INPUT', ['-s', str(remote), '-p', '47' if config['carrier_type'] == 'ip6gre' else '41', *comment, '-j', 'ACCEPT']
    for key, family, tool, overhead in [('peer_v4', 4, 'iptables', 40), ('peer_v6', 6, 'ip6tables', 60)]:
        if not config.get(key):
            continue
        peer = ipaddress.ip_address(config[key])
        if peer.version != family:
            raise ValueError('Wrong DC6 private address family')
        yield tool, 'filter', 'INPUT', ['-i', iface, '-s', str(peer), *comment, '-j', 'ACCEPT']
        for chain in ['OUTPUT', 'FORWARD']:
            yield tool, 'mangle', chain, ['-o', iface, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN', *comment, '-j', 'TCPMSS', '--set-mss', str(min(int(config.get('mss', mtu-60)), mtu-overhead))]


def remove(config):
    _, tag = identity(config)
    for tool in ['iptables', 'ip6tables']:
        for table, chain in [('filter', 'INPUT'), ('mangle', 'OUTPUT'), ('mangle', 'FORWARD')]:
            for row in command(tool, '-t', table, '-S', chain).stdout.splitlines():
                parts = shlex.split(row)
                if parts[:2] != ['-A', chain] or '--comment' not in parts:
                    continue
                index = parts.index('--comment')
                if index + 1 < len(parts) and parts[index+1] == tag:
                    command(tool, '-t', table, '-D', *parts[1:])


def apply(config):
    for tool, table, chain, rule in rules(config):
        result = command(tool, '-t', table, '-C', chain, *rule, allowed=(0, 1))
        if result.returncode:
            command(tool, '-t', table, '-I', chain, '1', *rule)


if __name__ == '__main__':
    action, path = sys.argv[1:]
    with open(path) as source:
        config = json.load(source)
    {'apply': apply, 'remove': remove}[action](config)
