"""Owned TUN ingress/MSS rules; never flush or restore a shared firewall table."""
import ipaddress
import json
import re
import shlex
import subprocess
import sys


def command(*args, allowed=(0,)):
    result = subprocess.run(['iptables', '-w', '5', *args], capture_output=True, text=True, timeout=15)
    if result.returncode not in allowed:
        raise RuntimeError(result.stderr.strip() or 'TUN firewall command failed')
    return result


def validated(config):
    iface = config['interface']
    if not re.fullmatch(r'lbt[0-9a-f]{10}', iface):
        raise ValueError('Invalid owned TUN interface')
    for key in ['remote_ip', 'peer_private']:
        ipaddress.IPv4Address(config[key])
    if config['role'] not in ['iran', 'kharej']:
        raise ValueError('Invalid TUN endpoint role')
    if not 1 <= int(config['port']) <= 65535 or not 1200 <= int(config['mtu']) <= 1420:
        raise ValueError('Invalid TUN port/MTU')
    return iface, 'ldbp-tun:' + iface


def rules(config):
    iface, tag = validated(config)
    comment = ['-m', 'comment', '--comment', tag]
    carrier = ['-s', config['remote_ip'], '-p', 'udp']
    if config['role'] == 'kharej':
        carrier += ['--dport', str(config['port'])]
    else:
        carrier += ['--sport', str(config['port']), '-m', 'conntrack', '--ctstate', 'ESTABLISHED']
    yield 'filter', 'INPUT', [*carrier, *comment, '-j', 'ACCEPT']
    yield 'filter', 'INPUT', ['-i', iface, '-s', config['peer_private'], *comment, '-j', 'ACCEPT']
    for chain in ['OUTPUT', 'FORWARD']:
        yield 'mangle', chain, ['-o', iface, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN',
                                *comment, '-j', 'TCPMSS', '--set-mss', str(int(config['mtu']) - 40)]


def remove(config):
    _, tag = validated(config)
    for table, chain in [('filter', 'INPUT'), ('mangle', 'OUTPUT'), ('mangle', 'FORWARD')]:
        for row in command('-t', table, '-S', chain).stdout.splitlines():
            parts = shlex.split(row)
            if parts[:2] != ['-A', chain] or '--comment' not in parts:
                continue
            index = parts.index('--comment')
            if index + 1 < len(parts) and parts[index + 1] == tag:
                command('-t', table, '-D', *parts[1:])


def apply(config):
    for table, chain, rule in rules(config):
        found = command('-t', table, '-C', chain, *rule, allowed=(0, 1))
        if found.returncode == 1:
            command('-t', table, '-I', chain, '1', *rule)


if __name__ == '__main__':
    action, path = sys.argv[1:]
    with open(path) as source:
        config = json.load(source)
    {'apply': apply, 'remove': remove}[action](config)
