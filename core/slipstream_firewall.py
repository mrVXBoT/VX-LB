"""Standalone, owned IPv4 DNS query-rate rules for a Slipstream server.

No ACCEPT rules, global policy changes or chain flushes. The rule drops UDP
packets above a per-source-IP token bucket, only on this pool's DNS port.
"""
import argparse
import json
import re
import shlex
import subprocess


def validated(config):
    token = str(config['id'])
    if not re.fullmatch(r'[0-9a-f]{16}', token):
        raise ValueError('Invalid Slipstream firewall identity')
    port, rate = str(config['dns_port']), str(config['rate_limit'])
    if not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError('Invalid DNS port')
    if not rate.isdecimal() or not 10 <= int(rate) <= 2000:
        raise ValueError('DNS rate limit must be 10..2000 packets/second per source IP')
    backend = config.get('backend_port')
    if backend is not None and (not str(backend).isdecimal() or not 1 <= int(backend) <= 65535 or int(backend) == int(port)):
        raise ValueError('Invalid internal DNS port')
    return token, int(port), int(rate)


def arguments(config):
    token, port, rate = validated(config)
    return ['-p', 'udp', '--dport', str(port), '-m', 'comment', '--comment', 'vxlb-slipstream:'+token,
            '-m', 'hashlimit', '--hashlimit-above', str(rate)+'/second',
            '--hashlimit-burst', str(rate * 2), '--hashlimit-mode', 'srcip',
            '--hashlimit-name', 'ls'+token[:12], '--hashlimit-htable-max', '4096',
            '--hashlimit-htable-expire', '10000', '-j', 'DROP']


def command(*values):
    return subprocess.run(['iptables', '-w', '5', *values], check=True, text=True,
                          capture_output=True, timeout=15).stdout


def remove(config, preserve_backend=False):
    token, _, _ = validated(config)
    tag = 'vxlb-slipstream:'+token
    for row in command('-S', 'INPUT').splitlines():
        parts = shlex.split(row)
        if len(parts) < 2 or parts[:2] != ['-A', 'INPUT']:
            continue
        if '--comment' not in parts:
            continue
        position = parts.index('--comment')
        if position + 1 < len(parts) and parts[position + 1] == tag:
            # Remove the exact saved rule, even if the port/rate changed before
            # ExecStopPost. Never guess the old rule from the new config.
            if preserve_backend and '--hashlimit-above' not in parts:
                continue
            command('-D', *parts[1:])


def apply(config):
    rule = arguments(config)
    if config.get('backend_port'):
        token, _, _ = validated(config)
        backend = ['!', '-i', 'lo', '-p', 'udp', '--dport', str(config['backend_port']),
                   '-m', 'comment', '--comment', 'vxlb-slipstream:'+token, '-j', 'DROP']
        try:
            command('-C', 'INPUT', *backend)
        except subprocess.CalledProcessError as error:
            if error.returncode != 1:
                raise
            command('-I', 'INPUT', '1', *backend)
        # The internal-port guard must remain installed while rate rules change.
        remove(config, preserve_backend=True)
    else:
        remove(config)
    command('-I', 'INPUT', '1', *rule)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['apply', 'remove'])
    parser.add_argument('config')
    args = parser.parse_args()
    with open(args.config) as source:
        config = json.load(source)
    (apply if args.action == 'apply' else remove)(config)
