"""Standalone owned IPv4 blackhole guard for a private link's reserved /30.

The guard survives interface/service shutdown. Only explicit verified deletion
removes it, so private packets cannot fall through to the management default.
"""
import ipaddress
import json
import subprocess
import sys

PROTOCOL=242
METRIC=42760


def execute(arguments):
    return subprocess.run(['ip', '-4', *arguments], check=True, capture_output=True, text=True, timeout=10).stdout


def guard(action, subnet):
    network=ipaddress.IPv4Network(subnet)
    if network.prefixlen!=30:
        raise ValueError('Route guard requires a reserved /30')
    rows=json.loads(execute(['-j','route','show','table','main','exact',str(network)]))
    candidates=[row for row in rows if int(row.get('metric',0))==METRIC]
    for row in candidates:
        # `ip -j` may return the numeric route type (6 for blackhole) on some
        # iproute2 versions instead of the name; accept either representation.
        if row.get('type') not in ('blackhole', 6, '6') or str(row.get('protocol'))!=str(PROTOCOL):
            raise RuntimeError('Route identity changed; foreign route was preserved')
    if action=='ensure':
        if not candidates:
            execute(['route','add','blackhole',str(network),'proto',str(PROTOCOL),'metric',str(METRIC)])
    elif action=='remove':
        for _ in candidates:
            execute(['route','del','blackhole',str(network),'proto',str(PROTOCOL),'metric',str(METRIC)])
    else:
        raise ValueError('Invalid route guard action')


if __name__=='__main__':
    guard(sys.argv[1],sys.argv[2])
