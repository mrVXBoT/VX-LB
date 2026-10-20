"""GRE-in-UDP on loopback only. HTTPS carries every datagram between hosts.

No public GRE endpoint, raw socket, custom cryptography or direct fallback.
The outside adapter returns GRE packets through the authenticated UDP session.
"""
import asyncio
import importlib.util
import ipaddress
import json
import re
import socket
import sys
from pathlib import Path


def validate(c):
    c = dict(c)
    if not re.fullmatch(r'ldh[0-9a-f]{16}', c.get('owner', '')):
        raise ValueError('Invalid GRE HTTPS owner')
    if c.get('interface') != 'ldc' + c['owner'][3:13]:
        raise ValueError('Invalid GRE HTTPS interface')
    if c.get('role') not in ('iran', 'kharej'):
        raise ValueError('Invalid role')
    network = ipaddress.IPv4Network('10.204.0.0/16')
    a, b = (ipaddress.IPv4Address(c[k]) for k in ('private', 'peer'))
    if a == b or a not in network or b not in network or ipaddress.IPv4Network(str(a)+'/30', strict=False) != ipaddress.IPv4Network(str(b)+'/30', strict=False):
        raise ValueError('Invalid private GRE peers')
    if a.packed[-1] % 4 not in (1, 2) or b.packed[-1] % 4 not in (1, 2):
        raise ValueError('Invalid /30 host')
    for k in ('receive_port', 'carrier_port'):
        c[k] = int(c[k])
        if not 1024 <= c[k] <= 65535: raise ValueError('Invalid loopback port')
    if c['receive_port'] == c['carrier_port']: raise ValueError('Port collision')
    c['key'] = int(c['key'])
    if not 1 <= c['key'] <= 4294967295: raise ValueError('Invalid GRE key')
    c['mtu'] = int(c['mtu'])
    if not 576 <= c['mtu'] <= 1400: raise ValueError('Invalid MTU')
    c['ports'] = sorted(set(int(p) for p in c['ports']))
    if not c['ports'] or any(not 1 <= p <= 65535 for p in c['ports']): raise ValueError('Invalid entry ports')
    return c


def shared():
    path = Path(__file__).with_name('gre_agent.py')
    if not path.exists(): path = Path('/usr/local/libexec/ldbp-gre-v1.py')
    spec = importlib.util.spec_from_file_location('ldbp_gre_shared', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def owned(c):
    result = shared().command('ip', '-j', '-d', 'link', 'show', 'dev', c['interface'], check=False)
    if result.returncode: return False
    link = json.loads(result.stdout)[0]
    if link.get('ifalias') != c['owner']: raise RuntimeError('Interface belongs to another owner')
    info = link.get('linkinfo', {})
    data = info.get('info_data', {})
    if info.get('info_kind') != 'gre' or data.get('local') != '127.0.0.1' or data.get('remote') != '127.0.0.1':
        raise RuntimeError('GRE is not restricted to loopback')
    return True


def up(c):
    command = shared().command
    if owned(c): return
    routes = json.loads(command('ip', '-j', 'route', 'show').stdout)
    subnet = ipaddress.IPv4Network(c['private']+'/30', strict=False)
    for route in routes:
        if route.get('dst', 'default') != 'default' and subnet.overlaps(ipaddress.ip_network(route['dst'], strict=False)):
            raise RuntimeError('Private GRE subnet overlaps an existing route')
    # Never adopt an existing FOU listener. Publication precedes this mutation.
    listeners = command('ip', 'fou', 'show').stdout
    if re.search(r'\bport '+str(c['receive_port'])+r'\b', listeners):
        raise RuntimeError('FOU receive port is already owned')
    command('ip', 'fou', 'add', 'port', str(c['receive_port']), 'ipproto', '47', 'local', '127.0.0.1')
    created = False
    try:
        marker(c).write_text(c['owner'])
        command('ip', 'link', 'add', c['interface'], 'type', 'gre', 'local', '127.0.0.1', 'remote', '127.0.0.1',
                'key', str(c['key']), 'ttl', '64', 'encap', 'fou', 'encap-sport', str(c['receive_port']), 'encap-dport', str(c['carrier_port']))
        created = True
        command('ip', 'link', 'set', c['interface'], 'alias', c['owner'])
        command('ip', 'addr', 'add', c['private']+'/30', 'dev', c['interface'])
        command('ip', 'link', 'set', c['interface'], 'mtu', str(c['mtu']), 'up')
    except Exception:
        # The interface was created by this call; cleanup can precede its alias.
        if created: command('ip', 'link', 'delete', c['interface'], check=False)
        command('ip', 'fou', 'del', 'port', str(c['receive_port']), 'local', '127.0.0.1', check=False)
        marker(c).unlink(missing_ok=True)
        raise


def marker(c): return Path('/run/'+c['owner']+'.fou-owned')


def down(c):
    if owned(c): shared().command('ip', 'link', 'delete', c['interface'])
    listeners = shared().command('ip', 'fou', 'show').stdout
    present = re.search(r'\bport '+str(c['receive_port'])+r'\b', listeners)
    if marker(c).exists() and marker(c).read_text() == c['owner']:
        if present:
            shared().command('ip', 'fou', 'del', 'port', str(c['receive_port']), 'local', '127.0.0.1')
        marker(c).unlink()
    elif present:
        raise RuntimeError('FOU listener ownership is unconfirmed; automatic deletion refused')


class ReturnAdapter(asyncio.DatagramProtocol):
    def __init__(self, c): self.c = c; self.peer = None
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, address):
        if address[0] != '127.0.0.1': return
        if address[1] == self.c['receive_port']:
            if self.peer: self.transport.sendto(data, self.peer)
        else:
            self.peer = address
            self.transport.sendto(data, ('127.0.0.1', self.c['receive_port']))


async def serve(c):
    up(c); transport = None
    try:
        if c['role'] == 'kharej':
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: ReturnAdapter(c), local_addr=('127.0.0.1', c['carrier_port']))
        while True:
            if c['role'] == 'iran':
                # Keep the authenticated UDP association live for traffic initiated
                # by the outside server, including after an Xray reconnection.
                p = await asyncio.create_subprocess_exec('ping', '-n', '-c', '1', '-W', '2', '-I', c['interface'], c['peer'], stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await p.wait()
            await asyncio.sleep(10)
    finally:
        if transport: transport.close()
        down(c)


def main():
    action, path = sys.argv[1:3]
    c = validate(json.loads(Path(path).read_text()))
    if action == 'serve': asyncio.run(serve(c))
    elif action == 'down': down(c)
    elif action == 'echo': asyncio.run(shared().echo(c))
    elif action == 'probe': shared().probe(c, int(sys.argv[3]), sys.argv[4])
    elif action == 'relay': asyncio.run(shared().relay(c))
    elif action == 'check':
        if not owned(c): raise RuntimeError('GRE interface missing')
    else: raise ValueError('Unknown action')


if __name__ == '__main__':
    try: main()
    except Exception as e: print(str(e), file=sys.stderr); sys.exit(1)
