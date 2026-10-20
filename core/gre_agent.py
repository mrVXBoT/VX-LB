"""Standalone stdlib helper installed on GRE endpoints by LD-BP.

All network mutations are restricted to a validated per-link interface and
comment-tagged INPUT/OUTPUT rules. No default route, NAT or forwarding sysctl changes.
"""
import asyncio
import os
import ipaddress
import json
import re
import socket
import subprocess
import sys
import time

# Official VICI client is shipped separately; no global pip installation.
sys.path.insert(0, "/usr/local/libexec/ldbp-gre-vici")


def validate(config):
    c = dict(config)
    if c.get('owner') != 'ldbp-gre-v1' or not re.fullmatch(r'ldg[0-9a-f]{10}', c.get('interface', '')):
        raise ValueError('Invalid GRE ownership/interface')
    for field in ('local', 'remote', 'private', 'peer'):
        addr = ipaddress.IPv4Address(c[field])
        if addr.is_unspecified or addr.is_multicast or addr.is_loopback:
            raise ValueError('Invalid GRE endpoint address')
        c[field] = str(addr)
    network = ipaddress.IPv4Network(c['private'] + '/30', strict=False)
    if ipaddress.IPv4Address(c['private']) not in list(network.hosts()) or ipaddress.IPv4Address(c['peer']) not in list(network.hosts()) or c['private'] == c['peer'] or c['local'] == c['remote']:
        raise ValueError('Invalid GRE /30 peers')
    c['mtu'] = int(c['mtu']); c['key'] = int(c['key'])
    if not 576 <= c['mtu'] <= 1472 or not 1 <= c['key'] <= 4294967295:
        raise ValueError('Invalid GRE MTU/key')
    c['ports'] = sorted(set(int(p) for p in c.get('ports', [])))
    if any(not 1 <= p <= 65535 for p in c['ports']) or c.get('role') not in ('iran', 'kharej'):
        raise ValueError('Invalid GRE ports/role')
    return c


def command(*args, check=True):
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError(' '.join(args[:3]) + ': ' + (result.stderr or result.stdout).strip())
    return result


def secure_config(c):
    security = c.get('security', {})
    if security.get('mode') != 'ipsec' or not re.fullmatch(r'[0-9a-f]{64}', security.get('psk', '')):
        raise RuntimeError('Plain GRE is disabled: authenticated IPsec configuration is required')
    if c['mtu'] > 1400:
        raise ValueError('Secure GRE MTU must not exceed 1400')
    reqid = int(security.get('reqid', 0))
    if not 1 <= reqid <= 2147483647:
        raise ValueError('Invalid IPsec reqid')
    return security


def ipsec_connection(c):
    sec = secure_config(c)
    return {
        'version': '2', 'local_addrs': [c['local']], 'remote_addrs': [c['remote']],
        'proposals': ['aes256gcm16-prfsha256-ecp256'], 'dpd_delay': '20s', 'mobike':'no',
        'local': {'auth': 'psk', 'id': c['local']},
        'remote': {'auth': 'psk', 'id': c['remote']},
        'children': {c['interface']: {
            'local_ts': [c['local'] + '/32[47]'], 'remote_ts': [c['remote'] + '/32[47]'],
            'mode': 'transport', 'reqid': str(sec['reqid']),
            'esp_proposals': ['aes256gcm16-ecp256'], 'rekey_time': '30m',
            'life_time': '40m', 'start_action': 'trap', 'dpd_action': 'trap',
            'close_action': 'trap'}}}


def installed_sa(session, name, reqid):
    return any(sa.get('state') == b'ESTABLISHED' and
               child.get('state') == b'INSTALLED' and child.get('encr-alg') == b'AES_GCM_16' and
               child.get('reqid') == str(reqid).encode()
               for row in session.list_sas({'ike': name}) for sa in row.values()
               for child in sa.get('child-sas', {}).values())


def ipsec(c, action):
    import vici
    sec = secure_config(c)
    sock = socket.socket(socket.AF_UNIX); sock.settimeout(40)
    sock.connect(os.environ.get('LD_BP_VICI_SOCKET', '/var/run/charon.vici'))
    session = vici.Session(sock)
    name = 'ldbp-' + c['interface']
    if action == 'load':
        session.load_shared({'id': name, 'type': 'IKE', 'data': bytes.fromhex(sec['psk']),
                             'owners': [c['local'], c['remote']]})
        session.load_conn({name: ipsec_connection(c)})
        session.install({'child': c['interface'], 'ike': name})
    elif action == 'start':
        # Trap policies may already have negotiated while the GRE link came up.
        if installed_sa(session, name, sec['reqid']): return
        messages=[]
        try:
            for event in session.initiate({'child': c['interface'], 'ike': name, 'timeout': '30000', 'loglevel':'1'}):
                messages.append(event.get('msg', b'').decode('utf-8', 'replace'))
        except Exception as error:
            if installed_sa(session, name, sec['reqid']): return
            raise RuntimeError('IPsec negotiation failed: '+str(error)+'; '+'; '.join(messages[-8:])) from error
    elif action == 'rekey':
        list(session.rekey({'child': c['interface'], 'ike': name}))
    elif action == 'check':
        for chain, rule in security_rules(c):
            if command('iptables', '-w', '-C', chain, *rule, check=False).returncode:
                raise RuntimeError('IPsec firewall guard is missing; GRE is not safe')
        if not installed_sa(session, name, sec['reqid']):
            raise RuntimeError('Authenticated AES-GCM IPsec CHILD_SA is not installed')
    elif action == 'stop':
        # Unload only our connection, never reload/unload the daemon's entire config.
        known = session.get_conns().get('conns', [])
        if name.encode() in known:
            session.unload_conn({'name': name})
        if list(session.list_sas({'ike': name})):
            list(session.terminate({'ike': name, 'timeout': '10000'}))
        if name.encode() in session.get_shared().get('keys', []):
            session.unload_shared({'id': name})


def security_rules(c):
    sec = secure_config(c)
    tag = ['-m', 'comment', '--comment', 'ldbp-sec-' + c['interface']]
    for chain, direction, source, destination in (
        ('INPUT', 'in', c['remote'], c['local']),
        ('OUTPUT', 'out', c['local'], c['remote'])):
        # A negative policy match drops plaintext even if all XFRM policies vanish.
        yield chain, ['-p', '47', '-s', source, '-d', destination,
                      '-m', 'policy', '--dir', direction, '--pol', 'none', *tag, '-j', 'DROP']
        yield chain, ['-p', '47', '-s', source, '-d', destination,
                      '-m', 'policy', '--dir', direction, '--pol', 'ipsec',
                      '--proto', 'esp', '--reqid', str(sec['reqid']), *tag, '-j', 'ACCEPT']
        yield chain, ['-p', '47', '-s', source, '-d', destination, *tag, '-j', 'DROP']
        for protocol, extra in [('udp', ['-m', 'multiport', '--dports', '500,4500']), ('50', [])]:
            yield chain, ['-p', protocol, '-s', source, '-d', destination, *extra, *tag, '-j', 'ACCEPT']


def security_firewall(c, remove=False):
    ruleset = list(security_rules(c))
    # Insert reversed, so the plaintext DROP is the first matching GRE rule.
    for chain, rule in ruleset if remove else reversed(ruleset):
        if remove:
            while not command('iptables', '-w', '-C', chain, *rule, check=False).returncode:
                command('iptables', '-w', '-D', chain, *rule)
        elif command('iptables', '-w', '-C', chain, *rule, check=False).returncode:
            command('iptables', '-w', '-I', chain, '1', *rule)


def rules(c):
    tag = ['-m', 'comment', '--comment', 'ldbp-gre-' + c['interface']]
    # Outer GRE acceptance is restricted to authenticated ESP by security_rules.
    yield ['-i', c['interface'], '-s', c['peer'], '-d', c['private'], *tag, '-j', 'ACCEPT']
    if c['role'] == 'iran':
        for port in c['ports']:
            for protocol in ('tcp', 'udp'):
                yield ['-p', protocol, '-d', c['local'], '--dport', str(port), *tag, '-j', 'ACCEPT']


def firewall(c, remove=False):
    for rule in rules(c):
        if remove:
            for _ in range(16):
                if command('iptables', '-w', '-C', 'INPUT', *rule, check=False).returncode: break
                command('iptables', '-w', '-D', 'INPUT', *rule)
        elif command('iptables', '-w', '-C', 'INPUT', *rule, check=False).returncode:
            command('iptables', '-w', '-I', 'INPUT', '1', *rule)


def underlay(c):
    command('modprobe','ip_gre',check=False)
    addresses = json.loads(command('ip', '-j', '-4', 'addr', 'show').stdout)
    if not any(a.get('local') == c['local'] for interface in addresses for a in interface.get('addr_info', [])):
        raise RuntimeError('GRE requires a locally assigned IPv4 endpoint; NAT/public-IP mapping needs separate configuration')
    route = json.loads(command('ip', '-j', '-4', 'route', 'get', c['remote']).stdout)[0]
    link = json.loads(command('ip', '-j', 'link', 'show', 'dev', route['dev']).stdout)[0]
    if c['mtu'] > int(link['mtu']) - 100:
        raise RuntimeError('GRE MTU exceeds underlay MTU minus conservative GRE/IPsec/NAT-T overhead (100 bytes)')


def preflight(c):
    secure_config(c)
    import vici
    sock = socket.socket(socket.AF_UNIX); sock.settimeout(10)
    sock.connect(os.environ.get('LD_BP_VICI_SOCKET', '/var/run/charon.vici'))
    vici.Session(sock).version()
    underlay(c)
    if not command('ip', 'link', 'show', 'dev', c['interface'], check=False).returncode:
        raise RuntimeError('GRE interface name already exists; refusing to overwrite it')
    subnet = ipaddress.IPv4Network(c['private'] + '/30', strict=False)
    for row in json.loads(command('ip', '-j', '-4', 'route', 'show', 'table', 'all').stdout):
        dst = row.get('dst', 'default')
        if dst == 'default': continue
        if subnet.overlaps(ipaddress.IPv4Network(dst, strict=False)):
            raise RuntimeError('GRE private subnet overlaps an existing route')
    command('iptables', '-w', '-S', 'INPUT')
    if c['role'] == 'iran':
        bound = []
        try:
            for port in c['ports']:
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    s = socket.socket(socket.AF_INET, kind); bound.append(s)
                    if kind == socket.SOCK_STREAM: s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                    s.bind(('0.0.0.0', port))
        finally:
            for s in bound: s.close()


def owned_link(c):
    existing = command('ip', '-d', '-j', 'link', 'show', 'dev', c['interface'], check=False)
    if existing.returncode: return None
    row = json.loads(existing.stdout)[0]
    info = row.get('linkinfo', {}); data = info.get('info_data', {})
    if row.get('ifalias') != 'ldbp-gre-v1:' + c['interface'] or info.get('info_kind') != 'gre' or data.get('local') != c['local'] or data.get('remote') != c['remote']:
        raise RuntimeError('Refusing to modify an unrelated interface')
    return row


def up(c):
    secure_config(c)
    security_firewall(c)
    ipsec(c, 'load')
    command('modprobe','ip_gre',check=False)
    if not owned_link(c):
        command('ip', 'tunnel', 'add', c['interface'], 'mode', 'gre', 'local', c['local'], 'remote', c['remote'], 'key', str(c['key']), 'ttl', '64')
        command('ip','link','set','dev',c['interface'],'alias','ldbp-gre-v1:'+c['interface'])
    command('ip', 'addr', 'replace', c['private'] + '/30', 'dev', c['interface'])
    command('ip', 'link', 'set', 'dev', c['interface'], 'mtu', str(c['mtu']), 'up')
    firewall(c)
    security_firewall(c)


def down(c):
    existing = owned_link(c)
    if existing: command('ip', 'tunnel', 'del', c['interface'])
    firewall(c, remove=True)
    if c.get('security'):
        ipsec(c, 'stop')
        security_firewall(c, remove=True)


async def pipe(reader, writer):
    while True:
        data = await reader.read(65536)
        if not data: break
        writer.write(data); await writer.drain()
    if writer.can_write_eof(): writer.write_eof()


async def forward_tcp(reader, writer, peer, port):
    remote_writer = None
    try:
        remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(peer, port), 8)
        await asyncio.gather(pipe(reader, remote_writer), pipe(remote_reader, writer))
    except (OSError, asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        writer.close()
        if remote_writer: remote_writer.close()


class UdpReplies(asyncio.DatagramProtocol):
    def __init__(self, parent, address): self.parent = parent; self.address = address
    def datagram_received(self, data, address):
        entry = self.parent.sessions.get(self.address)
        if entry:
            entry[1] = time.monotonic(); self.parent.transport.sendto(data, self.address)


class UdpRelay(asyncio.DatagramProtocol):
    def __init__(self, peer, port):
        self.peer = peer; self.port = port; self.sessions = {}; self.pending = {}; self.closed = False
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, address):
        if address in self.sessions:
            entry = self.sessions[address]; entry[1] = time.monotonic(); entry[0].sendto(data); return
        if address in self.pending:
            queue = self.pending[address]
            if len(queue) < 8 and sum(map(len,queue)) + len(data) <= 65536: queue.append(data)
            return
        if len(self.sessions) + len(self.pending) >= 1024: return
        self.pending[address] = [data]; asyncio.create_task(self.open(address))
    async def open(self, address):
        try:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: UdpReplies(self, address), remote_addr=(self.peer, self.port))
            if self.closed: transport.close(); return
            self.sessions[address] = [transport, time.monotonic()]
            for data in self.pending.get(address, []): transport.sendto(data)
        except OSError: pass
        finally: self.pending.pop(address, None)
    def expire(self):
        for address, entry in list(self.sessions.items()):
            if time.monotonic() - entry[1] > 60: entry[0].close(); del self.sessions[address]
    def connection_lost(self, error):
        self.closed = True
        for transport, _ in self.sessions.values(): transport.close()
        self.sessions.clear()


async def relay(c):
    tcp_servers = []; udp_transports = []; protocols = []
    try:
        for port in c['ports']:
            tcp_servers.append(await asyncio.start_server(lambda r,w,p=port: forward_tcp(r,w,c['peer'],p), '0.0.0.0', port))
            transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(lambda p=port: UdpRelay(c['peer'],p), local_addr=('0.0.0.0',port))
            udp_transports.append(transport); protocols.append(protocol)
        while True:
            await asyncio.sleep(15)
            for protocol in protocols: protocol.expire()
    finally:
        for server in tcp_servers: server.close(); await server.wait_closed()
        for transport in udp_transports: transport.close()


class EchoUdp(asyncio.DatagramProtocol):
    def __init__(self, peer): self.peer = peer
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, address):
        if address[0] == self.peer: self.transport.sendto(data, address)


async def echo(c):
    async def handle(reader, writer):
        try:
            if writer.get_extra_info('peername')[0] != c['peer']: return
            while True:
                data = await asyncio.wait_for(reader.read(65536), 5)
                if not data: break
                writer.write(data); await writer.drain()
        except (OSError, asyncio.TimeoutError): pass
        finally: writer.close()
    server = await asyncio.start_server(handle, c['private'], 0)
    port = server.sockets[0].getsockname()[1]
    udp, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: EchoUdp(c['peer']), local_addr=(c['private'],port))
    print(port, flush=True)
    try: await asyncio.sleep(45)
    finally: server.close(); await server.wait_closed(); udp.close()


def probe(c, port, nonce):
    payload = (nonce.encode() * 1366)[:65536]
    with socket.create_connection((c['peer'], port), timeout=4) as s:
        s.settimeout(4); s.sendall(payload); received = b''
        while len(received) < len(payload):
            chunk = s.recv(len(payload) - len(received))
            if not chunk: break
            received += chunk
        if received != payload: raise RuntimeError('GRE TCP data probe failed')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(4); s.connect((c['peer'], port))
        for index in range(8):
            data = str(index).encode() + payload[:1000]; s.send(data)
            if s.recv(1200) != data: raise RuntimeError('GRE UDP data probe failed')


def main():
    action, path = sys.argv[1:3]
    with open(path) as source: c = validate(json.load(source))
    if action == 'preflight': preflight(c)
    elif action == 'up': up(c)
    elif action == 'secure-start': ipsec(c, 'start')
    elif action == 'secure-check': ipsec(c, 'check')
    elif action == 'secure-stop': ipsec(c, 'stop')
    elif action == 'secure-rekey': ipsec(c, 'rekey')
    elif action == 'down': down(c)
    elif action == 'firewall': firewall(c)
    elif action == 'unfirewall': firewall(c, remove=True)
    elif action == 'relay': asyncio.run(relay(c))
    elif action == 'echo': asyncio.run(echo(c))
    elif action == 'probe': probe(c, int(sys.argv[3]), sys.argv[4])
    elif action == 'mtu':
        underlay(c)
        if not owned_link(c): raise RuntimeError('GRE interface is missing')
        command('ip','link','set','dev',c['interface'],'mtu',str(c['mtu']))
    else: raise ValueError('Unknown GRE action')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        print(str(error), file=sys.stderr); sys.exit(1)
