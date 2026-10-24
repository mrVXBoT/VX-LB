"""Owned runtime artifacts and verified deployment for the Slipstream adapter."""
import datetime
import hashlib
import json
from pathlib import Path
import secrets
import re
import shlex
import time

from core.slipstream_runtime import domain_name, resolver_address, server_argv, client_argv
from core.validation import validate_port, validate_ports, validate_tunnel_name


def identity_material(common_name="vxlb-slipstream"):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', common_name):
        raise ValueError('Invalid private TLS identity')
    result = {}
    now = datetime.datetime.now(datetime.timezone.utc)
    for role in ('server', 'client'):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if role == 'server' else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(key, hashes.SHA256()))
        result[role + '_cert'] = cert.public_bytes(serialization.Encoding.PEM).decode()
        result[role + '_key'] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return result


def unit(name, command, requires=None, pre=None, post=None):
    dependency = f'Wants={requires}\nAfter={requires}\n' if requires else ''
    # systemd's argv quoting differs from a shell; validated arguments contain
    # no whitespace. Escape percent specifiers regardless.
    encoded = ' '.join('"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"' for value in command)
    hooks = ''.join(key + '=' + ' '.join(shlex.quote(str(value)) for value in values) + '\n'
                    for key, values in (('ExecStartPre', pre), ('ExecStopPost', post)) if values)
    return (f'[Unit]\nDescription=VX-LB Slipstream {name}\nAfter=network-online.target\nWants=network-online.target\n{dependency}'
            f'[Service]\nType=simple\n{hooks}ExecStart={encoded}\nRestart=always\nRestartSec=2\n'
            'UMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\n'
            'Environment=SSLKEYLOGFILE=\n[Install]\nWantedBy=multi-user.target\n')


def plan(node, outside, pool):
    token = str(pool['slipstream_id'])
    if not re.fullmatch(r'[0-9a-f]{16}', token):
        raise ValueError('Slipstream resource identity is invalid')
    node_id = token + '-' + hashlib.sha256(node['ip'].encode()).hexdigest()[:10]
    base = f'/etc/vxlb/slipstream/{token}'
    domain = domain_name(pool.get('domain'))
    resolvers = pool.get('resolvers')
    if not isinstance(resolvers, list) or not resolvers:
        raise ValueError('Slipstream requires an explicit resolver list')
    resolvers = [resolver_address(value) for value in resolvers]
    ports = list(map(int, validate_ports(pool['client_ports'])))
    relay_port = int(validate_port(pool['slipstream_relay_port']))
    carrier_port = int(validate_port(node['slipstream_carrier_port']))
    security = pool['slipstream_security']
    server_config = dict(role='server', listen_port=relay_port, ports=ports, target_host='127.0.0.1',
                         cert=base+'/server.crt', key=base+'/server.key', peer_cert=base+'/client.crt')
    client_config = dict(role='client', carrier_port=carrier_port, ports=ports,
                         cert=base+'/client.crt', key=base+'/client.key', peer_cert=base+'/server.crt')
    server_relay = f'vxlb-slipstream-{token}-secure.service'
    server_dns = f'vxlb-slipstream-{token}-dns.service'
    client_dns = f'vxlb-slipstream-{node_id}-dns.service'
    client_relay = f'vxlb-slipstream-{node_id}-secure.service'
    agent = Path(__file__).with_name('slipstream_secure_relay.py').read_text()
    server_files = {base+'/server.crt': security['server_cert'], base+'/server.key': security['server_key'],
                    base+'/client.crt': security['client_cert'], base+'/relay.py': agent,
                    base+'/server.json': json.dumps(server_config)}
    client_files = {base+'/server.crt': security['server_cert'], base+'/client.crt': security['client_cert'],
                    base+'/client.key': security['client_key'], base+'/relay.py': agent,
                    base+f'/{node_id}.json': json.dumps(client_config)}
    server_files['/etc/systemd/system/'+server_relay] = unit(server_relay, ['/usr/bin/python3', base+'/relay.py', base+'/server.json'])
    server_files['/etc/systemd/system/'+server_dns] = unit(server_dns, server_argv('/usr/local/bin/slipstream-server', domain=domain,
        dns_port=pool['dns_port'], target_ip='127.0.0.1', target_port=relay_port, cert=base+'/server.crt', key=base+'/server.key'), server_relay)
    if int(pool.get('slipstream_runtime_version', 1)) >= 2:
        from core.slipstream_firewall import validated
        firewall = dict(id=token, dns_port=pool['dns_port'], rate_limit=pool.get('rate_limit', 1000))
        validated(firewall)
        server_files[base+'/firewall.py'] = Path(__file__).with_name('slipstream_firewall.py').read_text()
        server_files[base+'/firewall.json'] = json.dumps(firewall)
        server_files['/etc/systemd/system/'+server_dns] = unit(server_dns,
            server_argv('/usr/local/bin/slipstream-server', domain=domain, dns_port=pool['dns_port'],
                        target_ip='127.0.0.1', target_port=relay_port, cert=base+'/server.crt', key=base+'/server.key'),
            server_relay, pre=['/usr/bin/python3', base+'/firewall.py', 'apply', base+'/firewall.json'],
            post=['/usr/bin/python3', base+'/firewall.py', 'remove', base+'/firewall.json'])
    if int(pool.get('slipstream_runtime_version', 1)) >= 3:
        backend = int(validate_port(pool['slipstream_dns_backend_port']))
        guard = f'vxlb-slipstream-{token}-guard.service'
        server_files[base+'/guard.py'] = Path(__file__).with_name('slipstream_dns_guard.py').read_text()
        server_files[base+'/guard.json'] = json.dumps(dict(listen_host=outside['ip'], listen_port=pool['dns_port'], backend_port=backend, domain=domain))
        firewall['backend_port'] = backend
        server_files[base+'/firewall.json'] = json.dumps(firewall)
        server_files['/etc/systemd/system/'+server_dns] = unit(server_dns,
            server_argv('/usr/local/bin/slipstream-server', domain=domain, dns_port=backend,
                        target_ip='127.0.0.1', target_port=relay_port, cert=base+'/server.crt', key=base+'/server.key'),
            server_relay, pre=['/usr/bin/python3', base+'/firewall.py', 'apply', base+'/firewall.json'],
            post=['/usr/bin/python3', base+'/firewall.py', 'remove', base+'/firewall.json'])
        server_files['/etc/systemd/system/'+guard] = unit(guard, ['/usr/bin/python3', base+'/guard.py', base+'/guard.json'], server_dns)
    client_files['/etc/systemd/system/'+client_dns] = unit(client_dns, client_argv('/usr/local/bin/slipstream-client', domain=domain,
        listen_port=carrier_port, resolvers=resolvers))
    client_files['/etc/systemd/system/'+client_relay] = unit(client_relay, ['/usr/bin/python3', base+'/relay.py', base+f'/{node_id}.json'], client_dns)
    return dict(base=base, node_id=node_id, server_files=server_files, client_files=client_files,
                server_services=[server_relay, server_dns] + ([guard] if int(pool.get('slipstream_runtime_version', 1)) >= 3 else []), client_services=[client_dns, client_relay],
                client_config_path=base+f'/{node_id}.json', domain=domain, protocols=['tcp', 'udp'])


def deploy(ssh, files, services):
    # Every path belongs to a randomly identified connection. Never overwrite
    # another pool's files; upload as a temporary file before atomic rename.
    for path, content in files.items():
        temporary = path + '.stage-' + secrets.token_hex(6)
        try:
            if not ssh.write_file(temporary, content):
                raise RuntimeError('Could not upload Slipstream runtime artifact')
            mode = '644' if path.endswith('.service') else '600'
            code, _, _ = ssh.execute(f'chmod {mode} {shlex.quote(temporary)} && mv -f {shlex.quote(temporary)} {shlex.quote(path)}')
            if code:
                raise RuntimeError('Could not publish Slipstream runtime artifact')
        finally:
            ssh.execute('rm -f ' + shlex.quote(temporary))
    if not services:
        return
    names = ' '.join(map(shlex.quote, services))
    code, _, _ = ssh.execute(f'systemctl daemon-reload && systemctl enable {names} && systemctl restart {names}')
    if code:
        raise RuntimeError('Slipstream service startup failed')
    for service in services:
        code, out, _ = ssh.execute('systemctl is-active ' + shlex.quote(service))
        if code or out.strip() != 'active':
            raise RuntimeError('Slipstream service is not active')


def cleanup(ssh, files, services):
    present = []
    for service in services:
        code, state, _ = ssh.execute('systemctl show -p LoadState --value ' + shlex.quote(service))
        if code or state.strip() not in ('loaded', 'not-found', 'error', 'bad-setting', 'masked'):
            raise RuntimeError('Could not inspect Slipstream service ownership; inventory retained')
        if state.strip() != 'not-found':
            present.append(service)
    if present:
        names = ' '.join(map(shlex.quote, present))
        code, _, _ = ssh.execute(f'systemctl stop {names}')
        if code:
            raise RuntimeError('Could not stop Slipstream services; inventory retained')
        for service in present:
            _, state, _ = ssh.execute('systemctl is-active ' + shlex.quote(service))
            if state.strip() in ('active', 'activating', 'deactivating'):
                raise RuntimeError('Slipstream service still running; inventory retained')
        code, _, _ = ssh.execute(f'systemctl disable {names}')
        if code:
            raise RuntimeError('Could not disable Slipstream services; inventory retained')
    code, _, _ = ssh.execute('rm -f ' + ' '.join(map(shlex.quote, files)) + ' && systemctl daemon-reload')
    if code:
        raise RuntimeError('Slipstream cleanup incomplete; inventory retained')


def probe(ssh, config_path):
    # The nonce traverses client TLS -> actual DNS carrier -> remote TLS relay.
    # This proves transport, not the user's application service/UDP readiness.
    program = '''import importlib.util,json,secrets,struct,sys,time
path=sys.argv[1];spec=importlib.util.spec_from_file_location('relay',path.rsplit('/',1)[0]+'/relay.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with open(path) as source:config=json.load(source)
nonce=secrets.token_bytes(64);started=time.monotonic()
with m.connect_carrier(config) as connection:
 connection.sendall(b'LDS1'+bytes([3])+bytes(2)+struct.pack('!H',len(nonce))+nonce)
 assert m.exact(connection,len(nonce))==nonce
print(json.dumps({'passed':True,'protocols':['tcp'],'latency_ms':(time.monotonic()-started)*1000,'udp_application':'UNVERIFIED'}))
'''
    code, out, _ = ssh.execute('python3 -c ' + shlex.quote(program) + ' ' + shlex.quote(config_path), timeout=30)
    if code:
        return {'passed': False, 'status': 'DOWN', 'latency_ms': None, 'protocols': [], 'error': 'Authenticated Slipstream data challenge failed'}
    try:
        result = json.loads(out)
        if result.get('passed') is not True or result.get('protocols') != ['tcp']:
            raise ValueError('Invalid probe response')
        return result
    except (ValueError, TypeError):
        return {'passed': False, 'status': 'UNVERIFIED', 'latency_ms': None, 'protocols': [], 'error': 'Invalid probe response'}


def connection(server):
    from core.ssh_client import SSHManager
    ssh = SSHManager(server['ip'], int(server.get('port') or server.get('ssh_port') or 22),
                     server.get('username') or 'root', server.get('password'))
    ok, _ = ssh.connect()
    if not ok:
        ssh.close()
        raise RuntimeError('SSH connection failed')
    return ssh


def create(name, kharej, servers, ports, domain=None, resolvers=None, dns_port=53, callback=None, rate_limit=1000, **kwargs):
    from core.slipstream_adapter import get_pools, save_pool
    from core.validation import validate_pool_name
    from core.load_balancer import LoadBalancerManager
    from core.transport_change import mutation_lock
    with mutation_lock():
        try:
            name = validate_pool_name(name)
            ports = validate_ports(ports)
            domain = domain_name(domain)
            dns_port = int(validate_port(dns_port))
            from core.slipstream_firewall import validated
            validated(dict(id='0'*16, dns_port=dns_port, rate_limit=rate_limit))
            rate_limit = int(rate_limit)
            if str(dns_port) in ports:
                raise ValueError('DNS carrier port conflicts with application forwarding port')
            if not servers or not kharej or name in get_pools():
                raise ValueError('Pool requires endpoints and a unique name')
            if any(node['ip'] == kharej['ip'] for node in servers) or len({node['ip'] for node in servers}) != len(servers):
                raise ValueError('Pool endpoints must be distinct')
            if isinstance(resolvers, str):
                resolvers = [value.strip() for value in resolvers.split(',') if value.strip()]
            resolvers = [resolver_address(value) for value in (resolvers or [])]
            if not resolvers:
                raise ValueError('Configure at least one recursive DNS resolver')
            ok, message = LoadBalancerManager.check_port_conflicts(ports, [node['ip'] for node in servers])
            if not ok:
                raise ValueError(message)
            for existing in get_pools().values():
                if existing.get('engine') == 'slipstream' and existing.get('kharej_server', {}).get('ip') == kharej['ip'] and int(existing.get('dns_port', 53)) == dns_port:
                    raise ValueError('Another Slipstream pool owns this destination DNS listener')
            pool = dict(name=name, engine='slipstream', transport='slipstream', domain=domain, resolvers=resolvers,
                        dns_port=dns_port, client_ports=ports, kharej_server=kharej, nodes=[], rate_limit=rate_limit, slipstream_runtime_version=3,
                        slipstream_id=secrets.token_hex(8), slipstream_security=identity_material(),
                        slipstream_server_ready=False)
            save_pool(name, pool)
            results = [add(name, server, callback) for server in servers]
            updated = get_pools()[name]
            complete = all(ok for ok, _ in results)
            return complete, ('Slipstream provisioning verified' if complete else '; '.join(message for ok, message in results if not ok)), updated
        except (ValueError, RuntimeError) as error:
            return False, str(error), {}


def add(name, server, callback=None):
    from core.slipstream_adapter import get_pools, save_pool, SlipstreamAdapter
    from core.tunnel_probe import reserve_probe_port
    from core.transport_change import mutation_lock
    with mutation_lock():
        pool = get_pools().get(name)
        if not pool or 'slipstream_security' not in pool:
            return False, 'Slipstream pool requires verified runtime provisioning'
        if any(node['ip'] == server['ip'] for node in pool.get('nodes', [])):
            return False, 'Node already exists; remove its resources before retrying'
        from core.load_balancer import LoadBalancerManager
        if server['ip'] == pool['kharej_server']['ip']:
            return False, 'Iran and outside endpoints must be distinct'
        ok, message = LoadBalancerManager.check_port_conflicts(pool['client_ports'], [server['ip']], exclude_pool_name=name)
        if not ok:
            return False, message
        iran = outside = None
        config = None
        node = dict(ip=server['ip'], server_name=server.get('server_name') or server['ip'], engine='slipstream', provisioning=True)
        try:
            if callback:
                callback('Connecting Slipstream endpoints')
            iran = connection(server)
            outside = connection(pool['kharej_server'])
            adapter = SlipstreamAdapter()
            for ssh, role in ((iran, 'iran'), (outside, 'kharej')):
                ok, _ = adapter.install(ssh, role, {})
                if not ok:
                    raise RuntimeError('Verified Slipstream binary installation failed')
            if int(pool.get('slipstream_runtime_version', 1)) >= 2:
                code, _, _ = outside.execute('command -v iptables')
                if code:
                    raise RuntimeError('iptables is required for the owned DNS query limiter')
            if not pool.get('slipstream_server_ready'):
                dns_host = pool['kharej_server']['ip'] if int(pool.get('slipstream_runtime_version', 1)) >= 3 else '0.0.0.0'
                selected = reserve_probe_port(outside, [], preferred=pool['dns_port'], bind_host=dns_host)
                if selected != pool['dns_port']:
                    raise RuntimeError('Destination DNS port is occupied; no existing DNS service was modified')
                excluded = [pool['dns_port']] + list(map(int, pool['client_ports']))
                if int(pool.get('slipstream_runtime_version', 1)) >= 3:
                    pool['slipstream_dns_backend_port'] = reserve_probe_port(outside, excluded, bind_host='0.0.0.0')
                    excluded.append(pool['slipstream_dns_backend_port'])
                pool['slipstream_relay_port'] = reserve_probe_port(outside, excluded)
            node['slipstream_carrier_port'] = reserve_probe_port(iran, list(map(int, pool['client_ports'])), bind_host='0.0.0.0')
            config = plan(node, pool['kharej_server'], pool)
            node.update(node_name=config['node_id'], domain=pool['domain'],
                        slipstream_config_path=config['client_config_path'], status='provisioning')
            pool['nodes'].append(node)
            save_pool(name, pool)  # Persist ownership before remote mutation.
            if callback:
                callback('Installing Slipstream runtime services')
            if not pool.get('slipstream_server_ready'):
                deploy(outside, config['server_files'], config['server_services'])
                pool['slipstream_server_ready'] = True
                save_pool(name, pool)
            deploy(iran, config['client_files'], config['client_services'])
            if callback:
                callback('Verifying authenticated Slipstream path')
            result = {'passed': False}
            for _ in range(5):
                result = probe(iran, config['client_config_path'])
                if result.get('passed'):
                    break
                time.sleep(1)
            if not result.get('passed'):
                raise RuntimeError('Authenticated data did not traverse Slipstream DNS path; check domain delegation and resolvers')
            node.update(provisioning=False, status='ready', health=result)
            save_pool(name, pool)
            return True, 'Slipstream node installed and authenticated data verified'
        except Exception as error:
            # Ownership stays visible until cleanup is confirmed; never silently
            # discard a partially deployed host from inventory.
            if config is not None:
                node.update(status='failed', provisioning=True, error=str(error))
                save_pool(name, pool)
            return False, str(error)
        finally:
            for ssh in (iran, outside):
                if ssh:
                    ssh.close()


def remove(name, iran_ip, callback=None):
    from core.slipstream_adapter import get_pools, save_pool
    from core.storage import load_data
    from core.transport_change import mutation_lock
    with mutation_lock():
        pool = get_pools().get(name)
        node = next((node for node in (pool or {}).get('nodes', []) if node['ip'] == iran_ip), None)
        if not node:
            return False, 'Slipstream node not found'
        servers = load_data().get('iran_servers', [])
        if isinstance(servers, dict):
            servers = list(servers.values())
        server = next((item for item in servers if item['ip'] == iran_ip), None)
        if not server:
            return False, 'SSH credentials for the node were not found; inventory retained'
        ssh = None
        try:
            config = plan(node, pool['kharej_server'], pool)
            ssh = connection(server)
            cleanup(ssh, config['client_files'], config['client_services'])
            pool['nodes'] = [item for item in pool['nodes'] if item['ip'] != iran_ip]
            save_pool(name, pool)
            return True, 'Slipstream client resources removed'
        except Exception as error:
            return False, str(error)
        finally:
            if ssh:
                ssh.close()


def delete_pool(name, callback=None):
    from core.slipstream_adapter import get_pools
    from core.storage import atomic_update
    from core.transport_change import mutation_lock
    with mutation_lock():
        pool = get_pools().get(name)
        if not pool:
            return False, 'Slipstream pool not found'
        for node in list(pool.get('nodes', [])):
            ok, message = remove(name, node['ip'], callback)
            if not ok:
                return False, message
        ssh = None
        try:
            if pool.get('slipstream_relay_port'):
                # Server ownership is pool-wide and persists after the last
                # client is removed, until explicit pool deletion.
                config = plan({'ip': '127.0.0.1', 'slipstream_carrier_port': 1}, pool['kharej_server'], pool)
                ssh = connection(pool['kharej_server'])
                cleanup(ssh, config['server_files'], config['server_services'])
            from core.storage import delete_pool as delete_inventory_pool
            delete_inventory_pool(name)
            return True, 'Slipstream pool resources removed'
        except Exception as error:
            return False, str(error)
        finally:
            if ssh:
                ssh.close()
