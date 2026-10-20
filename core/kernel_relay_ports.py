"""Transactional forwarded-port edits for the integrated private-link engines.

Only relay scripts change; tunnel interfaces, keys and DNS remain untouched.
"""
import ipaddress
import re
import shlex
import uuid
from core.storage import get_pools, atomic_update, load_data
from core.transport_change import connect, mutation_lock, busy
from core.validation import validate_ports

ENGINES = {'wireguard', 'vxlan', 'gre6', 'ip6ip6', 'tun', 'dc6'}


def relay_spec(engine, node, ports):
    meta = node[engine]
    iface = meta.get('interface') or meta.get('iface')
    if not iface or not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', iface):
        raise ValueError('Invalid relay interface')
    peer = str(ipaddress.ip_address(meta['remote_private'].split('/')[0]))
    if engine == 'wireguard':
        from core.wireguard_adapter import generate_wireguard_relay
        script, _ = generate_wireguard_relay(iface, peer, ports)
        return f'/usr/local/bin/vxlb-wg-{iface}-relay.py', f'vxlb-wg-{iface}-relay.service', script
    if engine == 'vxlan':
        from core.vxlan_adapter import generate_relay_script_and_unit
        script, _ = generate_relay_script_and_unit(iface, peer, ports)
        return f'/usr/local/bin/vxlb-{iface}-relay.py', f'vxlb-vxlan-{iface}-relay.service', script
    from core.ipv6_tunnel_tools import render_relay_service
    service = f'vxlb-{engine}-{iface}-relay.service'
    script, _ = render_relay_service(service, iface, peer, ports)
    return f'/etc/vxlb/{iface}-relay.py', service, script


def node_credentials(node):
    # IPv6 link records keep credentials in inventory rather than duplicating them.
    data = load_data()
    servers = data.get('iran_servers', [])
    if isinstance(servers, dict):
        servers = servers.values()
    server = next((s for s in servers if s.get('ip') == node.get('ip')), {})
    return {**server, **{k:v for k,v in node.items() if v is not None}}


def checked(ssh, command):
    code, _, _ = ssh.execute(command, timeout=30)
    if code:
        raise RuntimeError('Relay operation failed on ' + ssh.ip)


def verify_listeners(ssh, service, ports):
    # Verify BOTH TCP and UDP sockets belong to this service, not another process.
    program = '''import subprocess,sys,time
pid=subprocess.check_output(['systemctl','show','--property=MainPID','--value',sys.argv[1]],text=True).strip()
assert pid.isdecimal() and int(pid)>0
for attempt in range(20):
 rows=subprocess.check_output(['ss','-H','-lntup'],text=True).splitlines()
 if all(any(r.split()[0]==proto and r.split()[4].endswith(':'+port) and ('pid='+pid+',') in r for r in rows) for port in sys.argv[2:] for proto in ('tcp','udp')):break
 time.sleep(0.2)
else:raise RuntimeError('Relay listener verification failed')
'''
    checked(ssh, 'python3 -c ' + shlex.quote(program) + ' ' + shlex.quote(service) + ' ' + ' '.join(map(str, ports)))


def change_ports(name, requested):
    try:
        ports = validate_ports(requested)
        if not ports:
            return False, 'At least one forwarded port is required'
        with mutation_lock():
            if busy(load_data()):
                return False, 'عملیات دیگری در حال اجراست یا نیاز به بازیابی دارد'
            pool = get_pools().get(name)
            if not pool:
                return False, 'Pool not found'
            engine = pool.get('engine') or pool.get('transport')
            if engine not in ENGINES:
                return False, 'Unsupported relay engine'
            nodes = pool.get('nodes', [])
            # Validate every node before modifying any remote host.
            specs = [(node, relay_spec(engine, node, ports)) for node in nodes]
            job_id = uuid.uuid4().hex
            sessions, backups = [], []
            def job(**fields):
                def update(data):
                    p = data['pools'][name]
                    p.setdefault('gre_update', {}).update(fields)
                atomic_update(update)
            job(status='running', kind='relay_ports', message='در حال تغییر پورت‌های رله', id=job_id, old_ports=pool.get('client_ports', []), new_ports=ports, backups=[])
            try:
                for node, (path, service, script) in specs:
                    ssh = connect(node_credentials(node))
                    sessions.append(ssh)
                    backup = path + '.ports-' + job_id
                    checked(ssh, 'cp -p -- ' + shlex.quote(path) + ' ' + shlex.quote(backup))
                    backups.append((ssh, path, backup, service))
                    job(backups=[{'ip': specs[i][0]['ip'], 'path': p, 'backup': b, 'service': svc} for i,(s,p,b,svc) in enumerate(backups)])
                    staged = path + '.new-' + job_id
                    if not ssh.write_file(staged, script):
                        raise RuntimeError('Could not stage relay configuration')
                    checked(ssh, 'python3 -m py_compile ' + shlex.quote(staged) + ' && chmod 700 ' + shlex.quote(staged) + ' && mv -- ' + shlex.quote(staged) + ' ' + shlex.quote(path))
                    checked(ssh, 'systemctl restart ' + shlex.quote(service))
                    verify_listeners(ssh, service, ports)
                def commit(data):
                    data['pools'][name]['client_ports'] = ports
                    data['pools'][name]['gre_update'].update(status='succeeded', message='پورت‌های TCP/UDP به‌روز شدند؛ شنونده‌های رله تأیید شدند')
                atomic_update(commit)
                return True, 'پورت‌های رله به‌روز شدند'
            except Exception as error:
                failures = []
                for ssh, path, backup, service in reversed(backups):
                    try:
                        checked(ssh, 'cp -p -- ' + shlex.quote(backup) + ' ' + shlex.quote(path) + ' && systemctl restart ' + shlex.quote(service))
                        verify_listeners(ssh, service, pool.get('client_ports', []))
                    except Exception:
                        failures.append(ssh.ip)
                job(status='rollback_failed' if failures else 'failed', error=str(error), rollback_failed_nodes=failures)
                return False, ('بازگردانی ناقص؛ نیاز به بازیابی: ' + ', '.join(failures)) if failures else 'تغییر پورت ناموفق بود؛ تنظیمات قبلی بازگردانده شد'
            finally:
                for ssh in sessions:
                    ssh.close()
    except (ValueError, KeyError) as error:
        return False, str(error)


def recover_ports(name):
    """Restore persisted remote backups after a crash or failed rollback."""
    with mutation_lock():
        pool = get_pools().get(name, {})
        record = pool.get('gre_update', {})
        if record.get('kind') != 'relay_ports' or record.get('status') != 'rollback_failed':
            return False, 'No relay port restoration is pending'
        failures = []
        for entry in record.get('backups', []):
            ssh = None
            try:
                node = next(n for n in pool.get('nodes', []) if n['ip'] == entry['ip'])
                ssh = connect(node_credentials(node))
                path, service, _ = relay_spec(pool['engine'], node, record['old_ports'])
                backup = path + '.ports-' + record['id']
                if (entry['path'], entry['service'], entry['backup']) != (path, service, backup):
                    raise ValueError('Invalid backup identity')
                checked(ssh, 'cp -p -- ' + shlex.quote(backup) + ' ' + shlex.quote(path) + ' && systemctl restart ' + shlex.quote(service))
                verify_listeners(ssh, service, record['old_ports'])
            except Exception:
                failures.append(entry['ip'])
            finally:
                if ssh:
                    ssh.close()
        def finish(data):
            p = data['pools'][name]
            if not failures:
                p['client_ports'] = record['old_ports']
            p['gre_update'].update(status='rollback_failed' if failures else 'failed', rollback_failed_nodes=failures, message='بازگردانی پورت‌ها ناقص است' if failures else 'پورت‌های قبلی بازگردانده شدند')
        atomic_update(finish)
        return not failures, 'بازگردانی ناقص است' if failures else 'پورت‌های قبلی بازگردانده شدند'
