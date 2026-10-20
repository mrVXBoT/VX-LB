"""Durable remote snapshots for Slipstream runtime changes and recovery.

Private keys are never included in job records. The unchanged pool inventory
remains the rollback source until every client passes a real transport probe.
"""
import copy
import re
import secrets
import shlex
import time

from core.storage import load_data, atomic_update
from core.transport_change import mutation_lock, busy
from core.validation import validate_ports, validate_port
from core import slipstream_deploy as runtime
from core.slipstream_runtime import domain_name, resolver_address
from core.kernel_relay_ports import verify_listeners

FIELDS = ('client_ports', 'domain', 'resolvers', 'dns_port', 'rate_limit')


def settings(pool):
    return {key: copy.deepcopy(pool.get(key, 1000) if key == 'rate_limit' else pool[key]) for key in FIELDS}


def candidate(pool, updates):
    if not updates or set(updates) - set(FIELDS):
        raise ValueError('Unsupported or empty Slipstream runtime update')
    if 'rate_limit' in updates and int(pool.get('slipstream_runtime_version', 1)) < 2:
        raise ValueError('This legacy Slipstream runtime requires re-provisioning before enabling the QPS limiter')
    result = copy.deepcopy(pool)
    result.update(copy.deepcopy(updates))
    result['client_ports'] = validate_ports(result['client_ports'])
    result['domain'] = domain_name(result['domain'])
    values = result['resolvers']
    if isinstance(values, str):
        values = [value.strip() for value in values.split(',') if value.strip()]
    if not isinstance(values, list) or not values:
        raise ValueError('At least one resolver is required')
    result['resolvers'] = [resolver_address(value) for value in values]
    result['dns_port'] = int(validate_port(result['dns_port']))
    from core.slipstream_firewall import validated
    validated(dict(id=result['slipstream_id'], dns_port=result['dns_port'], rate_limit=result.get('rate_limit', 1000)))
    result['rate_limit'] = int(result.get('rate_limit', 1000))
    if str(result.get('slipstream_relay_port')) in result['client_ports']:
        raise ValueError('Application port conflicts with reserved TLS backend')
    if str(result['dns_port']) in result['client_ports']:
        raise ValueError('DNS listener conflicts with application port')
    if str(result.get('slipstream_dns_backend_port')) in result['client_ports']:
        raise ValueError('Application port conflicts with protected internal DNS listener')
    for node in pool.get('nodes', []):
        if str(node.get('slipstream_carrier_port')) in result['client_ports']:
            raise ValueError('Application port conflicts with reserved DNS client carrier')
    if settings(result) == settings(pool):
        raise ValueError('No configuration change was requested')
    return result


def credentials(data, ip):
    servers = data.get('iran_servers', [])
    if isinstance(servers, dict):
        servers = servers.values()
    server = next((server for server in servers if server.get('ip') == ip), None)
    if not server:
        raise ValueError('Node SSH credentials were not found')
    return server


def check(ssh, command):
    code, _, _ = ssh.execute(command, timeout=30)
    if code:
        raise RuntimeError('Slipstream remote configuration operation failed')


def save_job(name, **values):
    def save(data):
        data['pools'][name].setdefault('gre_update', {}).update(values, updated_at=time.time())
    atomic_update(save)


def changes(pool, changed):
    entries = []
    for index, node in enumerate(pool['nodes']):
        previous = runtime.plan(node, pool['kharej_server'], pool)
        updated = runtime.plan(node, changed['kharej_server'], changed)
        roles = ['server', 'client'] if index == 0 else ['client']
        for role in roles:
            before, after = previous[role+'_files'], updated[role+'_files']
            modified = {path: content for path, content in after.items() if before.get(path) != content}
            if not modified:
                continue
            services = updated[role+'_services']
            # Port-only JSON changes restart the secure relay, leaving DNS
            # carrier processes running. Domain/resolver changes restart both.
            if not any(path.endswith('.service') for path in modified):
                services = [name for name in services if (name.endswith('-secure.service') and (role == 'client' or any(path.endswith(('/server.json', '/relay.py')) for path in modified))) or (name.endswith('-guard.service') and any(path.endswith(('/guard.json', '/guard.py')) for path in modified))]
            entries.append(dict(role=role, ip=pool['kharej_server']['ip'] if role == 'server' else node['ip'],
                                files=modified, services=services, firewall=any(path.endswith('/firewall.json') for path in modified)))
    if not entries:
        raise ValueError('No runtime artifact changed')
    return entries


def apply_firewall(ssh, entry):
    if entry.get('firewall'):
        path = next(path for path in entry['files'] if path.endswith('/firewall.json'))
        check(ssh, 'python3 ' + shlex.quote(path.rsplit('/', 1)[0]+'/firewall.py') + ' apply ' + shlex.quote(path))


def refresh_clients_after_server_restart(pool, entries, sessions):
    if not any(entry['role'] == 'server' and any(name.endswith(('-dns.service', '-guard.service')) for name in entry['services']) for entry in entries):
        return
    already = {entry['ip'] for entry in entries if entry['role'] == 'client' and any(name.endswith(('-dns.service', '-guard.service')) for name in entry['services'])}
    for node in pool['nodes']:
        if node['ip'] not in already:
            config = runtime.plan(node, pool['kharej_server'], pool)
            check(sessions[('client', node['ip'])], 'systemctl restart ' + ' '.join(map(shlex.quote, config['client_services'])))


def verify(pool, sessions):
    for node in pool['nodes']:
        ssh = sessions[('client', node['ip'])]
        config = runtime.plan(node, pool['kharej_server'], pool)
        verify_listeners(ssh, config['client_services'][1], pool['client_ports'])
        result = runtime.probe(ssh, config['client_config_path'])
        if not result.get('passed'):
            raise RuntimeError('Authenticated Slipstream path did not pass after configuration change')


def prune_snapshots(name, job, sessions):
    failures = []
    for entry in job.get('backups', []):
        ssh = sessions.get((entry['role'], entry['ip']))
        if ssh is None:
            failures.append(entry['ip'])
            continue
        paths = [value for item in entry['files'] for value in (item['backup'], item['path']+'.restore-'+job['id'])]
        try:
            check(ssh, 'rm -f -- ' + ' '.join(map(shlex.quote, paths)))
        except Exception:
            failures.append(entry['ip'])
    try:
        save_job(name, backup_cleanup_pending=sorted(set(failures)))
    except Exception:
        # Cleanup bookkeeping must never roll back a committed runtime.
        return False
    return not failures


def restore(name, pool, job, sessions):
    failures = []
    snapshots = job.get('backups', [])
    # Restore server first so clients can immediately verify the old path.
    ordered = [] if job.get('phase') == 'snapshotting' else sorted(snapshots, key=lambda entry: entry['role'] != 'server')
    for entry in ordered:
        try:
            ssh = sessions[(entry['role'], entry['ip'])]
            for item in entry['files']:
                staged = item['path'] + '.restore-' + job['id']
                check(ssh, 'test -f ' + shlex.quote(item['backup']) + ' && cp -p -- ' + shlex.quote(item['backup']) + ' ' + shlex.quote(staged) + ' && mv -f -- ' + shlex.quote(staged) + ' ' + shlex.quote(item['path']))
            if entry['services']:
                check(ssh, 'systemctl daemon-reload && systemctl restart ' + ' '.join(map(shlex.quote, entry['services'])))
            apply_firewall(ssh, {**entry, 'files': {item['path']: '' for item in entry['files']}})
        except Exception:
            failures.append(entry['ip'])
    if not failures:
        try:
            refresh_clients_after_server_restart(pool, ordered, sessions)
            verify(pool, sessions)
        except Exception:
            failures.append('data-path')
    def finish(data):
        target = data['pools'][name]
        if not failures:
            target.update(settings(pool))
            from core.composition_schema import deconstruct_legacy_pool
            target['composition'] = deconstruct_legacy_pool(target).to_dict()
        target['gre_update'].update(status='rollback_failed' if failures else 'failed',
            message='بازگردانی Slipstream کامل نشد' if failures else 'تنظیمات قبلی Slipstream بازگردانده و مسیر داده تأیید شد',
            rollback_failed_nodes=sorted(set(failures)), updated_at=time.time())
    atomic_update(finish)
    if not failures:
        prune_snapshots(name, job, sessions)
    return not failures


def open_sessions(data, pool):
    sessions = {}
    try:
        sessions[('server', pool['kharej_server']['ip'])] = runtime.connection(pool['kharej_server'])
        for node in pool['nodes']:
            sessions[('client', node['ip'])] = runtime.connection(credentials(data, node['ip']))
        return sessions
    except Exception:
        for ssh in sessions.values():
            ssh.close()
        raise


def change(name, updates):
    sessions = {}
    try:
        with mutation_lock():
            data = load_data()
            if busy(data):
                return False, 'عملیات دیگری در حال اجراست یا بازگردانی لازم است'
            pool = data.get('pools', {}).get(name)
            if not pool or pool.get('engine') != 'slipstream':
                return False, 'Slipstream pool not found'
            if not pool.get('nodes') or any(node.get('provisioning') for node in pool['nodes']):
                return False, 'All Slipstream nodes must be provisioned before changing runtime settings'
            changed = candidate(pool, updates)
            from core.load_balancer import LoadBalancerManager
            ok, message = LoadBalancerManager.check_port_conflicts(changed['client_ports'], [node['ip'] for node in pool['nodes']], exclude_pool_name=name)
            if not ok:
                return False, message
            specs = changes(pool, changed)
            for node in pool['nodes']:
                credentials(data, node['ip'])  # Preflight all credentials first.
            sessions = open_sessions(data, pool)
            if changed['dns_port'] != pool['dns_port']:
                from core.paqet_probe import reserve_probe_port
                dns_host = pool['kharej_server']['ip'] if int(pool.get('slipstream_runtime_version', 1)) >= 3 else '0.0.0.0'
                chosen = reserve_probe_port(sessions[('server', pool['kharej_server']['ip'])], [], preferred=changed['dns_port'], bind_host=dns_host)
                if chosen != changed['dns_port']:
                    return False, 'Requested destination DNS port is occupied'
            job = dict(kind='slipstream_runtime', id=secrets.token_hex(16), status='running',
                       old_settings=settings(pool), new_settings=settings(changed), backups=[],
                       message='در حال تغییر مرحله‌ای تنظیمات Slipstream', phase='snapshotting', error='')
            save_job(name, **job)
            try:
                # Snapshot EVERY changed file before mutating ANY host. Persist
                # the snapshot intent first, so a crash cannot orphan it.
                for spec in specs:
                    entry = dict(role=spec['role'], ip=spec['ip'], services=spec['services'], firewall=spec['firewall'],
                                 files=[dict(path=path, backup=path+'.slip-'+job['id']) for path in spec['files']])
                    job['backups'].append(entry)
                    save_job(name, backups=copy.deepcopy(job['backups']))
                    ssh = sessions[(spec['role'], spec['ip'])]
                    for item in entry['files']:
                        check(ssh, 'cp -p -- ' + shlex.quote(item['path']) + ' ' + shlex.quote(item['backup']))
                save_job(name, phase='applying')
                job['phase'] = 'applying'
                for spec in specs:
                    runtime.deploy(sessions[(spec['role'], spec['ip'])], spec['files'], spec['services'])
                    apply_firewall(sessions[(spec['role'], spec['ip'])], spec)
                refresh_clients_after_server_restart(changed, specs, sessions)
                verify(changed, sessions)
                def commit(current):
                    target = current['pools'][name]
                    target.update(settings(changed))
                    from core.composition_schema import deconstruct_legacy_pool
                    target['composition'] = deconstruct_legacy_pool(target).to_dict()
                    target['gre_update'].update(status='succeeded', message='تنظیمات Slipstream و مسیر داده تأیید شدند', error='')
                atomic_update(commit)
                prune_snapshots(name, job, sessions)
                return True, 'Slipstream configuration changed; authenticated data path and TCP/UDP listeners verified'
            except Exception:
                save_job(name, error='Slipstream runtime change failed; restoring persisted remote snapshots')
                restored = restore(name, pool, job, sessions)
                return False, 'تغییر ناموفق بود؛ تنظیمات قبلی و مسیر داده بازگردانده شد' if restored else 'بازگردانی کامل نشد؛ بازیابی را اجرا کنید'
    except (ValueError, KeyError, RuntimeError) as error:
        return False, str(error)
    finally:
        for ssh in sessions.values():
            ssh.close()


def recover(name):
    sessions = {}
    try:
        with mutation_lock():
            data = load_data()
            pool = data.get('pools', {}).get(name, {})
            job = pool.get('gre_update', {})
            if job.get('kind') != 'slipstream_runtime' or job.get('status') != 'rollback_failed':
                return False, 'No Slipstream runtime recovery is pending'
            if not re.fullmatch(r'[0-9a-f]{32}', str(job.get('id', ''))):
                return False, 'Invalid Slipstream recovery identity'
            old = copy.deepcopy(pool)
            old.update(job['old_settings'])
            new = copy.deepcopy(pool)
            new.update(job['new_settings'])
            expected = changes(old, new)
            allowed = {(entry['role'], entry['ip']): entry for entry in expected}
            actual = [(entry['role'], entry['ip']) for entry in job['backups']]
            if len(actual) != len(set(actual)) or (job.get('phase') != 'snapshotting' and set(actual) != set(allowed)):
                raise ValueError('Slipstream recovery snapshot set is incomplete')
            for entry in job['backups']:
                spec = allowed[(entry['role'], entry['ip'])]
                files = [dict(path=path, backup=path+'.slip-'+job['id']) for path in spec['files']]
                if entry['files'] != files or entry['services'] != spec['services'] or bool(entry.get('firewall')) != spec['firewall']:
                    raise ValueError('Slipstream recovery snapshot does not match owned artifacts')
            sessions = open_sessions(data, old)
            ok = restore(name, old, job, sessions)
            return ok, 'تنظیمات قبلی Slipstream بازگردانده شد' if ok else 'بازگردانی Slipstream کامل نشد'
    except (KeyError, ValueError, RuntimeError) as error:
        return False, str(error)
    finally:
        for ssh in sessions.values():
            ssh.close()
