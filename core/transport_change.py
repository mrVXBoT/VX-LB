"""Rolling transport changes with durable remote backups and conservative flow checks."""
import copy
import fcntl
import importlib
import os
import re
import shlex
import threading
import time
import uuid
import json
import subprocess
import secrets
from contextlib import contextmanager
from core.storage import DATA_DIR, load_data, atomic_update
from core.ssh_client import SSHManager
from core.tunnel import SUPPORTED_TRANSPORTS
from core.dns_routing import routing_lock
from core.tunnel_probe import TunnelProbe, add_probe_route
from core.pool_workflow import validate_options, pool_ready, creation_options, preserve_settings, validate_engine_target

ACTIVE = {'queued', 'preflight', 'changing', 'validating', 'rolling_back', 'rollback_failed'}
_lock = threading.RLock()
_mutation_local = threading.local()

@contextmanager
def mutation_lock():
    with _lock:
        depth = getattr(_mutation_local, 'depth', 0)
        if depth > 0:
            _mutation_local.depth = depth + 1
            try:
                yield
            finally:
                _mutation_local.depth -= 1
            return

        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        fd = os.open(os.path.join(DATA_DIR, 'pool-mutation.lock'), os.O_CREAT | os.O_RDWR, 0o600)
        _mutation_local.depth = 1
        _mutation_local.fd = fd
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            _mutation_local.depth = 0
            _mutation_local.fd = None
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

def busy(data=None):
    data = data if data is not None else load_data()
    if any(job.get('status') in {'queued', 'running'} and job.get('id') != getattr(_mutation_local, 'job_id', None) for job in data.get('link_tasks', {}).values()):
        return True
    if any(job.get('status') in {'queued','running'} and job.get('id') != getattr(_mutation_local, 'job_id', None) for job in data.get('pool_tasks', {}).values()):
        return True
    if any(job.get('status') in {'queued', 'running'} and job.get('id') != getattr(_mutation_local, 'job_id', None) for job in data.get('pool_creations', {}).values()):
        return True
    if any((pool.get('transport_change') or {}).get('status') in ACTIVE for pool in data.get('pool_backups', {}).values()):
        return True
    return any((pool.get('gre_update') or {}).get('status') in {'running','rollback_failed'} or (pool.get('transport_change') or {}).get('status') in ACTIVE or any(job.get('status') in {'queued', 'running'} for job in list(pool.get('node_removals', {}).values()) + list(pool.get('node_additions', {}).values())) for pool in (data if data is not None else load_data()).get('pools', {}).values())

def update_job(name, **fields):
    def update(data):
        pool = data.get('pools', {}).get(name) or data.get('pool_backups', {}).get(name)
        if pool is None: raise RuntimeError('استخر حذف شده است')
        pool['transport_change'].update(fields, updated_at=time.strftime('%Y-%m-%d %H:%M:%S'))
        backup = data.get('pool_backups', {}).get(name)
        if backup and (backup.get('transport_change') or {}).get('id') == pool['transport_change'].get('id'):
            backup['transport_change'].update(copy.deepcopy(fields))
    atomic_update(update)


def force_clear_change(name: str) -> tuple:
    """Abandon a wedged transport-change job (manual recovery).

    Only valid when the job is in terminal 'rollback_failed' state -- e.g.
    the node will never come back (decommissioned server) so rollback can
    never succeed and the pool would otherwise stay locked forever.
    Records the abandonment in the job history instead of silently deleting.
    Returns (ok, message).
    """
    from core.storage import load_data as _load
    pool = _load().get('pools', {}).get(name)
    if pool is None:
        return False, 'استخر یافت نشد'
    job = pool.get('transport_change') or {}
    if job.get('status') != 'rollback_failed':
        return False, 'فقط کارهای rollback_failed قابل رها کردن هستند'
    failed = job.get('failed_nodes', [])

    def _clear(data):
        p = data.get('pools', {}).get(name)
        if p is None:
            return
        history = p.setdefault('transport_change_history', [])
        history.append({
            'abandoned_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'reason': 'force-cleared by operator',
            'failed_nodes': failed,
            'job': {k: job.get(k) for k in ('target', 'status', 'message')},
        })
        p.pop('transport_change', None)
        backup = data.get('pool_backups', {}).pop(name, None)
        if backup:
            backup.pop('transport_change', None)
            data.setdefault('abandoned_pool_backups', {})[name] = backup

    atomic_update(_clear)
    return True, f'قفل transport استخر {name} رها شد ({len(failed)} نود ناموفق در تاریخچه ثبت شد)'

def replace_transport(content, old, new):
    pattern = r'(?m)^(\s*transport\s*=\s*)"([^"\n]+)"([ \t]*(?:#.*)?)$'
    matches = list(re.finditer(pattern, content))
    if len(matches) != 1 or matches[0].group(2) != old:
        raise RuntimeError('نوع تونل فایل با اطلاعات استخر یکسان نیست؛ تغییر متوقف شد')
    return re.sub(pattern, lambda match: match.group(1) + '"' + new + '"' + match.group(3), content)

def check(ssh, command):
    code, output, _ = ssh.execute(command, timeout=100 if command.startswith('systemctl restart ') else 15)
    if code != 0: raise RuntimeError('فرمان '+command.split()[0]+' روی '+ssh.ip+' ناموفق بود (کد '+str(code)+')')
    return output

def connect(server):
    address = server['ip']
    try:
        interfaces = json.loads(subprocess.check_output(['ip', '-j', 'addr'], timeout=5))
        local_addresses = {entry['local'] for interface in interfaces for entry in interface.get('addr_info', [])}
        if address in local_addresses:
            address = '127.0.0.1' if ':' not in address else '::1'
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    ssh = SSHManager(address, server.get('port',22), server.get('username','root'), server.get('password'))
    ok, _ = ssh.connect()
    if not ok: ssh.close(); raise RuntimeError('اتصال SSH به یکی از سرورها ناموفق بود')
    return ssh

def unit_name(node):
    name = node.get('node_name', '')
    if not re.fullmatch(r'[a-zA-Z0-9_.-]+', name): raise RuntimeError('نام سرویس تونل نامعتبر است')
    return 'backpack-' + name + '.service'

def active(ssh, unit):
    return check(ssh, 'systemctl is-active ' + shlex.quote(unit)).strip() == 'active'

def counters(output, pid, ports):
    samples = {}
    lines = output.splitlines()
    for index, line in enumerate(lines):
        parts = line.split()
        if len(parts) < 5 or parts[0] != 'ESTAB' or f'pid={pid},' not in line: continue
        if parts[3].rsplit(':',1)[-1] not in ports: continue
        info = lines[index+1] if index+1 < len(lines) else ''
        rx = re.search(r'\bbytes_received:(\d+)', info)
        ack = re.search(r'\bbytes_acked:(\d+)', info)
        if rx and ack: samples[(parts[3],parts[4])] = (int(rx.group(1)),int(ack.group(1)))
    return samples

def verify_flow(iran, kharej, unit, ports, timeout=45):
    """Only traffic on sockets owned by the restarted service can confirm success."""
    pid = check(iran, 'systemctl show -p MainPID --value ' + shlex.quote(unit)).strip()
    if not pid.isdigit() or pid == '0': return False
    deadline = time.monotonic() + timeout
    previous = {}
    while time.monotonic() < deadline:
        if not active(iran,unit) or not active(kharej,unit): return False
        if check(iran,'systemctl show -p MainPID --value ' + shlex.quote(unit)).strip() != pid: return False
        samples = counters(check(iran, 'ss -tinp'), pid, set(str(p) for p in ports))
        for key, (rx, ack) in samples.items():
            old = previous.get(key)
            if old and rx > old[0] and ack > old[1] and rx >= 128 and ack >= 128: return True
        previous = samples
        time.sleep(2)
    return False

def verify_control(iran, kharej, unit, timeout=45):
    """Require control establishment from each current process, never old logs."""
    deadline = time.monotonic() + timeout
    while True:
        ready = True
        for ssh in (iran, kharej):
            if not active(ssh, unit): return False
            pid = check(ssh, 'systemctl show -p MainPID --value ' + shlex.quote(unit)).strip()
            if not pid.isdigit() or pid == '0': return False
            started = check(ssh, 'systemctl show -p ExecMainStartTimestamp --value ' + shlex.quote(unit)).strip()
            code, logs, _ = ssh.execute('journalctl -u ' + shlex.quote(unit) + ' _PID=' + pid + ' --since ' + shlex.quote(started) + ' --no-pager -o cat --grep control -n 100', timeout=15)
            if code not in (0, 1): return False
            events = [line for line in logs.splitlines() if re.search(r'control channel.*(?:established|closed)|failed.*control|failed to receive control', line, re.I)]
            if not events or not re.search(r'control channel.*established', events[-1], re.I): ready = False
        if ready: return True
        if time.monotonic() >= deadline: return False
        time.sleep(1)

def write_and_restart(iran, kharej, unit, path, contents):
    errors = []
    for ssh, content in zip((iran, kharej), contents):
        try:
            apply_file(ssh, path, content)
            check(ssh, 'systemctl restart ' + shlex.quote(unit))
        except Exception as error:
            errors.append(error)
    if errors: raise RuntimeError('نوشتن یا راه‌اندازی یکی از دو سمت ناموفق بود: '+str(errors[0]))

def install_and_verify(iran, kharej, unit, path, contents, diagnostics=None):
    # Restore/install both sides even when starting the probe fails.
    write_and_restart(iran, kharej, unit, path, contents)
    passed = False
    with TunnelProbe(iran, kharej) as probe:
        try:
            probe_contents = [add_probe_route(contents[0], probe.listen_port, probe.backend_port), contents[1]]
            write_and_restart(iran, kharej, unit, path, probe_contents)
            control_ok = verify_control(iran, kharej, unit)
            passed = control_ok and probe.verify()
            if not passed and diagnostics is not None:
                diagnostics.append("کانال کنترل بین دو سرور برقرار نشد" if not control_ok else
                                   "کانال کنترل برقرار شد، اما انتقال دوطرفهٔ ۶۴ کیلوبایت داده تأیید نشد")
        finally:
            # Try both endpoints even if restoring one fails.
            write_and_restart(iran, kharej, unit, path, contents)
    if not passed:
        return False
    restored = verify_control(iran, kharej, unit)
    if not restored and diagnostics is not None:
        diagnostics.append("پس از بازگردانی پورت‌های واقعی، کانال کنترل برقرار نشد")
    return restored

def apply_file(ssh, path, content):
    staged = path + '.vxlb-new'
    if not ssh.write_file(staged, content): raise RuntimeError('نوشتن تنظیمات جدید ناموفق بود')
    check(ssh, 'chmod 600 ' + shlex.quote(staged) + ' && mv -- ' + shlex.quote(staged) + ' ' + shlex.quote(path))

def rollback(name, pool, job):
    update_job(name,status='rolling_back',message='بازگردانی تنظیمات قبلی دو سمت')
    failures = []
    servers = {node['node_name']:node for node in pool['nodes']}
    for record in reversed(job.get('changed', [])):
        node = servers.get(record['node_name'])
        if not node: failures.append(record['node_name']); continue
        sessions = []
        try:
            contents = []
            for server in (node, pool['kharej_server']):
                ssh = connect(server); sessions.append(ssh)
                contents.append(check(ssh, 'cat -- ' + shlex.quote(record['backup'])))
            if not install_and_verify(sessions[0], sessions[1], record['unit'], record['path'], contents):
                raise RuntimeError('اتصال و عبور ترافیک پس از بازگشت تأیید نشد')
        except Exception:
            failures.append(record['node_name'])
        finally:
            for ssh in sessions: ssh.close()
    if failures:
        update_job(name,status='rollback_failed',message='سلامت اتصال پس از بازگردانی تأیید نشد؛ عملیات دیگر قفل است. رسیدگی یا بازگردانی دوباره لازم است.', failed_nodes=sorted(set(failures)))
        return False
    update_job(name,status='rolled_back',message='تنظیمات قبلی بازگردانده و عبور آزمایشی ترافیک همهٔ نودهای تغییرکرده تأیید شد', failed_nodes=[])
    return True

def get_engine_for_transport(transport: str) -> str:
    if not transport:
        return 'backpack'
    t = str(transport).strip().lower()
    if t in {'http', 'https'}:
        return t
    if t == 'waterwall':
        return 'waterwall'
    if t == 'gost':
        return 'gost'
    if t == 'frp':
        return 'frp'
    if t == 'hedioum':
        return 'hedioum'
    if t == 'rathole':
        return 'rathole'
    if t == 'candy-spoof':
        return 'candy-spoof'
    if t == 'parsaksh':
        return 'parsaksh'
    if t == 'paqet':
        return 'paqet'
    if t == 'wireguard':
        return 'wireguard'
    if t in {'geneve', 'geneve_ipsec'}:
        return 'geneve'
    if t == 'vxlan':
        return 'vxlan'
    if t == 'vxlan_ipsec':
        return 'vxlan_ipsec'
    if t == 'gre6':
        return 'gre6'
    if t == 'ip6ip6':
        return 'ip6ip6'
    if t == 'gre':
        return 'gre'
    if t == 'tun':
        return 'tun'
    if t == 'dc6':
        return 'dc6'
    if t == 'slipstream':
        return 'slipstream'
    from core.spoof_adapter import SPOOF_TRANSPORTS as _SPOOF_TRANSPORTS
    if t in _SPOOF_TRANSPORTS:
        return 'spoof'
    return 'backpack'

# Kernel / network-layer engines that support per-node phased migration. The web
# UI also exposes "kernel" as a *group* label (ENGINE_TRANSPORTS.kernel) that is
# not itself a registered engine; it must be resolved to the concrete engine of
# the chosen transport before production-readiness validation.
KERNEL_ENGINES = {
    'tun', 'dc6', 'wireguard', 'gre', 'gre6', 'ip6ip6',
    'vxlan', 'vxlan_ipsec', 'geneve', 'geneve_ipsec',
}

def _coerce_engine(engine_id, transport):
    """Resolve an engine id that may be a UI group label to a registered engine.

    Group labels like "kernel" / "other" are not real engines; fall back to the
    concrete engine implied by the transport whenever the provided id is not
    itself registered.
    """
    eid = str(engine_id or '').lower().strip()
    if eid and eid not in ('kernel', 'other'):
        return {'gre_ipv4': 'gre', 'geneve_ipsec': 'geneve'}.get(eid, eid)
    return get_engine_for_transport(transport)

def _engine_module(engine):
    table = {
        'tun': 'core.tun_runtime',
        'dc6': 'core.dc6_runtime',
        'wireguard': 'core.wireguard_adapter',
        'gre': 'core.gre',
        'gre6': 'core.gre6',
        'ip6ip6': 'core.ip6ip6',
        'vxlan': 'core.vxlan_adapter',
        'vxlan_ipsec': 'core.vxlan_ipsec',
        'geneve': 'core.geneve',
        'geneve_ipsec': 'core.geneve',
        'waterwall': 'core.waterwall',
        'gost': 'core.gost_engine',
        'frp': 'core.frp_engine',
        'hedioum': 'core.hedioum_engine',
        'rathole': 'core.rathole_engine',
        'candy-spoof': 'core.candy_spoof_transport',
        'parsaksh': 'core.parsaksh_transport',
        'paqet': 'core.paqet_engine',
        'slipstream': 'core.slipstream_adapter',
        'spoof': 'core.spoof_adapter',
        'http': 'core.http_transport',
        'https': 'core.http_transport',
    }
    name = table.get((engine or '').lower().strip())
    if not name:
        return None
    return importlib.import_module(name)

def _remove_node_engine(name, node, engine, pool):
    """Tear down a single node's link for the given engine and drop it from the pool."""
    engine = (engine or '').lower().strip()
    if engine in ('', 'backpack'):
        from core.load_balancer import stop_and_remove_tunnel
        sessions = []
        try:
            node_name = node.get('node_name')
            if node_name:
                kh = connect(pool['kharej_server'])
                sessions.append(kh)
                kh_removed = stop_and_remove_tunnel(kh, node_name)
                ir = connect(node)
                sessions.append(ir)
                ir_removed = stop_and_remove_tunnel(ir, node_name)
                if not kh_removed or not ir_removed:
                    return False, 'حذف سرویس BackPack در یکی از دو سمت تأیید نشد'
        finally:
            for s in sessions:
                s.close()
        def discard(data):
            data['pools'][name]['nodes'] = [
                n for n in data['pools'][name]['nodes'] if n.get('ip') != node.get('ip')
            ]
        atomic_update(discard)
        return True, ''
    mod = _engine_module(engine)
    if mod is None or not hasattr(mod, 'remove'):
        return False, 'موتور منبع برای حذف مرحله‌ای پشتیبانی نمی‌شود: ' + str(engine)
    return mod.remove(name, node.get('ip'))

def _deploy_node(name, server, callback=None):
    """Deploy a single node onto the pool using the pool's current engine."""
    from core.load_balancer import LoadBalancerManager
    return LoadBalancerManager.add_node(name, server, callback)

def _resolve_server(server_dict, server_type):
    from core.storage import get_servers
    servers = get_servers(server_type)
    for s in servers:
        if s.get('ip') == server_dict.get('ip'):
            merged = dict(s)
            merged.update({k: v for k, v in server_dict.items() if v is not None})
            return merged
    return dict(server_dict)

def teardown_pool_runtime(pool):
    """Remove owned links and report failures instead of discarding them."""
    engine = pool.get('engine') or get_engine_for_transport(pool.get('transport'))
    failures = []
    for node in list(pool.get('nodes', [])):
        try:
            ok, message = _remove_node_engine(pool['name'], node, engine, pool)
            if not ok:
                failures.append(f"{node.get('ip')}: {message}")
        except Exception as error:
            failures.append(f"{node.get('ip')}: {error}")
    if failures:
        raise RuntimeError('; '.join(failures))


def _run_backpack_rolling_change(name, pool, job, recovering):
    if recovering:
        rollback(name, pool, job)
        return
    sessions = []
    prepared = []
    changed = []
    try:
        update_job(name, status='preflight', message='بررسی دسترسی، سرویس‌ها و نسخهٔ پشتیبان همهٔ نودها')
        kh = connect(pool['kharej_server'])
        sessions.append(kh)
        for node in pool['nodes']:
            ir = connect(node)
            sessions.append(ir)
            unit = unit_name(node)
            path = '/etc/backpack/' + node['node_name'] + '.toml'
            backup = path + '.vxlb-' + job['id'] + '.bak'
            if not active(ir, unit) or not active(kh, unit):
                raise RuntimeError('سرویس قبلی یکی از نودها فعال نیست؛ قبل از تغییر آن را اصلاح کنید')
            contents = []
            originals = []
            for ssh in (ir, kh):
                original = check(ssh, 'cat -- ' + shlex.quote(path))
                originals.append(original)
                contents.append(replace_transport(original, job['from'], job['to']))
                check(ssh, 'cp -- ' + shlex.quote(path) + ' ' + shlex.quote(backup) + ' && chmod 600 ' + shlex.quote(backup))
            prepared.append((node, ir, kh, unit, path, backup, contents, originals))
        for index, (node, ir, kh, unit, path, backup, contents, originals) in enumerate(prepared):
            changed.append({'node_name': node['node_name'], 'unit': unit, 'path': path, 'backup': backup})
            update_job(name, status='changing', changed=changed, completed=index, total=len(prepared), message='تغییر دو سمت نود: ' + node.get('server_name', node['ip']))
            if not job.get('repair'):
                update_job(name, status='validating', message='آزمون مستقل اتصال قبلی نود: ' + node.get('server_name', node['ip']))
                if not install_and_verify(ir, kh, unit, path, originals):
                    raise RuntimeError('آزمون اتصال قبلی نود ناموفق بود؛ نوع جدید اعمال نشد: ' + node['node_name'])
            update_job(name, status='validating', message='آزمون مستقل عبور ترافیک از نود: ' + node.get('server_name', node['ip']))
            if not install_and_verify(ir, kh, unit, path, contents):
                raise RuntimeError('کانال کنترل یا آزمون مستقل عبور ترافیک تأیید نشد؛ بازگشت به نوع قبلی')
            update_job(name, completed=index + 1)
        def commit(data):
            data['pools'][name]['transport'] = job['to']
            for member in data['pools'][name]['nodes']:
                member.pop('transport', None)
            data['pools'][name]['transport_change'].update(status='succeeded', message='نوع تونل همهٔ نودها تغییر کرد و عبور ترافیک تأیید شد', completed=len(prepared))
        atomic_update(commit)
    except (Exception, KeyboardInterrupt) as error:
        error_message = str(error) or 'عملیات قطع شد؛ بازگردانی تنظیمات قبلی'
        update_job(name, error=error_message)
        if changed:
            rollback(name, pool, load_data()['pools'][name]['transport_change'])
        else:
            update_job(name, status='failed', message=error_message)
    finally:
        for ssh in sessions:
            ssh.close()

def _finish_universal(name, original, job, deployed, status, error=''):
    def commit(data):
        pool = copy.deepcopy(deployed)
        preserve_settings(pool, original)
        pool['transport_change'] = dict(job, status=status, error=error,
            completed=len(pool.get('nodes', [])), total=len(original['nodes']),
            message='تونل جدید روی همهٔ نودها راه‌اندازی شد' if status == 'succeeded' else 'تونل قبلی روی همهٔ نودها بازگردانده شد')
        data.setdefault('pools', {})[name] = pool
        data.get('pool_backups', {}).pop(name, None)
    atomic_update(commit)


def _universal_failed(name, original, job, error):
    def record(data):
        pool = data.setdefault('pools', {}).setdefault(name, copy.deepcopy(original))
        pool['transport_change'] = dict(job, status='rollback_failed', error=str(error),
            message='بازگردانی کامل نشد؛ نسخهٔ پشتیبان حفظ شده و عملیات قفل است')
        for node in pool.get('nodes', []):
            node.update(provisioning=True, status='FAILED', reason='نیازمند بازیابی تونل')
    atomic_update(record)


def _restore_universal(name, original, job, error):
    from core.load_balancer import LoadBalancerManager
    try:
        partial = load_data().get('pools', {}).get(name)
        if partial:
            teardown_pool_runtime(partial)
        # The source remains durable in pool_backups throughout reconstruction.
        atomic_update(lambda data: data.setdefault('pools', {}).pop(name, None))
        kharej = _resolve_server(original['kharej_server'], 'kharej')
        servers = [_resolve_server(node, 'iran') for node in original['nodes']]
        ok, message, restored = LoadBalancerManager.create_pool(
            pool_name=name, kharej_server=kharej, iran_servers=servers,
            transport=original['transport'], client_ports=original['client_ports'],
            **creation_options(original))
        restored = load_data().get('pools', {}).get(name) or restored
        if not ok or not pool_ready(restored, servers):
            raise RuntimeError(message or 'بازگردانی همهٔ نودها تأیید نشد')
        _finish_universal(name, original, job, restored, 'rolled_back', str(error))
    except Exception as rollback_error:
        _universal_failed(name, original, job, str(error) + '; rollback: ' + str(rollback_error))


def _run_universal_engine_change(name, pool, job, recovering=False):
    from core.load_balancer import LoadBalancerManager
    original = copy.deepcopy(load_data().get('pool_backups', {}).get(name) or pool)
    if recovering:
        _restore_universal(name, original, job, job.get('error', 'Interrupted migration'))
        return
    sessions = []
    try:
        options = dict(job.get('arguments') or {})
        if job.get('from_engine') == job.get('to_engine') and original.get('camouflage'):
            options['camouflage'] = dict(original['camouflage'], **(options.get('camouflage') or {}))
        if job['to'] == 'waterwall':
            from core.waterwall import profile
            settings = dict(options.get('camouflage') or {})
            mode = settings.get('mode', 'trojan')
            if mode in {'trojan', 'reality'} and not settings.get('password'):
                settings['password'] = secrets.token_hex(12)
            profile(mode, settings)
            options['camouflage'] = dict(settings, mode=mode)
        validate_options(job['to'], options)
        update_job(name, status='preflight', message='بررسی دسترسی به همهٔ سرورها')
        kharej = _resolve_server(original['kharej_server'], 'kharej')
        servers = [_resolve_server(node, 'iran') for node in original['nodes']]
        for server in [kharej, *servers]:
            sessions.append(connect(server))
        error = _validate_target_prerequisites(job.get('to_engine'), job['to'], kharej, servers, sessions, options)
        if error:
            raise ValueError(error)
    except Exception as error:
        update_job(name, status='failed', message='بررسی پیش از تغییر ناموفق بود', error=str(error))
        return
    finally:
        for session in sessions:
            session.close()

    # Persist BEFORE the first destructive command, including source options.
    atomic_update(lambda data: data.setdefault('pool_backups', {}).__setitem__(name, copy.deepcopy(original)))
    try:
        update_job(name, status='changing', message='پاک‌سازی تونل قبلی')
        teardown_pool_runtime(original)
    except Exception as error:
        _universal_failed(name, original, job, error)
        return
    try:
        atomic_update(lambda data: data['pools'].pop(name, None))
        ok, message, deployed = LoadBalancerManager.create_pool(
            pool_name=name, kharej_server=kharej, iran_servers=servers,
            transport=job['to'], client_ports=original['client_ports'], **options)
        deployed = load_data().get('pools', {}).get(name) or deployed
        if not ok or not pool_ready(deployed, servers):
            raise RuntimeError(message or 'همهٔ نودهای تونل جدید آماده نیستند')
        _finish_universal(name, original, job, deployed, 'succeeded')
    except Exception as error:
        _restore_universal(name, original, job, error)


def _kernel_rollback(name, backup_pool, to_engine, from_engine, target):
    """Restore every checkpointed node and retain the backup on any failure."""
    failures = []
    job = load_data()['pools'][name].get('transport_change', {})
    changed = list(job.get('changed', []))
    blocked = set()
    update_job(name, status='rolling_back', message='بازگردانی نودهای تغییرکرده')
    for record in reversed(changed):
        ip = record.get('ip')
        current = next((node for node in load_data()['pools'][name].get('nodes', []) if node.get('ip') == ip), None)
        if current is None:
            continue
        engine = current.get('engine') or (from_engine if current.get('node_name') == (record.get('backup') or {}).get('node_name') else to_engine)
        try:
            ok, message = _remove_node_engine(name, current, engine, backup_pool)
            if not ok:
                raise RuntimeError(message)
        except Exception as error:
            blocked.add(ip)
            failures.append(str(error))

    def restore_metadata(data):
        pool = data['pools'][name]
        nodes = pool.get('nodes', [])
        current_job = pool['transport_change']
        pool.clear()
        pool.update(copy.deepcopy(backup_pool))
        pool['nodes'] = nodes
        pool['transport_change'] = current_job
    atomic_update(restore_metadata)

    for record in reversed(changed):
        if record.get('ip') in blocked:
            continue
        server = _resolve_server(record.get('backup') or record, 'iran')
        server.setdefault('name', server.get('server_name') or server.get('ip'))
        try:
            ok, message = _deploy_node(name, server)
            node = next((node for node in load_data()['pools'][name].get('nodes', []) if node.get('ip') == server['ip']), None)
            if not ok or not pool_ready({'nodes': [node] if node else []}, [server]):
                raise RuntimeError(message or 'بازگردانی نود تأیید نشد')
        except Exception as error:
            failures.append(str(error))
    if not pool_ready(load_data()['pools'][name], backup_pool['nodes']):
        failures.append('همهٔ اعضای استخر قبلی آماده نیستند')
    if failures:
        def mark_unready(data):
            changed_ips = {record.get('ip') for record in changed}
            for node in data['pools'][name].get('nodes', []):
                if node.get('ip') in changed_ips:
                    node.update(provisioning=True, status='FAILED', reason='بازگردانی کامل نشده است')
        atomic_update(mark_unready)
        update_job(name, status='rollback_failed', message='بازگردانی کامل نشد؛ نسخهٔ پشتیبان حفظ شده است',
                   error='; '.join(failures), failed_nodes=[record.get('ip') for record in changed])
        return False
    update_job(name, status='rolled_back', message='تنظیمات قبلی و آمادگی همهٔ نودها تأیید شد', failed_nodes=[])
    atomic_update(lambda data: data.get('pool_backups', {}).pop(name, None))
    return True


def _validate_target_prerequisites(
    to_engine, target, kharej_srv, iran_srvs, sessions, args
):
    """Return an error string if the target engine cannot be deployed.

    Runs BEFORE tearing down the healthy source tunnel so an infeasible target
    (e.g. gre6/ip6ip6 requiring native IPv6 on both endpoints) leaves the
    current state untouched instead of destroying it and failing rollback.
    """
    try:
        if to_engine in ("gre6", "ip6ip6"):
            endpoints = [kharej_srv] + list(iran_srvs)
            for sess, endpoint in zip(sessions, endpoints):
                host = str(endpoint.get("ip") or "")
                has_v6 = bool(host and ":" in host)
                if not has_v6:
                    _, out, _ = sess.execute(
                        "ip -6 addr show scope global 2>/dev/null | grep -c 'inet6 ' || true"
                    )
                    if (out or "").strip().lstrip("0").isdigit() and int((out or "0").strip() or 0) > 0:
                        has_v6 = True
                if not has_v6:
                    label = endpoint.get("name") or endpoint.get("server_name") or host
                    return (
                        f"پیش‌شرط تونل {to_engine} برآورده نشد: سرور {label} "
                        f"({host}) IPv6 عمومی بومی ندارد؛ تغییر انجام نشد و تونل قبلی دستنخورده ماند. "
                        "یا روی هر دو سرور IPv6 عمومی فعال کنید یا موتور دیگری (مثلاً dc6/sit یا tun) انتخاب کنید."
                    )
        return None
    except Exception as exc:
        return f"بررسی پیش‌شرط تونل مقصد ناموفق بود: {exc}"


def _run_kernel_rolling_change(name, pool, job, recovering=False):
    """Per-node phased migration for kernel-layer tunnel engines.

    One node (and both of its sides) is changed at a time while the rest of the
    pool keeps serving traffic. Pool-level members, client ports, subdomain and
    DNS routing are preserved; on failure every changed node reverts to its
    previous engine.
    """
    args = job.get('arguments', {}) or {}
    target = job['to']
    to_engine = job.get('to_engine') or get_engine_for_transport(target)
    from_engine = job.get('from_engine') or pool.get('engine') or get_engine_for_transport(job.get('from'))

    if recovering:
        original = load_data().get('pool_backups', {}).get(name)
        if original:
            _kernel_rollback(name, original, to_engine, from_engine, target)
        else:
            update_job(name, status='rollback_failed', message='نسخهٔ پشتیبان تغییر مرحله‌ای موجود نیست؛ رسیدگی دستی لازم است')
        return

    update_job(name, status='preflight', message='آماده‌سازی تغییر مرحله‌ای تونل و دسترسی به سرورها')

    kharej_srv = _resolve_server(pool['kharej_server'], 'kharej')
    iran_srvs = [_resolve_server(n, 'iran') for n in pool['nodes']]

    backup_pool = copy.deepcopy(pool)

    sessions = []
    try:
        sessions.append(connect(kharej_srv))
        for srv in iran_srvs:
            sessions.append(connect(srv))
        # Validate target feasibility BEFORE tearing down the healthy source
        # tunnel. If the target cannot be brought up (e.g. gre6/ip6ip6 need
        # native IPv6 on both endpoints), abort cleanly and leave the current
        # healthy state untouched instead of destroying it and failing rollback.
        preflight_err = _validate_target_prerequisites(
            to_engine, target, kharej_srv, iran_srvs, sessions, args
        )
        if preflight_err:
            update_job(name, status='failed', message=preflight_err)
            return
    except Exception as exc:
        update_job(name, status='failed', message=f'بررسی پیش‌پرواز ناموفق: {exc}')
        return
    finally:
        for s in sessions:
            s.close()

    def _set_target(data):
        p = data['pools'][name]
        p['transport'] = target
        p['engine'] = to_engine
        for key in ('mtu', 'tunnel_port', 'enable_psk', 'vni', 'bridge_name', 'underlay_dev'):
            if key in args:
                p[key] = copy.deepcopy(args[key])
        mtu_key = {'gre6': 'gre6_mtu', 'ip6ip6': 'ip6ip6_mtu', 'geneve_ipsec': 'geneve_mtu',
                   'wireguard': 'wireguard_mtu', 'tun': 'tun_mtu'}.get(target)
        if mtu_key and (args.get(mtu_key) or args.get('mtu')):
            p[mtu_key] = int(args.get(mtu_key) or args['mtu'])
        if target == 'wireguard' and (args.get('tunnel_port') or args.get('wireguard_port')):
            p['wireguard_port'] = int(args.get('tunnel_port') or args['wireguard_port'])
        if target == 'gre' and args.get('mtu'):
            p['gre_mtu'] = int(args['mtu'])
        if target == 'tun' and args.get('mtu'):
            p['tun_mtu'] = int(args['mtu'])
        if target == 'vxlan':
            vni = args.get('vni') or p.get('vni') or 1000
            dst_port = args.get('dst_port') or p.get('dst_port') or p.get('vxsec_dst_port') or 4789
            mtu = args.get('mtu') or p.get('vxlan_mtu') or p.get('vxsec_mtu') or 1400
            p['vni'] = int(vni)
            p['dst_port'] = int(dst_port)
            p['vxlan_mtu'] = int(mtu)
            p['vxlan_method'] = args.get('vxlan_method') or p.get('vxlan_method') or 'p2p'
        if target == 'vxlan_ipsec':
            vni = args.get('vni') or p.get('vni')
            dst_port = args.get('dst_port') or p.get('vxsec_dst_port') or 4789
            mtu = args.get('mtu') or p.get('vxsec_mtu') or 1280
            if vni is not None:
                p['vni'] = int(vni)
            p['vxsec_dst_port'] = int(dst_port)
            p['vxsec_mtu'] = int(mtu)
        if target == 'dc6':
            carrier = (
                args.get('carrier_type')
                or args.get('carrier')
                or p.get('carrier_type')
                or p.get('carrier')
                or 'sit'
            )
            p['carrier_type'] = carrier
            p['carrier'] = carrier
            if args.get('mtu') or args.get('dc6_mtu'):
                p['dc6_mtu'] = int(args.get('mtu') or args.get('dc6_mtu'))
            if args.get('mss_clamp'):
                p['dc6_mss_clamp'] = int(args['mss_clamp'])
    atomic_update(lambda data: data.setdefault('pool_backups', {}).__setitem__(name, copy.deepcopy(backup_pool)))

    changed = []
    try:
        atomic_update(_set_target)
        total = len(iran_srvs)
        for index, srv in enumerate(iran_srvs):
            data = load_data()
            cur = None
            for n in data['pools'][name]['nodes']:
                if n.get('ip') == srv.get('ip'):
                    cur = n
                    break
            label = srv.get('server_name') or srv.get('name') or srv.get('ip')
            if cur is None:
                raise RuntimeError('نود در استخر یافت نشد: ' + str(label))
            update_job(name, status='changing', changed=list(changed), completed=index, total=total,
                       message='تغییر دو سمت نود: ' + str(label))
            changed.append({'node_name': cur.get('node_name'), 'ip': cur.get('ip'),
                           'backup': copy.deepcopy(cur), 'from_engine': from_engine})
            update_job(name, changed=copy.deepcopy(changed))
            ok_src, msg_src = _remove_node_engine(name, cur, from_engine, pool)
            if not ok_src:
                raise RuntimeError('پاک‌سازی لینک قبلی نود ناموفق بود: ' + str(msg_src))
            ok_dst, msg_dst = _deploy_node(name, srv)
            if not ok_dst:
                raise RuntimeError('راه‌اندازی تونل جدید نود ناموفق بود: ' + str(msg_dst))
            deployed_pool = load_data().get('pools', {}).get(name, {})
            deployed_node = next(
                (n for n in deployed_pool.get('nodes', []) if n.get('ip') == srv.get('ip')),
                None,
            )
            changed[-1]['target_node'] = copy.deepcopy(deployed_node) if deployed_node else None
            update_job(name, changed=copy.deepcopy(changed))
            if not pool_ready({'nodes': [deployed_node] if deployed_node else []}, [srv]):
                raise RuntimeError('آمادگی نود مقصد تأیید نشد')

        def commit(data):
            p = data['pools'][name]
            p['transport'] = target
            p['engine'] = to_engine
            p['transport_change'].update(status='succeeded',
                message='نوع تونل همهٔ نودها تغییر کرد و عبور ترافیک تأیید شد',
                changed=copy.deepcopy(changed), completed=total, total=total)
            data.get('pool_backups', {}).pop(name, None)
        atomic_update(commit)
    except Exception as error:
        update_job(name, error=str(error), changed=list(changed))
        _kernel_rollback(name, backup_pool, to_engine, from_engine, target)

def run_change(name, recovering=False, job_id=None):
    with mutation_lock():
        data = load_data()
        pool = data.get('pools', {}).get(name) or data.get('pool_backups', {}).get(name) or {}
        job = pool.get('transport_change') or (data.get('pool_backups', {}).get(name) or {}).get('transport_change') or {}
        if job_id is not None and job.get('id') != job_id:
            return
        previous = getattr(_mutation_local, 'job_id', None)
        _mutation_local.job_id = job.get('id')
        try:
            return _run_change_locked(name, recovering)
        finally:
            _mutation_local.job_id = previous


def _run_change_locked(name, recovering=False):
    with mutation_lock():
        data = load_data()
        pool_data = data.get('pools', {}).get(name) or data.get('pool_backups', {}).get(name)
        if not pool_data:
            return
        pool = copy.deepcopy(pool_data)
        job = pool.get('transport_change') or (data.get('pool_backups', {}).get(name) or {}).get('transport_change')
        if not job:
            return
        if not recovering and job.get('status') != 'queued':
            return
        if recovering and job.get('status') not in ACTIVE:
            return
        if not pool.get('transport_change'):
            pool['transport_change'] = copy.deepcopy(job)
            atomic_update(lambda inventory: inventory['pools'][name].__setitem__('transport_change', copy.deepcopy(job)))
        if name not in data.get('pools', {}):
            atomic_update(lambda inventory: inventory.setdefault('pools', {}).__setitem__(name, copy.deepcopy(pool)))

        from_engine = job.get('from_engine') or pool.get('engine') or get_engine_for_transport(job.get('from'))
        to_engine = job.get('to_engine') or get_engine_for_transport(job.get('to'))
        from_trans = job.get('from')
        to_trans = job.get('to')

        is_legacy_backpack = (
            from_engine in (None, 'backpack') and
            to_engine in (None, 'backpack') and
            from_trans in {'tcp', 'stealth', 'pck', 'kcp', 'wss', 'quic'} and
            to_trans in {'tcp', 'stealth', 'pck', 'kcp', 'wss', 'quic'}
        )

        if is_legacy_backpack:
            _run_backpack_rolling_change(name, pool, job, recovering)
            return

        kernel_target = to_engine in KERNEL_ENGINES
        kernel_source = from_engine in (None, 'backpack') or from_engine in KERNEL_ENGINES
        if kernel_target and kernel_source:
            _run_kernel_rolling_change(name, pool, job, recovering)
            return

        _run_universal_engine_change(name, pool, job, recovering)

def start_change(name, target, background=True, repair=False, **kwargs):
    with mutation_lock(), routing_lock():
        data = load_data()
        pool = data.get('pools', {}).get(name)
        if busy(data):
            return False, 'عملیات تغییر تونل دیگری در جریان است یا بازگردانی آن نیاز به رسیدگی دارد'
        if not pool or not pool.get('nodes'):
            return False, 'استخر باید حداقل یک نود داشته باشد'

        all_transports = {v[0] for v in SUPPORTED_TRANSPORTS.values()}
        if target not in all_transports:
            return False, 'نوع تونل جدید نامعتبر است'
        try:
            validate_options(target, kwargs)
        except (ValueError, TypeError) as error:
            return False, str(error)

        from core.spoof_adapter import SPOOF_TRANSPORTS
        if target in SPOOF_TRANSPORTS or pool.get('engine') == 'spoof':
            return False, 'برای پروفایل پردازش بسته استخر جداگانه بسازید'
        if target in {'http', 'https'} or pool.get('transport') in {'http', 'https'}:
            return False, 'برای تغییر HTTP/HTTPS از عملیات اختصاصی CONNECT استفاده کنید؛ مهاجرت بین موتورهای دیگر پشتیبانی نمی‌شود'

        target_engine = _coerce_engine(kwargs.get('engine'), target)
        from core.capabilities import validate_production_readiness
        import os
        is_prod = bool(kwargs.get('is_production', False) or os.environ.get("VX_LB_PRODUCTION", "").lower() in ("1", "true", "yes"))
        allow_exp = bool(kwargs.get('allow_experimental', False))
        ok_gate, gate_msg = validate_production_readiness(target_engine, is_production=is_prod, allow_experimental=allow_exp)
        if not ok_gate:
            return False, gate_msg
        try:
            validate_engine_target(target, target_engine)
        except ValueError as error:
            return False, str(error)
        curr_engine = _coerce_engine(pool.get('engine'), pool.get('transport'))
        profile_changed = any(value != (pool.get('camouflage') or {}).get(key)
                              for key, value in (kwargs.get('camouflage') or {}).items())
        if target == pool.get('transport') and target_engine == curr_engine and not profile_changed:
            return False, 'نوع تونل جدید برابر نوع فعلی است'

        if pool.get('transport') == 'gre' and target_engine not in KERNEL_ENGINES:
            return False, 'GRE موتور مستقلی است؛ این تغییر تنها به موتورهای هسته (kernel) پشتیبانی می‌شود؛ برای بقیه استخر جدید بسازید'

        if target == 'slipstream':
            domain = kwargs.get('domain') or (kwargs.get('camouflage') or {}).get('domain') or (pool.get('camouflage') or {}).get('domain')
            if not domain:
                return False, 'وارد کردن دامنه برای تونل Slipstream الزامی است'

        job = {
            'repair': repair,
            'id': uuid.uuid4().hex,
            'status': 'queued',
            'from': pool.get('transport', 'tcp'),
            'to': target,
            'from_engine': curr_engine,
            'to_engine': target_engine,
            'completed': 0,
            'total': len(pool['nodes']),
            'changed': [],
            'message': 'در صف تغییر مرحله‌ای نوع تونل',
            'arguments': copy.deepcopy(kwargs),
        }
        def queue(d):
            d.setdefault('pools', {}).setdefault(name, {})['transport_change'] = job
        atomic_update(queue)

    if background:
        try:
            threading.Thread(target=run_change, args=(name, False, job['id']), daemon=True).start()
        except Exception:
            update_job(name, status='failed', message='عملیات شروع نشد؛ دوباره تلاش کنید')
            return False, 'عملیات شروع نشد'
    return True, 'تغییر مرحله‌ای شروع شد؛ وضعیت را در کارت استخر دنبال کنید'

def recover_changes():
    data = load_data()
    pools = dict(data.get('pool_backups', {}), **data.get('pools', {}))
    for name, pool in pools.items():
        job = pool.get('transport_change') or (data.get('pool_backups', {}).get(name) or {}).get('transport_change') or {}
        if job.get('status') in ACTIVE - {'rollback_failed'}:
            try:
                threading.Thread(target=run_change, args=(name, True, job['id']), daemon=True).start()
            except Exception:
                update_job(name, status='rollback_failed', message='شروع بازیابی ناموفق بود؛ دوباره تلاش کنید')

