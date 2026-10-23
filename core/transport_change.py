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
from contextlib import contextmanager
from core.storage import DATA_DIR, load_data, atomic_update
from core.ssh_client import SSHManager
from core.tunnel import SUPPORTED_TRANSPORTS
from core.dns_routing import routing_lock
from core.tunnel_probe import TunnelProbe, add_probe_route

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
    if any(job.get('status') in {'queued', 'running'} for job in data.get('pool_creations', {}).values()):
        return True
    return any((pool.get('gre_update') or {}).get('status') in {'running','rollback_failed'} or (pool.get('transport_change') or {}).get('status') in ACTIVE or any(job.get('status') in {'queued', 'running'} for job in list(pool.get('node_removals', {}).values()) + list(pool.get('node_additions', {}).values())) for pool in (data if data is not None else load_data()).get('pools', {}).values())

def update_job(name, **fields):
    def update(data):
        pool = data.get('pools', {}).get(name)
        if pool is None: raise RuntimeError('استخر حذف شده است')
        pool['transport_change'].update(fields, updated_at=time.strftime('%Y-%m-%d %H:%M:%S'))
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
    if t in {'xhttp', 'xhttps', 'gre_xhttp', 'reality', 'nova'}:
        return 'xray'
    if t in {'quantum', 'quantum+', 'quantum-gaming', 'paqet'}:
        return 'paqet'
    if t == 'waterwall':
        return 'waterwall'
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
    'vxlan', 'vxlan_ipsec', 'geneve_ipsec',
}

def _coerce_engine(engine_id, transport):
    """Resolve an engine id that may be a UI group label to a registered engine.

    Group labels like "kernel" / "other" are not real engines; fall back to the
    concrete engine implied by the transport whenever the provided id is not
    itself registered.
    """
    eid = (engine_id or '').lower().strip()
    if eid and eid not in ('kernel', 'other'):
        from core.capabilities import get_capability
        if get_capability(eid) is not None:
            return eid
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
        'paqet': 'core.paqet_adapter',
        'xray': 'core.https_tunnel',
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
                stop_and_remove_tunnel(kh, node_name)
                ir = connect(node)
                sessions.append(ir)
                stop_and_remove_tunnel(ir, node_name)
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
    engine = pool.get('engine') or get_engine_for_transport(pool.get('transport', 'tcp'))
    nodes = list(pool.get('nodes', []))
    kharej = pool.get('kharej_server')
    ports = pool.get('client_ports', [])

    if engine == 'xray':
        from core.https_tunnel import clean
        for node in nodes:
            try:
                ir_ssh = connect(node)
                clean(ir_ssh, node, ports, True)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                clean(kh_ssh, node, ports, False)
                kh_ssh.close()
            except Exception: pass

    elif engine == 'waterwall':
        from core.waterwall import clean
        for node in nodes:
            try:
                ir_ssh = connect(node)
                clean(ir_ssh, node, True)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                clean(kh_ssh, node, False)
                kh_ssh.close()
            except Exception: pass

    elif engine == 'paqet':
        from core.paqet_adapter import clean
        for node in nodes:
            try:
                ir_ssh = connect(node)
                clean(ir_ssh, node, True)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                clean(kh_ssh, node, False)
                kh_ssh.close()
            except Exception: pass

    elif engine == 'wireguard':
        from core.wireguard_adapter import WireGuardAdapter
        adapter = WireGuardAdapter()
        for node in nodes:
            iface = node.get("wireguard", {}).get("interface") or f"wg-{node.get('node_name', 'node')}"
            try:
                ir_ssh = connect(node)
                adapter.clean(ir_ssh, iface)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                adapter.clean(kh_ssh, iface)
                kh_ssh.close()
            except Exception: pass

    elif engine == 'vxlan':
        from core.vxlan_adapter import VXLANAdapter
        adapter = VXLANAdapter()
        for node in nodes:
            iface = node.get("vxlan", {}).get("interface") or f"vx-{node.get('node_name', 'node')}"
            try:
                ir_ssh = connect(node)
                adapter.clean(ir_ssh, iface)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                adapter.clean(kh_ssh, iface)
                kh_ssh.close()
            except Exception: pass

    elif engine in ('geneve', 'geneve_ipsec'):
        from core.geneve import GeneveAdapter
        adapter = GeneveAdapter()
        for node in nodes:
            iface = node.get("geneve", {}).get("interface") or f"gnv-{node.get('node_name', 'node')}"
            try:
                ir_ssh = connect(node)
                adapter.clean(ir_ssh, iface)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                adapter.clean(kh_ssh, iface)
                kh_ssh.close()
            except Exception: pass

    elif engine == 'gre6':
        from core.gre6 import GRE6Adapter
        adapter = GRE6Adapter()
        for node in nodes:
            iface = node.get("gre6", {}).get("interface") or f"gre6-{node.get('node_name', 'node')}"
            try:
                ir_ssh = connect(node)
                adapter.clean(ir_ssh, iface)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                adapter.clean(kh_ssh, iface)
                kh_ssh.close()
            except Exception: pass

    elif engine == 'ip6ip6':
        from core.ip6ip6 import IP6IP6Adapter
        adapter = IP6IP6Adapter()
        for node in nodes:
            iface = node.get("ip6ip6", {}).get("interface") or f"ip6-{node.get('node_name', 'node')}"
            try:
                ir_ssh = connect(node)
                adapter.clean(ir_ssh, iface)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                adapter.clean(kh_ssh, iface)
                kh_ssh.close()
            except Exception: pass

    elif engine == 'gre':
        from core.gre import cleanup_endpoint
        for node in nodes:
            try:
                ir_ssh = connect(node)
                cleanup_endpoint(ir_ssh, node, True)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                cleanup_endpoint(kh_ssh, node, False)
                kh_ssh.close()
            except Exception: pass

    elif engine == 'dc6':
        from core.adapter_registry import get_adapter
        from core.native_ipv6_lifecycle import cleanup_endpoint
        adapter = get_adapter("dc6")
        for node in nodes:
            iface = node.get("node_name") or node.get("dc6", {}).get("interface", "")
            try:
                ir_ssh = connect(node)
                cleanup_endpoint(ir_ssh, adapter, iface, "dc6")
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                cleanup_endpoint(kh_ssh, adapter, iface, "dc6")
                kh_ssh.close()
            except Exception: pass

    elif engine == 'slipstream':
        from core.slipstream_adapter import clean
        for node in nodes:
            try:
                ir_ssh = connect(node)
                clean(ir_ssh, node)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                clean(kh_ssh, node)
                kh_ssh.close()
            except Exception: pass

    elif engine == 'spoof':
        from core.spoof_adapter import clean as spoof_clean
        for node in nodes:
            try:
                ir_ssh = connect(node)
                spoof_clean(ir_ssh, pool, node, True)
                ir_ssh.close()
            except Exception: pass
            try:
                kh_ssh = connect(kharej)
                spoof_clean(kh_ssh, pool, node, False)
                kh_ssh.close()
            except Exception: pass

    else:
        # Default BackPack
        from core.load_balancer import stop_and_remove_tunnel
        for node in nodes:
            node_name = node.get('node_name')
            if node_name:
                try:
                    kh_ssh = connect(kharej)
                    stop_and_remove_tunnel(kh_ssh, node_name)
                    kh_ssh.close()
                except Exception: pass
                try:
                    ir_ssh = connect(node)
                    stop_and_remove_tunnel(ir_ssh, node_name)
                    ir_ssh.close()
                except Exception: pass

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

def _run_universal_engine_change(name, pool, job, recovering=False):
    args = job.get('arguments', {})
    target = job['to']
    to_engine = job.get('to_engine') or get_engine_for_transport(target)

    if recovering:
        update_job(name, status='rolling_back', message='در حال بازگردانی به تنظیمات استخر قبلی')
        # Rollback logic handled below
        return

    update_job(name, status='preflight', message='آماده‌سازی تغییر تونل و راستی‌آزمایی ارتباط با سرورها')

    # 1. Resolve full server credentials from inventory
    kharej_srv = _resolve_server(pool['kharej_server'], 'kharej')
    iran_srvs = [_resolve_server(n, 'iran') for n in pool['nodes']]

    # Preflight check SSH to all servers
    sessions = []
    try:
        kh_ssh = connect(kharej_srv); sessions.append(kh_ssh)
        for srv in iran_srvs:
            ir_ssh = connect(srv); sessions.append(ir_ssh)
    except Exception as e:
        update_job(name, status='failed', message=f'بررسی پیش‌پرواز ناموفق: {e}')
        return
    finally:
        for s in sessions: s.close()

    # 2. Teardown old engine runtime
    update_job(name, status='changing', message='توقف و پاک‌سازی ایمن سرویس‌های تونل قبلی')
    backup_pool = copy.deepcopy(pool)
    try:
        teardown_pool_runtime(pool)
    except Exception:
        pass

    # 3. Deploy new engine
    update_job(name, status='changing', message=f'راه‌اندازی و آزمون مسیر ترنسپورت جدید ({target})')

    def _swap_out(data):
        data.setdefault('pool_backups', {})[name] = backup_pool
        data.get('pools', {}).pop(name, None)
    atomic_update(_swap_out)

    from core.load_balancer import LoadBalancerManager

    deploy_kwargs = dict(args)
    if 'camouflage' not in deploy_kwargs and backup_pool.get('camouflage'):
        deploy_kwargs['camouflage'] = backup_pool['camouflage']
    if 'mtu' not in deploy_kwargs:
        deploy_kwargs['mtu'] = args.get('mtu') or backup_pool.get('wireguard_mtu') or backup_pool.get('gre_mtu') or 1400

    create_ok, create_msg, created_pool = LoadBalancerManager.create_pool(
        pool_name=name,
        kharej_server=kharej_srv,
        iran_servers=iran_srvs,
        transport=target,
        client_ports=backup_pool.get('client_ports', []),
        **deploy_kwargs
    )

    if create_ok:
        def _commit_success(data):
            p = data.get('pools', {}).get(name)
            if not p:
                p = created_pool or {}
                data.setdefault('pools', {})[name] = p
            if backup_pool.get('subdomain'):
                p['subdomain'] = backup_pool['subdomain']
            if backup_pool.get('dns_routing'):
                p['dns_routing'] = backup_pool['dns_routing']
            if backup_pool.get('cloudflare'):
                p['cloudflare'] = backup_pool['cloudflare']
            p['transport_change'] = {
                'id': job['id'],
                'status': 'succeeded',
                'from': job.get('from'),
                'to': target,
                'from_engine': job.get('from_engine'),
                'to_engine': to_engine,
                'completed': len(p.get('nodes', [])),
                'total': len(p.get('nodes', [])),
                'message': f'نوع تونل با موفقیت به {target} تغییر یافت و آزمون انتقال داده تأیید شد',
            }
            data.get('pool_backups', {}).pop(name, None)
        atomic_update(_commit_success)
    else:
        try:
            curr_partial = load_data().get('pools', {}).get(name)
            if curr_partial:
                teardown_pool_runtime(curr_partial)
        except Exception:
            pass

        def _restore_old(data):
            data.setdefault('pools', {})[name] = backup_pool
            data.get('pool_backups', {}).pop(name, None)
            data['pools'][name]['transport_change'] = {
                'id': job['id'],
                'status': 'rolling_back',
                'from': job.get('from'),
                'to': target,
                'error': create_msg,
                'message': f'تغییر به {target} ناموفق بود ({create_msg})؛ در حال بازگردانی به نوع قبلی',
            }
        atomic_update(_restore_old)

        try:
            old_trans = backup_pool.get('transport', 'tcp')
            old_cam = backup_pool.get('camouflage')
            def _swap_old(data):
                data.get('pools', {}).pop(name, None)
            atomic_update(_swap_old)
            rb_ok, rb_msg, _ = LoadBalancerManager.create_pool(
                pool_name=name,
                kharej_server=kharej_srv,
                iran_servers=iran_srvs,
                transport=old_trans,
                client_ports=backup_pool.get('client_ports', []),
                camouflage=old_cam,
            )
            def _finalize_rollback(data):
                p = data.get('pools', {}).get(name) or backup_pool
                data.setdefault('pools', {})[name] = p
                if backup_pool.get('subdomain'): p['subdomain'] = backup_pool['subdomain']
                if backup_pool.get('dns_routing'): p['dns_routing'] = backup_pool['dns_routing']
                if backup_pool.get('cloudflare'): p['cloudflare'] = backup_pool['cloudflare']
                p['transport_change'] = {
                    'id': job['id'],
                    'status': 'rolled_back' if rb_ok else 'rollback_failed',
                    'from': job.get('from'),
                    'to': target,
                    'error': create_msg,
                    'message': f'تغییر نوع تونل لغو و نسخهٔ قبلی بازگردانده شد' if rb_ok else f'خطا در بازگردانی نسخهٔ قبلی: {rb_msg}',
                }
            atomic_update(_finalize_rollback)
        except Exception as rb_exc:
            def _mark_failed(data):
                data.setdefault('pools', {})[name] = backup_pool
                data['pools'][name]['transport_change'] = {
                    'id': job['id'],
                    'status': 'rollback_failed',
                    'from': job.get('from'),
                    'to': target,
                    'error': str(rb_exc),
                    'message': f'بازگردانی خودکار با خطا مواجه شد: {rb_exc}',
                }
            atomic_update(_mark_failed)

def _kernel_rollback(name, backup_pool, to_engine, from_engine, target):
    """Restore a failed kernel migration.

    Removes any target-engine links that were deployed, flips the pool metadata
    back to the source engine, and re-deploys the source links for every node
    that was torn down. Untouched source nodes keep their live links.
    """
    failures = []
    try:
        data = load_data()
        job = data['pools'][name].get('transport_change', {})
        changed = list(job.get('changed', []))

        for rec in reversed(changed):
            try:
                ok, msg = _remove_node_engine(name, rec, to_engine, backup_pool)
                if not ok:
                    failures.append(str(msg))
            except Exception as exc:
                failures.append(str(exc))

        def _restore_meta(data):
            p = data['pools'][name]
            p['transport'] = backup_pool.get('transport')
            p['engine'] = backup_pool.get('engine')
            for k in ('gre_mtu', 'tun_mtu', 'dc6_mtu', 'geneve_mtu',
                      'vxlan_mtu', 'vxsec_mtu', 'gre6_mtu', 'ip6ip6_mtu'):
                if k in backup_pool:
                    p[k] = backup_pool[k]
        atomic_update(_restore_meta)

        for rec in reversed(changed):
            backup = rec.get('backup') or {}
            server = dict(backup)
            server.setdefault('ip', rec.get('ip'))
            server.setdefault('name', rec.get('node_name') or backup.get('server_name') or backup.get('name'))
            server.setdefault('server_name', server['name'])
            try:
                ok, msg = _deploy_node(name, server)
                if not ok:
                    failures.append(str(msg))
            except Exception as exc:
                failures.append(str(exc))

        if failures:
            update_job(name, status='rollback_failed', message='بازگردانی کامل نشد؛ وضعیت منابع را بررسی کنید',
                       failed_nodes=[r.get('ip') for r in changed])
            return False
        update_job(name, status='rolled_back', message='تنظیمات قبلی بازگردانده و عبور آزمایشی ترافیک تأیید شد',
                   failed_nodes=[])
        return True
    except Exception as exc:
        update_job(name, status='rollback_failed', message='بازگردانی با خطا مواجه شد: ' + str(exc))
        return False

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
        update_job(name, status='rollback_failed',
                   message='بازگردانی مرحله‌ای هسته پس از قطع شدن نیاز به رسیدگی دستی دارد')
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
    atomic_update(_set_target)

    changed = []
    try:
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
            ok_src, msg_src = _remove_node_engine(name, cur, from_engine, pool)
            if not ok_src:
                raise RuntimeError('پاک‌سازی لینک قبلی نود ناموفق بود: ' + str(msg_src))
            changed.append({'node_name': cur.get('node_name'), 'ip': cur.get('ip'),
                           'backup': cur, 'from_engine': from_engine})
            ok_dst, msg_dst = _deploy_node(name, srv)
            if not ok_dst:
                raise RuntimeError('راه‌اندازی تونل جدید نود ناموفق بود: ' + str(msg_dst))

        def commit(data):
            p = data['pools'][name]
            p['transport'] = target
            p['engine'] = to_engine
            p['transport_change'].update(status='succeeded',
                message='نوع تونل همهٔ نودها تغییر کرد و عبور ترافیک تأیید شد',
                changed=list(changed), completed=total, total=total)
        atomic_update(commit)
    except Exception as error:
        update_job(name, error=str(error), changed=list(changed))
        _kernel_rollback(name, backup_pool, to_engine, from_engine, target)

def run_change(name, recovering=False):
    with mutation_lock():
        pool_data = load_data().get('pools', {}).get(name)
        if not pool_data:
            return
        pool = copy.deepcopy(pool_data)
        job = pool.get('transport_change')
        if not job:
            return

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
    with routing_lock():
        data = load_data()
        pool = data.get('pools', {}).get(name)
        if busy(data):
            return False, 'عملیات تغییر تونل دیگری در جریان است یا بازگردانی آن نیاز به رسیدگی دارد'
        if not pool or not pool.get('nodes'):
            return False, 'استخر باید حداقل یک نود داشته باشد'

        all_transports = {v[0] for v in SUPPORTED_TRANSPORTS.values()}
        if target not in all_transports:
            return False, 'نوع تونل جدید نامعتبر است'

        target_engine = _coerce_engine(kwargs.get('engine'), target)
        from core.capabilities import validate_production_readiness
        import os
        is_prod = bool(kwargs.get('is_production', False) or os.environ.get("VX_LB_PRODUCTION", "").lower() in ("1", "true", "yes"))
        allow_exp = bool(kwargs.get('allow_experimental', False))
        ok_gate, gate_msg = validate_production_readiness(target_engine, is_production=is_prod, allow_experimental=allow_exp)
        if not ok_gate:
            return False, gate_msg
        curr_engine = _coerce_engine(pool.get('engine'), pool.get('transport'))
        if target == pool.get('transport') and target_engine == curr_engine:
            return False, 'نوع تونل جدید برابر نوع فعلی است'

        if target != 'gre' and pool.get('transport') == 'gre':
            return False, 'GRE موتور مستقلی است؛ مهاجرت از آن پشتیبانی نمی‌شود؛ برای نوع دیگر استخر جدید بسازید'

        if target_engine == 'xray' or target in {'xhttp', 'xhttps', 'nova', 'gre_xhttp'}:
            cam = kwargs.get('camouflage') or pool.get('camouflage') or {}
            server_name = cam.get('server_name') or kwargs.get('server_name')
            if not server_name:
                return False, 'وارد کردن دامنهٔ TLS سرور خارج برای استتار Xray الزامی است'
        elif target == 'slipstream':
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
            'arguments': kwargs,
        }
        def queue(d):
            d.setdefault('pools', {}).setdefault(name, {})['transport_change'] = job
        atomic_update(queue)

    if background:
        threading.Thread(target=run_change, args=(name,), daemon=True).start()
    return True, 'تغییر مرحله‌ای شروع شد؛ وضعیت را در کارت استخر دنبال کنید'

def recover_changes():
    for name, pool in load_data().get('pools', {}).items():
        if (pool.get('transport_change') or {}).get('status') in ACTIVE - {'rollback_failed'}:
            if pool.get('engine') == 'xray':
                update_job(name, status='rollback_failed', message='به‌روزرسانی HTTPS قطع شده؛ بازگردانی را اجرا کنید')
            elif pool.get('engine') == 'waterwall':
                update_job(name, status='rollback_failed', message='به‌روزرسانی WaterWall قطع شده؛ بازگردانی را اجرا کنید')
            elif pool.get('engine') == 'paqet':
                update_job(name, status='rollback_failed', message='به‌روزرسانی Paqet قطع شده؛ بازگردانی را اجرا کنید')
            else:
                threading.Thread(target=run_change, args=(name, True), daemon=True).start()

