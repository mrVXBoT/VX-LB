"""Hedioum Pool Tunnel engine: drives the bundled hedioum-tunnel binary.

The hedioum binary is self-sufficient (it installs its own systemd unit and
manages its config), so this engine is a thin driver that runs its subcommands
on the servers rather than synthesizing config files. It is fully offline: the
binary is bundled in the depot and installed via `hedioum-tunnel install`.

Topology (as designed by the project):
  - Foreign/egress node (Kharej): `setup-foreign` prints an auth/pairing token.
  - Iran hub: `setup-iran --token <TOKEN> --socks-port N ...`.

Modes:
  socks    : SOCKS5 on the first client port (socks-bind 0.0.0.0).
  tun      : expose an OS-level TUN interface (+ optional :53 DNS forwarder).
  gateway  : transparent L3 gateway for a whole LAN (implies TUN).
"""
import ipaddress
import os
import re
import secrets
import shlex
import time
from core.storage import get_pools, save_pool, delete_pool, atomic_update
from core.validation import validate_pool_name, validate_ports, validate_port
from core.transport_change import connect
from core.gre import write

BINARY = '/usr/local/bin/hedioum-tunnel'
SERVICE = 'hedioum.service'

MODES = ('socks', 'tun', 'gateway')

MODE_LABELS = {
    'socks': 'Hedioum SOCKS5',
    'tun': 'Hedioum TUN',
    'gateway': 'Hedioum Gateway',
}

PERSONAS = ('auto', 'cpanel', 'directadmin', 'devops')


def execute(ssh, command, timeout=60):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or f'Hedioum command failed: {command}')
    return out


def normalize_mode(mode):
    if mode not in MODES:
        raise ValueError(f'حالت Hedioum نامعتبر: {mode}')
    return mode


def install_hedioum(ssh):
    code, _, err = ssh.execute(f'test "$(id -u)" = 0 && test -x {shlex.quote(BINARY)} && command -v systemctl')
    if code != 0:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _, arch_raw, _ = ssh.execute('uname -m')
        remote_arch = arch_raw.strip().lower()
        arch_dir = 'x86_64' if remote_arch in ('x86_64', 'amd64') else 'aarch64' if remote_arch in ('aarch64', 'arm64') else remote_arch
        candidate = os.path.join(base_dir, 'bin', arch_dir, 'hedioum-tunnel')
        from core.dependency_manifest import get_dependency_manifest, verify_file_sha256
        manifest = get_dependency_manifest('hedioum')
        expected = (manifest.architectures.get(arch_dir, {}) if manifest else {}).get('sha256')
        if not os.path.isfile(candidate):
            return False, f'Hedioum binary not in offline depot: {candidate}'
        if not expected or not verify_file_sha256(candidate, expected):
            return False, f'Hedioum binary checksum mismatch or missing manifest for {arch_dir}'
        if not hasattr(ssh, 'upload_binary'):
            return False, 'SSH manager has no upload_binary support'
        if not ssh.upload_binary(candidate, BINARY, mode=0o755):
            return False, 'Failed to upload hedioum-tunnel'
        try:
            execute(ssh, f'{shlex.quote(BINARY)} install', timeout=60)
        except Exception as e:
            return False, f'Hedioum install failed: {e}'
    return True, 'Hedioum binary installed'


def setup_foreign(ssh, persona='auto', domain=None, move_ssh=False, mimics=None):
    cmd = f'mkdir -p /etc/hedioum && cd /etc/hedioum && {BINARY} setup-foreign --persona {shlex.quote(persona)}'
    if domain:
        cmd += f' --domain {shlex.quote(domain)}'
    if move_ssh:
        cmd += ' --move-ssh'
    if mimics:
        cmd += f' --mimics {shlex.quote(mimics)}'
    out = execute(ssh, cmd, timeout=120)
    m = (re.search(r'(ey[A-Za-z0-9_-]{20,})', out) or
         re.search(r'(?i)pairing token[^\n]*\n+([A-Za-z0-9_\-\.\=]{20,})', out) or
         re.search(r'(?i)raw auth key[^\n]*:\s*([0-9a-f]{8,})', out) or
         re.search(r'(?i)token[:\s]+([0-9a-f]{8,})', out))
    if not m:
        raise RuntimeError('Hedioum foreign setup did not produce an auth token')
    return m.group(1).strip()


def _command(mode, alias, token, socks_port, tun_dns=False):
    cmd = (f'mkdir -p /etc/hedioum && cd /etc/hedioum && {BINARY} setup-iran --alias {shlex.quote(alias)} '
           f'--token {shlex.quote(token)} '
           f'--socks-port {int(socks_port)} --socks-bind 0.0.0.0')
    if mode == 'tun':
        cmd += ' --tun'
        if tun_dns:
            cmd += ' --dns'
    elif mode == 'gateway':
        cmd += ' --tun --dns --gateway'
    return cmd


def setup_iran(ssh, alias, token, socks_port, mode, tun_dns=False):
    """Provision an Iran hub node.

    A node that was previously used as an egress/foreign (Kharej) endpoint
    still carries a Hedioum config with role "foreign"; the binary refuses to
    overwrite it (``existing config role is "foreign", not iran``). In that
    case we wipe the stale config on THIS node only via the binary's standalone
    ``--reset`` (removes /etc/hedioum/hedioum.json and stops the service) and
    retry once. The reset never touches the Kharej side, which owns the token.
    """
    try:
        execute(ssh, _command(mode, alias, token, socks_port, tun_dns=tun_dns), timeout=120)
    except Exception as error:
        text = str(error)
        if 'not iran' in text or 'config role' in text:
            execute(ssh, f'cd /etc/hedioum && {BINARY} --reset', timeout=60)
            execute(ssh, _command(mode, alias, token, socks_port, tun_dns=tun_dns), timeout=120)
            return
        raise


def _alias(node):
    return node['hedioum']['alias']


def create(name, kharej, servers, ports, settings, callback=None):
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        mode = normalize_mode((settings or {}).get('mode', 'socks'))
        persona = str((settings or {}).get('persona', 'auto'))
        if persona not in PERSONAS:
            raise ValueError(f'persona نامعتبر: {persona}')
        domain = (settings or {}).get('domain') or None
        move_ssh = bool((settings or {}).get('move_ssh'))
        tun_dns = bool((settings or {}).get('tun_dns'))
        socks_port = int(validate_port((settings or {}).get('socks_port') or ports[0]))
        if not ports or not servers or name in get_pools():
            raise ValueError('نام تکراری یا فهرست سرورها/پورت‌ها خالی است')
        if len({s['ip'] for s in servers}) != len(servers):
            raise ValueError('سرور تکراری مجاز نیست')
        if any(s['ip'] == kharej['ip'] for s in servers):
            raise ValueError('دو سمت تونل باید متفاوت باشند')
        for s in servers + [kharej]:
            ipaddress.IPv4Address(s['ip'])
    except (ValueError, TypeError) as error:
        return False, str(error), {}

    save_pool(name, {
        'name': name,
        'transport': 'hedioum',
        'engine': 'hedioum',
        'hedioum_mode': mode,
        'camouflage': {'mode': mode, 'persona': persona, 'domain': domain,
                       'move_ssh': move_ssh, 'tun_dns': tun_dns, 'socks_port': socks_port},
        'kharej_server': kharej,
        'client_ports': ports,
        'nodes': [],
    })
    results = [add(name, server, callback) for server in servers]
    pool = get_pools()[name]
    return any(ok for ok, _ in results), 'نتیجهٔ نصب هر نود در کارت استخر ثبت شد', pool


def add(name, server, callback=None):
    pool = get_pools().get(name)
    if not pool:
        return False, 'استخر یافت نشد'
    if any(n['ip'] == server['ip'] for n in pool['nodes']):
        return False, 'سرور قبلاً عضو استخر است'

    sessions = []
    prof = pool['camouflage']
    node = dict(server, node_name='hed' + secrets.token_hex(8), engine='hedioum', transport='hedioum', provisioning=True)

    def progress(message, status='running', error=''):
        def update(data):
            data['pools'][name].setdefault('node_additions', {}).setdefault(server['ip'], {}).update({
                'ip': server['ip'], 'name': server['name'], 'status': status,
                'message': message, 'error': error, 'updated_at': time.time()
            })
        atomic_update(update)
        if callback:
            callback(message)

    try:
        progress('اتصال به سرورها و بررسی Hedioum')
        kharej = connect(pool['kharej_server'])
        sessions.append(kharej)
        iran = connect(server)
        sessions.append(iran)

        for ssh in sessions:
            ok, msg = install_hedioum(ssh)
            if not ok:
                raise RuntimeError(msg)

        alias = node['node_name']
        token = setup_foreign(kharej, persona=prof['persona'], domain=prof.get('domain'),
                              move_ssh=prof.get('move_ssh'))
        socks_port = int(validate_port(prof['socks_port'] or pool['client_ports'][0]))
        setup_iran(iran, alias, token, socks_port, prof['mode'], tun_dns=prof.get('tun_dns'))

        # Ensure hedioum daemon is running and enabled on both servers
        execute(kharej, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(SERVICE)}')
        execute(iran, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(SERVICE)}')

        node['hedioum'] = {'alias': alias, 'mode': prof['mode'], 'socks_port': socks_port}
        node['tunnel_port'] = socks_port

        def reserve(data):
            data['pools'][name]['nodes'].append(node)
        atomic_update(reserve)
        progress('نود Hedioum فعال شد', 'succeeded')

        def finish(data):
            member = next(n for n in data['pools'][name]['nodes'] if n['node_name'] == node['node_name'])
            member.update(provisioning=False, status='active')
        atomic_update(finish)
        return True, 'نود Hedioum فعال شد'

    except Exception as failure:
        errors = []
        try:
            for ssh in sessions:
                try:
                    execute(ssh, f'systemctl stop {SERVICE} 2>/dev/null || true', timeout=20)
                except Exception as e:
                    errors.append(str(e))
            if not errors:
                def discard(data):
                    data['pools'][name]['nodes'] = [n for n in data['pools'][name]['nodes'] if n['node_name'] != node['node_name']]
                atomic_update(discard)
        except Exception:
            pass
        message = str(failure) + ('; پاک‌سازی ناقص: ' + '; '.join(errors) if errors else '')
        progress('راه‌اندازی نود ناموفق بود', 'failed', message)
        return False, message
    finally:
        for ssh in sessions:
            ssh.close()


def remove(name, ip, callback=None):
    pool = get_pools().get(name, {})
    node = next((n for n in pool.get('nodes', []) if n['ip'] == ip), None)
    if not node:
        return False, 'نود یافت نشد'
    sessions = []
    try:
        for server in (node, pool['kharej_server']):
            sessions.append(connect(server))
        alias = _alias(node)
        for ssh in sessions:
            try:
                execute(ssh, f'{BINARY} remove-node --alias {shlex.quote(alias)} 2>/dev/null || true', timeout=60)
            except Exception:
                execute(ssh, f'systemctl stop {SERVICE} 2>/dev/null || true', timeout=20)
        def discard(data):
            data['pools'][name]['nodes'] = [n for n in data['pools'][name]['nodes'] if n['node_name'] != node['node_name']]
        atomic_update(discard)
        return True, 'نود و منابع اختصاصی آن حذف شدند'
    except Exception as error:
        return False, str(error)
    finally:
        for ssh in sessions:
            ssh.close()


def remove_pool(name, callback=None):
    for node in list(get_pools().get(name, {}).get('nodes', [])):
        ok, error = remove(name, node['ip'], callback)
        if not ok:
            return ok, error
    delete_pool(name)
    return True, 'استخر حذف شد'


def health(name, node, ports):
    if node.get('provisioning'):
        return 'DOWN', 'نصب یا پاک‌سازی نود کامل نشده است', {}
    try:
        pool = get_pools()[name]
        sessions = []
        for server in (node, pool['kharej_server']):
            sessions.append(connect(server))
        ok = True
        for ssh in sessions:
            code, _, _ = ssh.execute(f'systemctl is-active --quiet {SERVICE}')
            ok = ok and code == 0
        if not ok:
            return 'DOWN', 'سرویس Hedioum در یکی از سرورها فعال نیست', {}
        details = {p: {'status': 'HEALTHY', 'reason': 'سرویس Hedioum فعال است'} for p in ports}
        return 'HEALTHY', 'سرویس Hedioum فعال است', details
    except Exception as error:
        return 'DOWN', str(error), {}
    finally:
        for ssh in sessions:
            ssh.close()


def change_ports(name, ports, recovery=False):
    pool = get_pools()[name]
    sessions = []
    try:
        ports = validate_ports(ports)
        if not ports:
            raise ValueError('حداقل یک پورت باید باقی بماند')
        socks_port = int(ports[0])
        for node in pool['nodes']:
            kh_ssh = connect(pool['kharej_server'])
            sessions.append(kh_ssh)
            # Only the hub's SOCKS port changes; foreign node untouched.
            if node.get('hedioum'):
                node['hedioum']['socks_port'] = socks_port
            node['tunnel_port'] = socks_port
        def commit(data):
            data['pools'][name]['client_ports'] = ports
        atomic_update(commit)
        return True, 'پورت‌ها به‌روزرسانی شدند (SOCKS پورت جدید روی نودها پس از بازآرایی اعمال می‌شود)'
    except Exception as failure:
        return False, str(failure)
    finally:
        for ssh in sessions:
            ssh.close()
