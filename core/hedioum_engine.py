"""Hedioum Pool Tunnel engine: drives the bundled hedioum-tunnel binary.

The hedioum binary is self-sufficient (it installs its own systemd unit and
manages its config), so this engine is a thin driver that runs its subcommands
on the servers rather than synthesizing config files. It is fully offline: the
binary is bundled in the depot and installed via `hedioum-tunnel install`.

Topology (as designed by the project):
  - Foreign/egress node (Kharej): `setup-foreign` prints an auth/pairing token.
  - Iran hub: `setup-iran --token <TOKEN> --socks-port N ...`.

Modes:
  socks    : SOCKS5 on 127.0.0.1:19080; each client port is a raw TCP forward to Kharej.
  tun      : same TCP forward, plus an OS-level TUN interface (+ optional :53 DNS).
  gateway  : same TCP forward, plus a transparent L3 gateway (implies TUN).
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
# The user's TCP port cannot be the SOCKS listener: Hedioum blocks CONNECT to
# 127.0.0.1, and a raw client does not speak SOCKS. SOCKS stays on loopback and
# a forwarder publishes each client port to the Kharej address on that same port.
LOCAL_SOCKS_PORT = 19080

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
    del socks_port
    cmd = (f'mkdir -p /etc/hedioum && cd /etc/hedioum && {BINARY} setup-iran --alias {shlex.quote(alias)} '
           f'--token {shlex.quote(token)} '
           f'--socks-port {LOCAL_SOCKS_PORT} --socks-bind 127.0.0.1')
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


def _bridge_service(alias):
    return f'vxlb-hedioum-tcp-{alias}.service'


def _bridge_program(kharej_ip, ports):
    port_list = ','.join(str(int(port)) for port in ports)
    return f'''import socket, threading
socks_port = {LOCAL_SOCKS_PORT}
kharej = {kharej_ip!r}
ports = [{port_list}]

def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("short read")
        data += chunk
    return data

def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for sock in (src, dst):
            try:
                sock.close()
            except OSError:
                pass

def handle(client, port):
    remote = None
    try:
        remote = socket.create_connection(("127.0.0.1", socks_port), 5)
        remote.sendall(b"\\x05\\x01\\x00")
        if read_exact(remote, 2) != b"\\x05\\x00":
            return
        ip = bytes(int(part) for part in kharej.split("."))
        remote.sendall(b"\\x05\\x01\\x00\\x01" + ip + int(port).to_bytes(2, "big"))
        reply = read_exact(remote, 4)
        if reply[1] != 0:
            return
        if reply[3] == 1:
            read_exact(remote, 6)
        elif reply[3] == 4:
            read_exact(remote, 18)
        else:
            length = read_exact(remote, 1)[0]
            read_exact(remote, length + 2)
        threading.Thread(target=pipe, args=(client, remote), daemon=True).start()
        pipe(remote, client)
    except OSError:
        pass
    finally:
        for sock in (client, remote):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

def serve(port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(128)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client, port), daemon=True).start()

for port in ports:
    threading.Thread(target=serve, args=(port,), daemon=True).start()
threading.Event().wait()
'''


def publish_tcp_bridge(ssh, alias, kharej_ip, ports):
    ipaddress.IPv4Address(kharej_ip)
    ports = [int(port) for port in ports]
    script = f'/etc/vxlb/hedioum/tcp-{alias}.py'
    unit = _bridge_service(alias)
    execute(ssh, 'mkdir -p /etc/vxlb/hedioum')
    write(ssh, script, _bridge_program(kharej_ip, ports))
    write(ssh, f'/etc/systemd/system/{unit}', f'''[Unit]
Description=VX-LB Hedioum TCP forward
After=hedioum.service
Wants=hedioum.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
''')
    execute(ssh, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(unit)} && systemctl restart {shlex.quote(unit)}')


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
        publish_tcp_bridge(iran, alias, pool['kharej_server']['ip'], pool['client_ports'])

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
                execute(ssh, f'systemctl disable --now {shlex.quote(_bridge_service(alias))} 2>/dev/null || true', timeout=20)
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
        if ok:
            code, _, _ = sessions[0].execute(f'systemctl is-active --quiet {shlex.quote(_bridge_service(_alias(node)))}')
            ok = code == 0
            if not ok:
                return 'DOWN', 'فوروارد TCP هدیوم روی ایران فعال نیست', {}
        if not ok:
            return 'DOWN', 'سرویس Hedioum در یکی از سرورها فعال نیست', {}
        details = {p: {'status': 'HEALTHY', 'reason': 'سرویس Hedioum فعال است'} for p in ports}
        from core.link_latency import annotate
        annotate(sessions[0], pool['kharej_server']['ip'], details)
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
            iran = connect(node)
            sessions.append(iran)
            if node.get('hedioum'):
                publish_tcp_bridge(iran, _alias(node), pool['kharej_server']['ip'], ports)
        def commit(data):
            data['pools'][name]['client_ports'] = ports
            data['pools'][name].setdefault('camouflage', {})['socks_port'] = socks_port
            for node in data['pools'][name]['nodes']:
                if node.get('hedioum'):
                    node['hedioum']['socks_port'] = socks_port
                node['tunnel_port'] = socks_port
        atomic_update(commit)
        return True, 'پورت‌های TCP هدیوم به‌روزرسانی شدند'
    except Exception as failure:
        return False, str(failure)
    finally:
        for ssh in sessions:
            ssh.close()
