"""GOST engine: profile-based tunnels using the bundled gost binary.

Profiles mirror the well-known Gost-Manager menu but only include those that do
not duplicate transports VX-LB already provides (KCP/TLS/WS/QUIC/HTTP2 are
covered elsewhere). Each profile maps to a GOST v2/v3 URL chain.

Profiles:
  shadowsocks-tcp, shadowsocks-udp, shadowsocks-tls, shadowsocks-ws,
  obfs4, obfs4-tls, grpc, grpc-tls, ssh,
  kcp-obfs4, web-tunnel, gaming-socks5-kcp, quic-socks5
"""
import ipaddress
import json
import os
import re
import secrets
import shlex
import time
from pathlib import Path
from core.storage import get_pools, save_pool, delete_pool, atomic_update
from core.validation import validate_pool_name, validate_ports, validate_port, validate_tunnel_name
from core.transport_change import connect
from core.gre import write

DIRECTORY = '/etc/vxlb/gost'
BINARY_DEFAULT = '/usr/local/bin/gost'

PROFILES = {
    'shadowsocks-tcp': {'transport': 'ss', 'params': 'aes-256-gcm', 'proto': 'tcp'},
    'shadowsocks-udp': {'transport': 'ssu', 'params': 'aes-256-gcm', 'proto': 'udp'},
    'shadowsocks-tls': {'transport': 'ss+tls', 'params': 'aes-256-gcm', 'proto': 'tcp', 'tls': True},
    'shadowsocks-ws': {'transport': 'ss+ws', 'params': 'aes-256-gcm', 'proto': 'tcp', 'tls': True},
    'obfs4': {'transport': 'relay+obfs4', 'params': 'iat-mode=0', 'proto': 'tcp'},
    'obfs4-tls': {'transport': 'relay+obfs4+tls', 'params': 'iat-mode=0', 'proto': 'tcp', 'tls': True},
    'grpc': {'transport': 'relay+grpc', 'params': 'keepalive=true&ping=30', 'proto': 'tcp'},
    'grpc-tls': {'transport': 'relay+grpc+tls', 'params': 'keepalive=true', 'proto': 'tcp', 'tls': True},
    'ssh': {'transport': 'forward+ssh', 'params': 'ping=60', 'proto': 'tcp'},
    'kcp-obfs4': {'transport': 'relay+kcp+obfs4', 'params': 'mode=fast3&crypt=chacha20&mtu=1350&sndwnd=2048&rcvwnd=2048&iat-mode=0', 'proto': 'udp'},
    'web-tunnel': {'transport': 'http+mwss', 'params': 'keepalive=true&ping=30&path=/ws', 'proto': 'tcp', 'tls': True},
    'gaming-socks5-kcp': {'transport': 'socks5+kcp', 'params': 'mode=fast3&crypt=aes-128-gcm', 'proto': 'udp'},
    'quic-socks5': {'transport': 'socks5+quic', 'params': 'keepalive=true&timeout=60', 'proto': 'udp'},
}

PROFILE_LABELS = {
    'shadowsocks-tcp': 'Shadowsocks TCP',
    'shadowsocks-udp': 'Shadowsocks UDP',
    'shadowsocks-tls': 'Shadowsocks + TLS',
    'shadowsocks-ws': 'Shadowsocks + WebSocket',
    'obfs4': 'obfs4',
    'obfs4-tls': 'obfs4 + TLS',
    'grpc': 'gRPC',
    'grpc-tls': 'gRPC + TLS',
    'ssh': 'SSH Tunnel',
    'kcp-obfs4': 'KCP + obfs4',
    'web-tunnel': 'Web-Tunnel (HTTP + MWSS)',
    'gaming-socks5-kcp': 'SOCKS5 + KCP',
    'quic-socks5': 'QUIC + SOCKS5',
}


def execute(ssh, command, timeout=30):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or 'GOST command failed')


def normalize_profile(profile):
    if profile not in PROFILES:
        raise ValueError(f'GOST profile نامعتبر: {profile}')
    return profile


def install_gost(ssh, binary=None):
    binary = binary or BINARY_DEFAULT
    code, _, err = ssh.execute(f'test "$(id -u)" = 0 && test -x {shlex.quote(binary)} && command -v python3 && command -v systemctl')
    if code != 0:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _, arch_raw, _ = ssh.execute('uname -m')
        remote_arch = arch_raw.strip().lower()
        arch_dir = 'x86_64' if remote_arch in ('x86_64', 'amd64') else 'aarch64' if remote_arch in ('aarch64', 'arm64') else remote_arch
        candidate = os.path.join(base_dir, 'bin', arch_dir, 'gost')
        from core.dependency_manifest import get_dependency_manifest, verify_file_sha256
        manifest = get_dependency_manifest('gost')
        expected = (manifest.architectures.get(arch_dir, {}) if manifest else {}).get('sha256')
        if os.path.isfile(candidate) and expected and verify_file_sha256(candidate, expected) and hasattr(ssh, 'upload_binary'):
            if ssh.upload_binary(candidate, binary, mode=0o755):
                code, out, err = ssh.execute(f'test -x {shlex.quote(binary)} && command -v python3 && command -v systemctl')
        if code != 0:
            return False, f'GOST install check failed: root, binary ({binary}), or system tools missing: {err or out}'
    return True, 'GOST binary verified'


def _server_listen_url(profile, port, password, tls_files=None):
    info = PROFILES[profile]
    transport = info['transport']
    params = info['params']
    if info.get('tls') and tls_files:
        params = (params + '&' if params else '') + f'cert={tls_files[0]}&key={tls_files[1]}'
    url = f'{transport}://:{port}'
    if params:
        url += '?' + params
    url += '&key=' + password
    return url


def _client_forward_url(profile, remote_ip, port, password):
    info = PROFILES[profile]
    transport = info['transport']
    params = info['params']
    url = f'{transport}://{remote_ip}:{port}'
    if params:
        url += '?' + params
    url += '&key=' + password
    return url


def _service_name(node):
    return f'vxlb-gost-{node["gost"]["id"]}.service'


def _unit(node, command, cert_files=None):
    binary = shlex.quote(node['gost']['binary'])
    encoded = ' '.join('"' + str(v).replace('\\', '\\\\').replace('"', '\\"') + '"' for v in command)
    return f'''[Unit]
Description=VX-LB GOST Tunnel node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} {encoded}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
'''


def _cmd(ssh, node, role, outside_ip=None, ports=None):
    info = node['gost']
    profile = info['profile']
    port = info['port']
    password = info['password']
    host = info['host']
    if role == 'server':
        return ['-L', _server_listen_url(profile, port, password, (host + '.crt', host + '.key') if PROFILES[profile].get('tls') else None)]
    cmds = []
    for p in ports:
        proto = 'udp' if PROFILES[profile]['proto'] == 'udp' else 'tcp'
        cmds += ['-L', f'{proto}://:{p}/127.0.0.1:{p}']
    cmds += ['-F', _client_forward_url(profile, outside_ip, port, password)]
    return cmds


def create(name, kharej, servers, ports, settings, callback=None):
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        profile = normalize_profile((settings or {}).get('profile', 'shadowsocks-tcp'))
        password = str((settings or {}).get('password') or secrets.token_hex(16))
        binary = str((settings or {}).get('binary') or BINARY_DEFAULT)
        if len(password) < 8:
            raise ValueError('رمز GOST باید حداقل ۸ نویسه باشد')
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
        'transport': 'gost',
        'engine': 'gost',
        'gost_profile': profile,
        'camouflage': {'profile': profile, 'password': password, 'binary': binary},
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
    node = dict(server, node_name='gost' + secrets.token_hex(8), engine='gost', transport='gost', provisioning=True)

    def progress(message, status='running', error=''):
        def update(data):
            data['pools'][name].setdefault('node_additions', {}).setdefault(server['ip'], {}).update({
                'ip': server['ip'], 'name': server['name'], 'status': status, 'message': message, 'error': error, 'updated_at': time.time()
            })
        atomic_update(update)
        if callback:
            callback(message)

    try:
        progress('اتصال به سرورها و بررسی GOST')
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool['kharej_server'])
        sessions.append(kharej)

        for ssh, role in zip(sessions, ('iran', 'kharej')):
            ok, msg = install_gost(ssh, prof['binary'])
            if not ok:
                raise RuntimeError(msg)

        from core.load_balancer import LoadBalancerManager
        outer = int(validate_port(prof['port'])) if str(prof.get('port', '')).isdigit() else 8443
        ok, err = LoadBalancerManager.check_port_conflicts(pool['client_ports'], [server['ip']])
        if not ok:
            raise RuntimeError(err)

        host = f'{DIRECTORY}/{node["node_name"]}'
        node['gost'] = {
            'id': node['node_name'],
            'profile': prof['profile'],
            'password': prof['password'],
            'binary': prof['binary'],
            'port': outer,
            'host': host,
        }
        node['tunnel_port'] = int(outer)

        def reserve(data):
            data['pools'][name]['nodes'].append(node)
        atomic_update(reserve)

        svc = _service_name(node)
        for ssh, role in zip(sessions, ('iran', 'kharej')):
            execute(ssh, f'mkdir -p {DIRECTORY}')
            tls_files = None
            if PROFILES[prof['profile']].get('tls'):
                cert, key = host + '.crt', host + '.key'
                execute(ssh, f'openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 '
                             f'-subj "/C=US/ST=CA/L=Los Angeles/O=Speedtest Inc/CN=www.speedtest.net" '
                             f'-keyout {shlex.quote(key)} -out {shlex.quote(cert)}')
                tls_files = (cert, key)
            cmd = _cmd(ssh, node, 'server' if role == 'kharej' else 'client',
                       outside_ip=pool['kharej_server']['ip'], ports=pool['client_ports'])
            write(ssh, f'/etc/systemd/system/{svc}', _unit(node, cmd, tls_files))
            execute(ssh, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(svc)}')

        progress('نود GOST فعال شد', 'succeeded')

        def finish(data):
            member = next(n for n in data['pools'][name]['nodes'] if n['node_name'] == node['node_name'])
            member.update(provisioning=False, status='active')
        atomic_update(finish)
        return True, 'نود GOST فعال شد'

    except Exception as failure:
        errors = []
        try:
            for ssh in sessions:
                try:
                    execute(ssh, f'systemctl disable --now {shlex.quote(_service_name(node))} 2>/dev/null || true')
                    execute(ssh, f'rm -f {DIRECTORY}/{node["node_name"]}.*')
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
        svc = _service_name(node)
        for ssh in sessions:
            execute(ssh, f'systemctl disable --now {shlex.quote(svc)} 2>/dev/null || true')
            execute(ssh, f'rm -f {DIRECTORY}/{node["node_name"]}.* /etc/systemd/system/{svc}')
            execute(ssh, 'systemctl daemon-reload')
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
        svc = _service_name(node)
        ok = True
        for ssh in sessions:
            code, _, _ = ssh.execute(f'systemctl is-active --quiet {shlex.quote(svc)}')
            ok = ok and code == 0
        if not ok:
            return 'DOWN', 'سرویس GOST در یکی از سرورها فعال نیست', {}
        details = {p: {'status': 'HEALTHY', 'reason': 'سرویس GOST فعال است'} for p in ports}
        return 'HEALTHY', 'سرویس GOST فعال است', details
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
        for node in pool['nodes']:
            ir_ssh = connect(node)
            kh_ssh = connect(pool['kharej_server'])
            sessions.append((ir_ssh, kh_ssh))
            svc = _service_name(node)
            for ssh, role in zip((ir_ssh, kh_ssh), ('iran', 'kharej')):
                cmd = _cmd(ssh, node, 'client' if role == 'iran' else 'server',
                           outside_ip=pool['kharej_server']['ip'], ports=ports)
                write(ssh, f'/etc/systemd/system/{svc}', _unit(node, cmd))
                execute(ssh, f'systemctl restart {shlex.quote(svc)}')
        def commit(data):
            data['pools'][name]['client_ports'] = ports
        atomic_update(commit)
        return True, 'پورت‌ها به‌روزرسانی شدند'
    except Exception as failure:
        return False, str(failure)
    finally:
        for ir_ssh, kh_ssh in sessions:
            ir_ssh.close()
            kh_ssh.close()
