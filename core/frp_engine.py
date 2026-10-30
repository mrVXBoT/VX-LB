"""FRP engine: Fast Reverse Proxy (frps/frpc) using the bundled binaries.

Modern TOML config. Server runs on Kharej, client on Iran. Each pool client
port is forwarded to the same port on Kharej. Mode selects traffic type:
  tcp, udp, or dual (both).
"""
import ipaddress
import os
import secrets
import shlex
import time
from core.storage import get_pools, save_pool, delete_pool, atomic_update
from core.validation import validate_pool_name, validate_ports, validate_port
from core.transport_change import connect
from core.gre import write

DIRECTORY = '/etc/vxlb/frp'
SERVER_BIN = '/usr/local/bin/frps'
CLIENT_BIN = '/usr/local/bin/frpc'

MODES = ('tcp', 'udp', 'dual')

MODE_LABELS = {
    'tcp': 'FRP TCP',
    'udp': 'FRP UDP',
    'dual': 'FRP TCP+UDP',
}


def execute(ssh, command, timeout=30):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or 'FRP command failed')


def normalize_mode(mode):
    if mode not in MODES:
        raise ValueError(f'حالت FRP نامعتبر: {mode}')
    return mode


def install_frp(ssh, role):
    binary = SERVER_BIN if role == 'iran' else CLIENT_BIN
    code, _, err = ssh.execute(f'test "$(id -u)" = 0 && test -x {shlex.quote(binary)} && command -v python3 && command -v systemctl')
    if code == 0:
        return True, 'FRP binary verified'
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _, arch_raw, _ = ssh.execute('uname -m')
        remote_arch = arch_raw.strip().lower()
        arch_dir = 'x86_64' if remote_arch in ('x86_64', 'amd64') else 'aarch64' if remote_arch in ('aarch64', 'arm64') else remote_arch
        file_name = 'frps' if role == 'iran' else 'frpc'
        candidate = os.path.join(base_dir, 'bin', arch_dir, file_name)
        from core.dependency_manifest import get_dependency_manifest, verify_file_sha256
        manifest = get_dependency_manifest(file_name)
        expected = (manifest.architectures.get(arch_dir, {}) if manifest else {}).get('sha256')
        if not os.path.isfile(candidate):
            return False, f'FRP binary not in offline depot: {candidate}'
        if not expected:
            return False, f'FRP manifest missing checksum for {file_name}/{arch_dir}'
        if not verify_file_sha256(candidate, expected):
            return False, f'FRP binary checksum mismatch for {candidate}'
        if not hasattr(ssh, 'upload_binary'):
            return False, 'SSH manager has no upload_binary support'
        if not ssh.upload_binary(candidate, binary, mode=0o755):
            return False, 'Failed to upload FRP binary to server'
        code, out, err = ssh.execute(f'test -x {shlex.quote(binary)} && command -v python3 && command -v systemctl')
        if code != 0:
            return False, f'FRP post-install check failed: {err or out}'
    except Exception as e:
        return False, f'FRP install error: {e}'
    return True, 'FRP binary verified'


def _server_config(port, token):
    return f'bindPort = {int(port)}\nauth.token = "{token}"\n'


def _client_config(kh_ip, port, token, mode, client_ports):
    # The published client port is the user's TCP entry on every mode. UDP mode
    # also forwards UDP; without the TCP proxy that port accepts no TCP connection.
    blocks = []
    for p in client_ports:
        p = int(p)
        blocks.append(
            f'[[proxies]]\nname = "p{p}"\ntype = "tcp"\nlocalIP = "127.0.0.1"\n'
            f'localPort = {p}\nremotePort = {p}\n'
        )
        if mode in ('udp', 'dual'):
            blocks.append(
                f'[[proxies]]\nname = "p{p}u"\ntype = "udp"\nlocalIP = "127.0.0.1"\n'
                f'localPort = {p}\nremotePort = {p}\n'
            )
    return (f'serverAddr = "{kh_ip}"\nserverPort = {int(port)}\nauth.token = "{token}"\n\n'
            + '\n'.join(blocks))


def _unit(binary, cfg):
    return f'''[Unit]
Description=VX-LB FRP Tunnel node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} -c {cfg}
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


def _service_name(node, role):
    return f'vxlb-frp{role}-{node["frp"]["id"]}.service'


def create(name, kharej, servers, ports, settings, callback=None):
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        mode = normalize_mode((settings or {}).get('mode', 'tcp'))
        token = str((settings or {}).get('token') or secrets.token_hex(16))
        port = int(validate_port((settings or {}).get('port', 7000)))
        if len(token) < 8:
            raise ValueError('توکن FRP باید حداقل ۸ نویسه باشد')
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
        'transport': 'frp',
        'engine': 'frp',
        'frp_mode': mode,
        'camouflage': {'mode': mode, 'token': token, 'port': port},
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
    node = dict(server, node_name='frp' + secrets.token_hex(8), engine='frp', transport='frp', provisioning=True)

    def progress(message, status='running', error=''):
        def update(data):
            data['pools'][name].setdefault('node_additions', {}).setdefault(server['ip'], {}).update({
                'ip': server['ip'], 'name': server['name'], 'status': status, 'message': message, 'error': error, 'updated_at': time.time()
            })
        atomic_update(update)
        if callback:
            callback(message)

    try:
        progress('اتصال به سرورها و بررسی FRP')
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool['kharej_server'])
        sessions.append(kharej)

        for ssh, role in zip(sessions, ('iran', 'kharej')):
            ok, msg = install_frp(ssh, role)
            if not ok:
                raise RuntimeError(msg)

        port = int(validate_port(prof['port']))
        token = prof['token']
        mode = prof['mode']
        node['frp'] = {'id': node['node_name'], 'mode': mode, 'token': token, 'port': port}
        node['tunnel_port'] = port

        def reserve(data):
            data['pools'][name]['nodes'].append(node)
        atomic_update(reserve)

        # frps (server) lives on Iran and exposes the client ports; frpc (client)
        # lives on Kharej and tunnels traffic back to Iran. Users connect to Iran.
        server_cfg = _server_config(port, token)
        client_cfg = _client_config(node['ip'], port, token, mode, pool['client_ports'])
        ir_svc = _service_name(node, 's')
        kh_svc = _service_name(node, 'c')
        ir_cfg = f'{DIRECTORY}/frps-{node["node_name"]}.toml'
        kh_cfg = f'{DIRECTORY}/frpc-{node["node_name"]}.toml'

        execute(iran, f'mkdir -p {DIRECTORY}')
        execute(kharej, f'mkdir -p {DIRECTORY}')
        write(iran, ir_cfg, server_cfg)
        write(kharej, kh_cfg, client_cfg)
        write(iran, f'/etc/systemd/system/{ir_svc}', _unit(SERVER_BIN, ir_cfg))
        write(kharej, f'/etc/systemd/system/{kh_svc}', _unit(CLIENT_BIN, kh_cfg))
        execute(iran, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(ir_svc)}')
        execute(kharej, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(kh_svc)}')

        progress('نود FRP فعال شد', 'succeeded')
        def finish(data):
            member = next(n for n in data['pools'][name]['nodes'] if n['node_name'] == node['node_name'])
            member.update(provisioning=False, status='active')
        atomic_update(finish)
        return True, 'نود FRP فعال شد'

    except Exception as failure:
        errors = []
        try:
            for ssh, svc in ((iran, _service_name(node, 'c')), (kharej, _service_name(node, 's'))):
                try:
                    execute(ssh, f'systemctl disable --now {shlex.quote(svc)} 2>/dev/null || true')
                    execute(ssh, f'rm -f {DIRECTORY}/frp*-{node["node_name"]}.toml /etc/systemd/system/{svc}')
                    execute(ssh, 'systemctl daemon-reload')
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
        for server, role in ((node, 's'), (pool['kharej_server'], 'c')):
            sessions.append(connect(server))
        for ssh, role in zip(sessions, ('s', 'c')):
            svc = _service_name(node, role)
            execute(ssh, f'systemctl disable --now {shlex.quote(svc)} 2>/dev/null || true')
            execute(ssh, f'rm -f {DIRECTORY}/frp*-{node["node_name"]}.toml /etc/systemd/system/{svc}')
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
        for server, role in ((node, 's'), (pool['kharej_server'], 'c')):
            sessions.append(connect(server))
        ok = True
        for ssh, role in zip(sessions, ('s', 'c')):
            svc = _service_name(node, role)
            code, _, _ = ssh.execute(f'systemctl is-active --quiet {shlex.quote(svc)}')
            ok = ok and code == 0
        if not ok:
            return 'DOWN', 'سرویس FRP در یکی از سرورها فعال نیست', {}
        details = {p: {'status': 'HEALTHY', 'reason': 'سرویس FRP فعال است'} for p in ports}
        return 'HEALTHY', 'سرویس FRP فعال است', details
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
            client_cfg = _client_config(node['ip'], node['frp']['port'],
                                        node['frp']['token'], node['frp']['mode'], ports)
            kh_cfg = f'{DIRECTORY}/frpc-{node["node_name"]}.toml'
            kh_svc = _service_name(node, 'c')
            write(kh_ssh, kh_cfg, client_cfg)
            execute(kh_ssh, f'systemctl restart {shlex.quote(kh_svc)}')
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
