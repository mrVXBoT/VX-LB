"""Rathole engine: lightweight, secure NAT-traversal reverse proxy (Rust).

Uses the bundled `rathole` binary (rapiz1/rathole v0.5.0). Topology matches
the rest of VX-LB: users connect to the Iran edge, which exposes the client
ports; Kharej is the egress that actually owns the destination service.

  - Iran (server): `[server] bind_addr` control port + `[server.services.X]`
    bind_addr = client port.
  - Kharej (client): `[client] remote_addr` = Iran control port + per-service
    `local_addr` = client port.

The pool's *transport type* is the `[server.transport]`/`[client.transport]`
block, exactly as in upstream (rapiz1/rathole):
  tcp | tls | noise | websocket
Each forwarded port is a service whose `type` (tcp/udp) selects the forwarded
protocol. The `noise` transport auto-generates an X25519 keypair on the server
via `rathole --genkey` (server keeps the private key, client pins the public key).
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

DIRECTORY = '/etc/vxlb/rathole'
BINARY = '/usr/local/bin/rathole'

# Upstream `[server.transport] type` values.
TRANSPORTS = ('tcp', 'tls', 'noise', 'websocket')

TRANSPORT_LABELS = {
    'tcp': 'TCP (بدون رمزنگاری)',
    'tls': 'TLS (گواهی PKCS#12)',
    'noise': 'Noise (رمزنگاری بدون گواهی)',
    'websocket': 'WebSocket (TLS اختیاری)',
}

# Forwarded protocol per service (upstream `[server.services.X] type`).
SERVICE_PROTOCOLS = ('tcp', 'udp')

_NOISE_PATTERN = 'Noise_NK_25519_ChaChaPoly_BLAKE2s'


def execute(ssh, command, timeout=30):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or 'Rathole command failed')
    return out


def validate_transport(transport):
    if transport not in TRANSPORTS:
        raise ValueError(f'روش انتقال Rathole نامعتبر: {transport}')
    return transport


def validate_proto(proto):
    if proto not in SERVICE_PROTOCOLS:
        raise ValueError(f'پروتکل سرویس Rathole نامعتبر: {proto}')
    return proto


def install_rathole(ssh):
    code, _, err = ssh.execute(f'test "$(id -u)" = 0 && test -x {shlex.quote(BINARY)} && command -v systemctl')
    if code == 0:
        return True, 'Rathole binary verified'
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _, arch_raw, _ = ssh.execute('uname -m')
        remote_arch = arch_raw.strip().lower()
        arch_dir = 'x86_64' if remote_arch in ('x86_64', 'amd64') else 'aarch64' if remote_arch in ('aarch64', 'arm64') else remote_arch
        candidate = os.path.join(base_dir, 'bin', arch_dir, 'rathole')
        from core.dependency_manifest import get_dependency_manifest, verify_file_sha256
        manifest = get_dependency_manifest('rathole')
        expected = (manifest.architectures.get(arch_dir, {}) if manifest else {}).get('sha256')
        if not os.path.isfile(candidate):
            return False, f'Rathole binary not in offline depot: {candidate}'
        if not expected:
            return False, f'Rathole manifest missing checksum for {arch_dir}'
        if not verify_file_sha256(candidate, expected):
            return False, f'Rathole binary checksum mismatch for {candidate}'
        if not hasattr(ssh, 'upload_binary'):
            return False, 'SSH manager has no upload_binary support'
        if not ssh.upload_binary(candidate, BINARY, mode=0o755):
            return False, 'Failed to upload rathole binary to server'
        code, out, err = ssh.execute(f'test -x {shlex.quote(BINARY)} && command -v systemctl')
        if code != 0:
            return False, f'Rathole post-install check failed: {err or out}'
    except Exception as e:
        return False, f'Rathole install error: {e}'
    return True, 'Rathole binary verified'


def genkey(ssh):
    """Generate an X25519 keypair via `rathole --genkey` (upstream)."""
    out = execute(ssh, f'{BINARY} --genkey', timeout=30)
    priv = re.search(r'Private Key:\s*(\S+)', out)
    pub = re.search(r'Public Key:\s*(\S+)', out)
    if not priv or not pub:
        raise RuntimeError('Rathole --genkey did not produce a keypair')
    return priv.group(1).strip(), pub.group(1).strip()


def _transport_lines(side, transport, settings):
    """Return `[<side>.transport]` + protocol block, per upstream schema."""
    if transport == 'tls':
        if side == 'server':
            if not settings.get('pkcs12') or not settings.get('pkcs12_password'):
                raise RuntimeError('TLS انتقال نیازمند مسیر PKCS#12 و رمز آن است')
            return [
                f'[{side}.transport]\ntype = "tls"\n',
                f'[{side}.transport.tls]\npkcs12 = "{settings["pkcs12"]}"\n'
                f'pkcs12_password = "{settings["pkcs12_password"]}"\n',
            ]
        if not settings.get('trusted_root'):
            raise RuntimeError('TLS انتقال نیازمند trusted_root (گواهی ریشه) در سمت کلاینت است')
        host = settings.get('hostname') or ''
        return [
            f'[{side}.transport]\ntype = "tls"\n',
            f'[{side}.transport.tls]\ntrusted_root = "{settings["trusted_root"]}"\n'
            + (f'hostname = "{host}"\n' if host else ''),
        ]
    if transport == 'noise':
        lines = [
            f'[{side}.transport]\ntype = "noise"\n',
            f'[{side}.transport.noise]\npattern = "{_NOISE_PATTERN}"\n',
        ]
        if side == 'server':
            if not settings.get('noise_local_priv'):
                raise RuntimeError('Noise انتقال نیازمند کلید خصوصی سرور است')
            lines.append(f'local_private_key = "{settings["noise_local_priv"]}"\n')
        else:
            if not settings.get('noise_remote_pub'):
                raise RuntimeError('Noise انتقال نیازمند کلید عمومی سرور است')
            lines.append(f'remote_public_key = "{settings["noise_remote_pub"]}"\n')
        return lines
    if transport == 'websocket':
        ws_tls = bool(settings.get('ws_tls'))
        lines = [
            f'[{side}.transport]\ntype = "websocket"\n',
            f'[{side}.transport.websocket]\ntls = {"true" if ws_tls else "false"}\n',
        ]
        if ws_tls:
            lines += _transport_lines(side, 'tls', settings)
        return lines
    # tcp
    return [
        f'[{side}.transport]\ntype = "tcp"\n',
        f'[{side}.transport.tcp]\nnodelay = true\n',
    ]


def _server_config(port, token, transport, proto, client_ports, settings):
    blocks = [
        f'[server]\nbind_addr = "0.0.0.0:{int(port)}"\ndefault_token = "{token}"\n'
        f'heartbeat_interval = 30\n',
    ]
    blocks += _transport_lines('server', transport, settings)
    for p in client_ports:
        p = int(p)
        blocks.append(f'[server.services.{p}]\ntype = "{proto}"\nbind_addr = "0.0.0.0:{p}"\n')
    return '\n'.join(blocks)


def _client_config(iran_ip, port, token, transport, proto, client_ports, settings):
    blocks = [
        f'[client]\nremote_addr = "{iran_ip}:{int(port)}"\ndefault_token = "{token}"\n'
        f'heartbeat_timeout = 40\nretry_interval = 1\n',
    ]
    blocks += _transport_lines('client', transport, settings)
    for p in client_ports:
        p = int(p)
        blocks.append(f'[client.services.{p}]\ntype = "{proto}"\nlocal_addr = "127.0.0.1:{p}"\n')
    return '\n'.join(blocks)


def _unit(role, cfg):
    return f'''[Unit]
Description=VX-LB Rathole Tunnel {role}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={BINARY} {cfg}
Restart=always
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
    return f'vxlb-rathole{role}-{node["node_name"]}.service'


def create(name, kharej, servers, ports, settings, callback=None):
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        transport = validate_transport((settings or {}).get('transport', 'tcp'))
        proto = validate_proto((settings or {}).get('proto', 'tcp'))
        token = str((settings or {}).get('token') or secrets.token_hex(16))
        port = int(validate_port((settings or {}).get('port', 2333)))
        if len(token) < 8:
            raise ValueError('توکن Rathole باید حداقل ۸ نویسه باشد')
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
        'transport': 'rathole',
        'engine': 'rathole',
        'rathole_transport': transport,
        'camouflage': {
            'transport': transport,
            'proto': proto,
            'token': token,
            'port': port,
            'pkcs12': (settings or {}).get('pkcs12'),
            'pkcs12_password': (settings or {}).get('pkcs12_password'),
            'trusted_root': (settings or {}).get('trusted_root'),
            'hostname': (settings or {}).get('hostname'),
            'ws_tls': bool((settings or {}).get('ws_tls')),
        },
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
    node = dict(server, node_name='rath' + secrets.token_hex(8), engine='rathole', transport='rathole', provisioning=True)

    def progress(message, status='running', error=''):
        def update(data):
            data['pools'][name].setdefault('node_additions', {}).setdefault(server['ip'], {}).update({
                'ip': server['ip'], 'name': server['name'], 'status': status, 'message': message, 'error': error, 'updated_at': time.time()
            })
        atomic_update(update)
        if callback:
            callback(message)

    try:
        progress('اتصال به سرورها و بررسی Rathole')
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool['kharej_server'])
        sessions.append(kharej)

        for ssh in sessions:
            ok, msg = install_rathole(ssh)
            if not ok:
                raise RuntimeError(msg)

        port = int(validate_port(prof['port']))
        token = prof['token']
        transport = prof['transport']
        proto = prof['proto']
        settings = dict(prof)

        if transport == 'noise':
            server_priv, server_pub = genkey(iran)
            settings['noise_local_priv'] = server_priv
            settings['noise_remote_pub'] = server_pub

        node['rathole'] = {
            'id': node['node_name'], 'transport': transport, 'proto': proto,
            'token': token, 'port': port, 'settings': settings,
        }
        node['tunnel_port'] = port

        def reserve(data):
            data['pools'][name]['nodes'].append(node)
        atomic_update(reserve)

        # rathole server lives on Iran and exposes the client ports; the client
        # lives on Kharej and points at the local egress service. Users connect
        # to the Iran node's public client ports.
        server_cfg = _server_config(port, token, transport, proto, pool['client_ports'], settings)
        client_cfg = _client_config(node['ip'], port, token, transport, proto, pool['client_ports'], settings)
        ir_svc = _service_name(node, 's')
        kh_svc = _service_name(node, 'c')
        ir_cfg = f'{DIRECTORY}/server-{node["node_name"]}.toml'
        kh_cfg = f'{DIRECTORY}/client-{node["node_name"]}.toml'

        execute(iran, f'mkdir -p {DIRECTORY}')
        execute(kharej, f'mkdir -p {DIRECTORY}')
        write(iran, ir_cfg, server_cfg)
        write(kharej, kh_cfg, client_cfg)
        write(iran, f'/etc/systemd/system/{ir_svc}', _unit('server', ir_cfg))
        write(kharej, f'/etc/systemd/system/{kh_svc}', _unit('client', kh_cfg))
        execute(iran, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(ir_svc)}')
        execute(kharej, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(kh_svc)}')

        progress('نود Rathole فعال شد', 'succeeded')
        def finish(data):
            member = next(n for n in data['pools'][name]['nodes'] if n['node_name'] == node['node_name'])
            member.update(provisioning=False, status='active')
        atomic_update(finish)
        return True, 'نود Rathole فعال شد'

    except Exception as failure:
        errors = []
        try:
            for ssh, svc in ((iran, _service_name(node, 's')), (kharej, _service_name(node, 'c'))):
                try:
                    execute(ssh, f'systemctl disable --now {shlex.quote(svc)} 2>/dev/null || true')
                    execute(ssh, f'rm -f {DIRECTORY}/*-{node["node_name"]}.toml /etc/systemd/system/{svc}')
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
            execute(ssh, f'rm -f {DIRECTORY}/*-{node["node_name"]}.toml /etc/systemd/system/{svc}')
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
            return 'DOWN', 'سرویس Rathole در یکی از سرورها فعال نیست', {}
        details = {p: {'status': 'HEALTHY', 'reason': 'سرویس Rathole فعال است'} for p in ports}
        from core.link_latency import annotate
        annotate(sessions[0], pool['kharej_server']['ip'], details)
        return 'HEALTHY', 'سرویس Rathole فعال است', details
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
            info = node['rathole']
            settings = info.get('settings') or {}
            server_cfg = _server_config(info['port'], info['token'], info['transport'],
                                        info['proto'], ports, settings)
            client_cfg = _client_config(node['ip'], info['port'], info['token'], info['transport'],
                                        info['proto'], ports, settings)
            ir_cfg = f'{DIRECTORY}/server-{node["node_name"]}.toml'
            kh_cfg = f'{DIRECTORY}/client-{node["node_name"]}.toml'
            write(ir_ssh, ir_cfg, server_cfg)
            write(kh_ssh, kh_cfg, client_cfg)
            execute(ir_ssh, f'systemctl restart {shlex.quote(_service_name(node, "s"))}')
            execute(kh_ssh, f'systemctl restart {shlex.quote(_service_name(node, "c"))}')
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
