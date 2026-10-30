"""Managed lifecycle for the ParsaKSH Spoof Tunnel engine.

ParsaKSH/spoof-tunnel (v3, UDP-pipe mode) is a mutual IP-spoofing tunnel with a
Go/Rust core. The client (Iran, mode=local) exposes a UDP pipe; the server
(Kharej, mode=remote) listens for tunneled datagrams and forwards them to a
configured endpoint.

Topology matches the rest of VX-LB:
  - Iran node runs the core in `local` mode, listening on UDP
    0.0.0.0:<client_udp_port> (the pool's first client port).
  - Kharej runs the core in `remote` mode, listening on `data_port` and
    forwarding received datagrams to `forward_target` (e.g. a local WireGuard
    or DNS endpoint).

Raw sockets require CAP_NET_RAW / root. Binaries ship for x86_64 and arm64.
"""
import ipaddress
import json
import os
import re
import secrets
import shlex
import time

from core.storage import get_pools, save_pool, delete_pool, atomic_update
from core.validation import validate_pool_name, validate_ports, validate_port
from core.transport_change import connect
from core.gre import write

DIRECTORY = '/etc/vxlb/parsaksh'
BINARY = '/usr/local/bin/spoof'
TRANSPORT = 'parsaksh'

TRANSPORTS = ('udp', 'icmp', 'icmpv6', 'tcp')
_TRANSPORT_HINTS = {
    'udp': 'UDP datagrams with shiftable source ports',
    'icmp': 'ICMP Echo (looks like ping)',
    'icmpv6': 'ICMPv6 payload over IPv4',
    'tcp': 'TCP SYN-flag packets (last to be blocked)',
}


def execute(ssh, command, timeout=30):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or 'ParsaKSH command failed')
    return out


def install_binary(ssh):
    code, _, err = ssh.execute(
        f'test "$(id -u)" = 0 && test -x {shlex.quote(BINARY)} && command -v systemctl'
    )
    if code == 0:
        return True, 'ParsaKSH binary verified'
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _, arch_raw, _ = ssh.execute('uname -m')
    remote_arch = arch_raw.strip().lower()
    arch_dir = 'x86_64' if remote_arch in ('x86_64', 'amd64') else 'aarch64' if remote_arch in ('aarch64', 'arm64') else remote_arch
    candidate = os.path.join(base_dir, 'bin', arch_dir, 'spoof')
    from core.dependency_manifest import get_dependency_manifest, verify_file_sha256
    manifest = get_dependency_manifest(TRANSPORT)
    expected = (manifest.architectures.get(arch_dir, {}) if manifest else {}).get('sha256')
    if not os.path.isfile(candidate):
        return False, f'ParsaKSH binary not in offline depot: {candidate}'
    if not expected:
        return False, f'ParsaKSH manifest missing checksum for {arch_dir}'
    if not verify_file_sha256(candidate, expected):
        return False, f'ParsaKSH binary checksum mismatch for {candidate}'
    if not hasattr(ssh, 'upload_binary'):
        return False, 'SSH manager has no upload_binary support'
    if not ssh.upload_binary(candidate, BINARY, mode=0o755):
        return False, 'Failed to upload ParsaKSH binary to server'
    code, out, err = ssh.execute(f'test -x {shlex.quote(BINARY)} && command -v systemctl')
    if code != 0:
        return False, f'ParsaKSH post-install check failed: {err or out}'
    return True, 'ParsaKSH binary verified'


def _client_config(iran_ip, kharej_ip, cfg):
    return json.dumps({
        'mode': 'local',
        'listen': f'0.0.0.0:{cfg["client_udp_port"]}',
        'remote': kharej_ip,
        'remote_port': cfg['data_port'],
        'recv_port': cfg['recv_port'],
        'spoof_ip': cfg['spoof_ip'],
        'spoof_port': cfg['spoof_port'],
        'peer_spoof_ip': cfg['server_spoof_ip'],
    }, indent=2)


def _server_config(kharej_ip, iran_ip, cfg):
    return json.dumps({
        'mode': 'remote',
        'listen_port': cfg['data_port'],
        'forward': cfg['forward_target'],
        'client_ip': iran_ip,
        'client_port': cfg['recv_port'],
        'spoof_ip': cfg['server_spoof_ip'],
        'spoof_port': cfg['spoof_port'],
        'peer_spoof_ip': cfg['spoof_ip'],
    }, indent=2)


def _unit(role, cfg_path):
    return f'''[Unit]
Description=VX-LB ParsaKSH Spoof Tunnel {role}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={BINARY} run -c {cfg_path}
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
'''


def _service_name(node, role):
    return f'vxlb-parsaksh{role}-{node["node_name"]}.service'


def create(name, kharej, servers, ports, settings, callback=None):
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        data_port = int(validate_port((settings or {}).get('data_port', 8090)))
        recv_port = int(validate_port((settings or {}).get('recv_port', 5001)))
        spoof_port = int(validate_port((settings or {}).get('spoof_port', 443)))
        client_sip = str((settings or {}).get('spoof_ip') or '8.8.4.4')
        server_sip = str((settings or {}).get('server_spoof_ip') or '1.2.3.4')
        ipaddress.IPv4Address(client_sip)
        ipaddress.IPv4Address(server_sip)
        forward_target = str((settings or {}).get('forward_target') or '').strip() or None
        if forward_target and ':' not in forward_target:
            raise ValueError('forward_target must be host:port')
        transport = str((settings or {}).get('transport') or 'udp').strip().lower()
        if transport not in TRANSPORTS:
            raise ValueError(f'Invalid ParsaKSH transport: {transport}')
        if not ports or not servers or name in get_pools():
            raise ValueError('یک نام استخر بلااستفاده، حداقل یک پورت و سرورهای ایران الزامی است')
        if len({server['ip'] for server in servers}) != len(servers):
            raise ValueError('سرور تکراری مجاز نیست')
        if any(server['ip'] == kharej['ip'] for server in servers):
            raise ValueError('دو سمت تونل باید متفاوت باشند')
    except (ValueError, TypeError) as error:
        return False, str(error), {}

    if forward_target is None:
        forward_target = f'{kharej["ip"]}:{data_port}'
    cfg = {
        'data_port': data_port,
        'recv_port': recv_port,
        'spoof_port': spoof_port,
        'client_udp_port': int(ports[0]),
        'spoof_ip': client_sip,
        'server_spoof_ip': server_sip,
        'forward_target': forward_target,
        'transport': transport,
    }

    save_pool(name, {
        'name': name,
        'transport': TRANSPORT,
        'engine': TRANSPORT,
        'camouflage': cfg,
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
    profile = pool['camouflage']
    node = dict(server, node_name='pk' + secrets.token_hex(8), engine=TRANSPORT, transport=TRANSPORT, provisioning=True)
    iran = None
    kharej = None

    def progress(message, status='running', error=''):
        def update(data):
            data['pools'][name].setdefault('node_additions', {}).setdefault(server['ip'], {}).update({
                'ip': server['ip'], 'name': server['name'], 'status': status, 'message': message, 'error': error, 'updated_at': time.time()
            })
        atomic_update(update)
        if callback:
            callback(message)

    try:
        progress('اتصال به سرورها و بررسی ParsaKSH')
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool['kharej_server'])
        sessions.append(kharej)

        for ssh in sessions:
            ok, msg = install_binary(ssh)
            if not ok:
                raise RuntimeError(msg)

        node['parsaksh'] = {
            'id': node['node_name'],
            'data_port': profile['data_port'],
            'recv_port': profile['recv_port'],
            'client_udp_port': profile['client_udp_port'],
            'spoof_ip': profile['spoof_ip'],
            'server_spoof_ip': profile['server_spoof_ip'],
            'forward_target': profile['forward_target'],
            'transport': profile['transport'],
        }
        node['tunnel_port'] = profile['data_port']

        def reserve(data):
            data['pools'][name]['nodes'].append(node)
        atomic_update(reserve)

        ir_cfg = f'{DIRECTORY}/client-{node["node_name"]}.json'
        kh_cfg = f'{DIRECTORY}/server-{node["node_name"]}.json'
        ir_svc = _service_name(node, 'c')
        kh_svc = _service_name(node, 's')

        execute(iran, f'mkdir -p {DIRECTORY}')
        execute(kharej, f'mkdir -p {DIRECTORY}')
        write(iran, ir_cfg, _client_config(node['ip'], pool['kharej_server']['ip'], profile))
        write(kharej, kh_cfg, _server_config(pool['kharej_server']['ip'], node['ip'], profile))
        write(iran, f'/etc/systemd/system/{ir_svc}', _unit('client', ir_cfg))
        write(kharej, f'/etc/systemd/system/{kh_svc}', _unit('server', kh_cfg))
        execute(iran, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(ir_svc)}')
        execute(kharej, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(kh_svc)}')

        progress('نود ParsaKSH فعال شد', 'succeeded')

        def finish(data):
            member = next(n for n in data['pools'][name]['nodes'] if n['node_name'] == node['node_name'])
            member.update(provisioning=False, status='active')
        atomic_update(finish)
        return True, 'نود ParsaKSH فعال شد'

    except Exception as failure:
        errors = []
        try:
            for ssh, svc in (
                (iran, _service_name(node, 'c')),
                (kharej, _service_name(node, 's')),
            ):
                if ssh is None:
                    continue
                try:
                    execute(ssh, f'systemctl disable --now {shlex.quote(svc)} 2>/dev/null || true')
                    execute(ssh, f'rm -f {DIRECTORY}/*-{node["node_name"]}.json /etc/systemd/system/{svc}')
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
        iran = connect(node)
        kharej = connect(pool['kharej_server'])
        sessions.extend((iran, kharej))
        for ssh, svc in (
            (iran, _service_name(node, 'c')),
            (kharej, _service_name(node, 's')),
        ):
            execute(ssh, f'systemctl disable --now {shlex.quote(svc)} 2>/dev/null || true')
            execute(ssh, f'rm -f {DIRECTORY}/*-{node["node_name"]}.json /etc/systemd/system/{svc}')
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
    sessions = []
    try:
        pool = get_pools()[name]
        iran = connect(node)
        sessions.append(iran)
        try:
            kharej = connect(pool['kharej_server'])
            sessions.append(kharej)
        except Exception:
            kharej = None
        ok = True
        for ssh, svc in (
            (iran, _service_name(node, 'c')),
            (kharej, _service_name(node, 's')),
        ):
            if ssh is None:
                ok = False
                continue
            code, _, _ = ssh.execute(f'systemctl is-active --quiet {shlex.quote(svc)}')
            ok = ok and code == 0
        if not ok:
            return 'DOWN', 'سرویس ParsaKSH در یکی از سرورها فعال نیست', {}
        udp_port = int((node.get('parsaksh') or {}).get('client_udp_port') or (pool.get('camouflage') or {}).get('client_udp_port') or (ports or [0])[0])
        listen_code, _, _ = iran.execute(f'ss -lunp | grep -q ":{udp_port}\\b"')
        if listen_code != 0:
            details = {p: {'status': 'DEGRADED', 'reason': 'سرویس فعال است اما شنونده UDP یافت نشد'} for p in ports}
            from core.link_latency import annotate
            annotate(iran, pool['kharej_server']['ip'], details)
            return 'DEGRADED', 'سرویس فعال است اما شنونده UDP روی نود ایران پیدا نشد', details
        details = {p: {'status': 'HEALTHY', 'reason': 'سرویس ParsaKSH فعال و شنونده UDP در دسترس است'} for p in ports}
        from core.link_latency import annotate
        annotate(iran, pool['kharej_server']['ip'], details)
        return 'HEALTHY', 'سرویس ParsaKSH فعال است', details
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
        udp_port = int(ports[0])
        for node in pool['nodes']:
            ir_ssh = connect(node)
            kh_ssh = connect(pool['kharej_server'])
            sessions.append((ir_ssh, kh_ssh))
            profile = dict(pool['camouflage'], client_udp_port=udp_port)
            ir_cfg = f'{DIRECTORY}/client-{node["node_name"]}.json'
            write(ir_ssh, ir_cfg, _client_config(node['ip'], pool['kharej_server']['ip'], profile))
            execute(ir_ssh, f'systemctl restart {shlex.quote(_service_name(node, "c"))}')

        def commit(data):
            data['pools'][name]['client_ports'] = ports
            for member in data['pools'][name]['nodes']:
                if member.get('parsaksh'):
                    member['parsaksh']['client_udp_port'] = udp_port
        atomic_update(commit)
        return True, 'پورت‌های UDP به‌روزرسانی شدند'
    except Exception as failure:
        return False, str(failure)
    finally:
        for ir_ssh, kh_ssh in sessions:
            ir_ssh.close()
            kh_ssh.close()
