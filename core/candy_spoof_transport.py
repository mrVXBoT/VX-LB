"""Managed lifecycle for the Candy-Spoof bidirectional IP spoofing tunnel.

Candy-Spoof (AmiRCandy/Candy-Spoof) is a Rust binary that spoofs the source
IP on both ends of a tunnel. The client exposes a local SOCKS5 proxy and the
server is the egress that forwards to the destination service.

Topology matches the rest of VX-LB:
  - Iran node runs the Candy-Spoof *client* (SOCKS5 proxy). Applications route
    through the Iran node's SOCKS5 port, which equals the pool's first client
    port.
  - Kharej runs the Candy-Spoof *server* (tunnel endpoint / egress).

Both binaries require CAP_NET_RAW / root (raw sockets for spoofing). The
binaries are shipped as prebuilt Linux x86_64 assets from GitHub Releases and
are bundled in the offline depot (bin/x86_64/).
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

DIRECTORY = '/etc/vxlb/candy'

BINARY_NAME = {
    'client': 'candy-spoof-client',
    'server': 'candy-spoof-server',
}

BINARY = {
    'client': '/usr/local/bin/candy-spoof-client',
    'server': '/usr/local/bin/candy-spoof-server',
}

TRANSPORT = 'candy-spoof'

_DEFAULT_CLIENT_SPOOFED_IP = '8.8.4.4'
_DEFAULT_SERVER_SPOOFED_IP = '1.2.3.4'


def execute(ssh, command, timeout=30):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or 'Candy-Spoof command failed')
    return out


def _detect_interface(ssh):
    try:
        out = execute(ssh, 'ip route get 1.1.1.1')
        match = re.search(r'\bdev\s+(\S+)', out)
        if match and match.group(1):
            return match.group(1)
    except Exception:
        pass
    return 'eth0'


def install_binary(ssh, role):
    """Upload and verify the bundled binary for the given endpoint role."""
    code, _, err = ssh.execute(
        f'test "$(id -u)" = 0 && test -x {shlex.quote(BINARY[role])} && command -v systemctl'
    )
    if code == 0:
        return True, 'Candy-Spoof binary verified'
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _, arch_raw, _ = ssh.execute('uname -m')
    remote_arch = arch_raw.strip().lower()
    arch_dir = 'x86_64' if remote_arch in ('x86_64', 'amd64') else 'aarch64' if remote_arch in ('aarch64', 'arm64') else remote_arch
    if arch_dir != 'x86_64':
        return False, f'Candy-Spoof currently ships Linux x86_64 binaries only (node arch: {remote_arch})'
    candidate = os.path.join(base_dir, 'bin', arch_dir, BINARY_NAME[role])
    from core.dependency_manifest import get_dependency_manifest, verify_file_sha256
    manifest = get_dependency_manifest(BINARY_NAME[role])
    expected = (manifest.architectures.get(arch_dir, {}) if manifest else {}).get('sha256')
    if not os.path.isfile(candidate):
        return False, f'Candy-Spoof binary not in offline depot: {candidate}'
    if not expected:
        return False, f'Candy-Spoof manifest missing checksum for {arch_dir}'
    if not verify_file_sha256(candidate, expected):
        return False, f'Candy-Spoof binary checksum mismatch for {candidate}'
    if not hasattr(ssh, 'upload_binary'):
        return False, 'SSH manager has no upload_binary support'
    if not ssh.upload_binary(candidate, BINARY[role], mode=0o755):
        return False, f'Failed to upload Candy-Spoof binary ({role}) to server'
    code, out, err = ssh.execute(f'test -x {shlex.quote(BINARY[role])} && command -v systemctl')
    if code != 0:
        return False, f'Candy-Spoof post-install check failed: {err or out}'
    return True, 'Candy-Spoof binary verified'


def _client_config(iran_ip, kharej_ip, cfg):
    pool_lines = ', '.join(f'"{ip}"' for ip in cfg['spoofed_ip_pool'])
    return (
        f'real_ip = "{iran_ip}"\n'
        f'peer_real_ip = "{kharej_ip}"\n'
        f'spoofed_ip = "{cfg["client_spoofed_ip"]}"\n'
        f'spoofed_ip_pool = [{pool_lines}]\n'
        f'peer_spoofed_ip = "{cfg["server_spoofed_ip"]}"\n'
        f'\ndata_port = {cfg["data_port"]}\n'
        f'icmp_id = {cfg["icmp_id"]}\n'
        f'\npre_shared_key = "{cfg["pre_shared_key"]}"\n'
        f'allowed_peers = []\n'
        f'\ntunnel_count = {cfg["tunnel_count"]}\n'
        f'mtu = {cfg["mtu"]}\n'
        f'initial_cwnd = {cfg["initial_cwnd"]}\n'
        f'\ninterface = "{cfg["interface"]}"\n'
        f'socks5_port = {cfg["socks5_port"]}\n'
    )


def _server_config(kharej_ip, iran_ip, cfg):
    return (
        f'real_ip = "{kharej_ip}"\n'
        f'peer_real_ip = "{iran_ip}"\n'
        f'spoofed_ip = "{cfg["server_spoofed_ip"]}"\n'
        f'spoofed_ip_pool = ["{cfg["server_spoofed_ip"]}"]\n'
        f'peer_spoofed_ip = "{cfg["client_spoofed_ip"]}"\n'
        f'\ndata_port = {cfg["data_port"]}\n'
        f'icmp_id = {cfg["icmp_id"]}\n'
        f'\npre_shared_key = "{cfg["pre_shared_key"]}"\n'
        f'allowed_peers = []\n'
        f'\ntunnel_count = {cfg["tunnel_count"]}\n'
        f'mtu = {cfg["mtu"]}\n'
        f'initial_cwnd = {cfg["initial_cwnd"]}\n'
        f'\ninterface = "{cfg["interface"]}"\n'
        f'socks5_port = {cfg["socks5_port"]}\n'
    )


def _unit(role, cfg_path):
    return f'''[Unit]
Description=VX-LB Candy-Spoof Tunnel {role}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={BINARY[role]} --config {cfg_path}
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
    return f'vxlb-candy{role}-{node["node_name"]}.service'


_RELAY_PREFIX = 'vxlb-candy-relay-'
_INTERNAL_SOCK_LOW = 40000
_INTERNAL_SOCK_HIGH = 54000


def _relay_service_name(port):
    return f'{_RELAY_PREFIX}{int(port)}.service'


def _ensure_socat(ssh):
    return


_RELAY_SCRIPT = r'''#!/usr/bin/env python3
import socket
import struct
import sys
import threading
import ipaddress


def _connect(host, port, dst_host, dst_port):
    s = socket.create_connection((host, port), timeout=20)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("socks5 greeting failed")
    ip = ipaddress.ip_address(str(dst_host))
    atyp = b"\x01" if ip.version == 4 else b"\x04"
    s.sendall(b"\x05\x01\x00" + atyp + ip.packed + struct.pack(">H", int(dst_port)))
    rep = s.recv(4)
    if len(rep) < 4 or rep[1] != 0:
        raise RuntimeError("socks5 connect failed")
    atyp = rep[3]
    if atyp == 1:
        need = 6
    elif atyp == 4:
        need = 18
    else:
        need = 1 + s.recv(1)[0] + 2
    while need > 0:
        data = s.recv(need)
        if not data:
            break
        need -= len(data)
    return s


def _pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except Exception:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def _handle(client, host, port, dst_host, dst_port):
    try:
        upstream = _connect(host, port, dst_host, dst_port)
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        return
    ta = threading.Thread(target=_pipe, args=(client, upstream), daemon=True)
    tb = threading.Thread(target=_pipe, args=(upstream, client), daemon=True)
    ta.start()
    tb.start()
    ta.join()
    tb.join()
    try:
        client.close()
    except Exception:
        pass
    try:
        upstream.close()
    except Exception:
        pass


def main():
    listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 53248
    dst_host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    dst_port = int(sys.argv[3]) if len(sys.argv) > 3 else listen_port
    proxy_port = int(sys.argv[4]) if len(sys.argv) > 4 else 1080
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", listen_port))
    srv.listen(512)
    while True:
        client, _ = srv.accept()
        threading.Thread(
            target=_handle,
            args=(client, "127.0.0.1", proxy_port, dst_host, dst_port),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()
'''


def _relay_unit(port, kharej_ip, proxy_port):
    return f'''[Unit]
Description=VX-LB Candy-Spoof TCP relay {port} -> Kharej
After=network-online.target vxlb-candyc-*.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/candy_relay.py {port} {kharej_ip} {port} {proxy_port}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
'''


def _install_relay(ssh, port, kharej_ip, proxy_port):
    svc = _relay_service_name(port)
    write(ssh, '/usr/local/bin/candy_relay.py', _RELAY_SCRIPT)
    execute(ssh, 'chmod 0755 /usr/local/bin/candy_relay.py')
    write(ssh, f'/etc/systemd/system/{svc}', _relay_unit(port, kharej_ip, proxy_port))
    execute(ssh, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(svc)}')


def _remove_relay(ssh, port):
    svc = _relay_service_name(port)
    execute(ssh, f'systemctl disable --now {shlex.quote(svc)} 2>/dev/null || true')
    execute(ssh, f'rm -f /etc/systemd/system/{svc}')


def _sync_relays(ssh, kharej_ip, ports, proxy_port):
    wanted = {int(p) for p in ports}
    code, out, _ = ssh.execute('systemctl list-unit-files | grep "vxlb-candy-relay-" || true')
    existing = set()
    for line in out.strip().splitlines():
        match = re.search(r'vxlb-candy-relay-(\d+)\.service', line)
        if match:
            existing.add(int(match.group(1)))
    changed = False
    for port in existing - wanted:
        _remove_relay(ssh, port)
        changed = True
    for port in wanted - existing:
        _install_relay(ssh, port, kharej_ip, proxy_port)
        changed = True
    if changed:
        execute(ssh, 'systemctl daemon-reload')


def create(name, kharej, servers, ports, settings, callback=None):
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        data_port = int(validate_port((settings or {}).get('data_port', 51820)))
        icmp_id = int((settings or {}).get('icmp_id') or secrets.randbelow(65536))
        if not 0 <= icmp_id <= 65535:
            raise ValueError('ICMP identifier must be a 16-bit value (0-65535)')
        psk = str((settings or {}).get('pre_shared_key') or secrets.token_hex(24))
        if len(psk) < 16:
            raise ValueError('Candy-Spoof pre-shared key must contain at least 16 characters')
        tunnel_count = int((settings or {}).get('tunnel_count', 4))
        if not 1 <= tunnel_count <= 32:
            raise ValueError('Parallel tunnel count must be between 1 and 32')
        mtu = int((settings or {}).get('mtu', 1380))
        if not 576 <= mtu <= 9000:
            raise ValueError('MTU must be an integer from 576 to 9000')
        initial_cwnd = float((settings or {}).get('initial_cwnd', 10.0))
        if initial_cwnd <= 0:
            raise ValueError('Initial congestion window must be positive')
        client_sip = str((settings or {}).get('client_spoofed_ip') or _DEFAULT_CLIENT_SPOOFED_IP)
        server_sip = str((settings or {}).get('server_spoofed_ip') or _DEFAULT_SERVER_SPOOFED_IP)
        ipaddress.IPv4Address(client_sip)
        ipaddress.IPv4Address(server_sip)
        raw_pool = (settings or {}).get('spoofed_ip_pool') or []
        if not isinstance(raw_pool, list) or not raw_pool:
            raw_pool = [client_sip, '1.1.1.1', '208.67.222.222']
        pool_ips = [str(ip) for ip in raw_pool]
        for ip in pool_ips:
            ipaddress.IPv4Address(ip)
        interface = str((settings or {}).get('interface') or '').strip() or None
        if not ports or not servers or name in get_pools():
            raise ValueError('یک نام استخر بلااستفاده، حداقل یک پورت و سرورهای ایران الزامی است')
        if len({server['ip'] for server in servers}) != len(servers):
            raise ValueError('سرور تکراری مجاز نیست')
        if any(server['ip'] == kharej['ip'] for server in servers):
            raise ValueError('دو سمت تونل باید متفاوت باشند')
    except (ValueError, TypeError) as error:
        return False, str(error), {}

    socks5_port = int(ports[0])
    internal_sock = secrets.randbelow(_INTERNAL_SOCK_HIGH - _INTERNAL_SOCK_LOW) + _INTERNAL_SOCK_LOW
    cfg = {
        'data_port': data_port,
        'icmp_id': icmp_id,
        'pre_shared_key': psk,
        'tunnel_count': tunnel_count,
        'mtu': mtu,
        'initial_cwnd': initial_cwnd,
        'interface': interface,
        'client_spoofed_ip': client_sip,
        'server_spoofed_ip': server_sip,
        'spoofed_ip_pool': pool_ips,
        'socks5_port': socks5_port,
        'socks5_port_internal': internal_sock,
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
    node = dict(server, node_name='candy' + secrets.token_hex(8), engine=TRANSPORT, transport=TRANSPORT, provisioning=True)
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
        progress('اتصال به سرورها و بررسی Candy-Spoof')
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool['kharej_server'])
        sessions.append(kharej)

        ok_client, msg_client = install_binary(iran, 'client')
        if not ok_client:
            raise RuntimeError(msg_client)
        ok_server, msg_server = install_binary(kharej, 'server')
        if not ok_server:
            raise RuntimeError(msg_server)

        iran_iface = profile.get('interface') or _detect_interface(iran)
        kharej_iface = profile.get('interface') or _detect_interface(kharej)
        internal_sock = int(profile.get('socks5_port_internal') or 1080)

        client_cfg = dict(profile, interface=iran_iface, socks5_port=internal_sock)
        server_cfg = dict(profile, interface=kharej_iface)

        node['candy'] = {
            'id': node['node_name'],
            'data_port': profile['data_port'],
            'icmp_id': profile['icmp_id'],
            'socks5_port': profile['socks5_port'],
            'socks5_port_internal': internal_sock,
            'relay_ports': [int(p) for p in pool['client_ports']],
            'tunnel_count': profile['tunnel_count'],
            'mtu': profile['mtu'],
            'initial_cwnd': profile['initial_cwnd'],
            'interface_iran': iran_iface,
            'interface_kharej': kharej_iface,
            'client_spoofed_ip': profile['client_spoofed_ip'],
            'server_spoofed_ip': profile['server_spoofed_ip'],
        }
        node['tunnel_port'] = profile['data_port']

        def reserve(data):
            data['pools'][name]['nodes'].append(node)
        atomic_update(reserve)

        ir_cfg = f'{DIRECTORY}/client-{node["node_name"]}.toml'
        kh_cfg = f'{DIRECTORY}/server-{node["node_name"]}.toml'
        ir_svc = _service_name(node, 'c')
        kh_svc = _service_name(node, 's')

        execute(iran, f'mkdir -p {DIRECTORY}')
        execute(kharej, f'mkdir -p {DIRECTORY}')
        write(iran, ir_cfg, _client_config(node['ip'], pool['kharej_server']['ip'], client_cfg))
        write(kharej, kh_cfg, _server_config(pool['kharej_server']['ip'], node['ip'], server_cfg))
        write(iran, f'/etc/systemd/system/{ir_svc}', _unit('client', ir_cfg))
        write(kharej, f'/etc/systemd/system/{kh_svc}', _unit('server', kh_cfg))
        execute(iran, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(ir_svc)}')
        execute(kharej, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(kh_svc)}')

        _ensure_socat(iran)
        _sync_relays(iran, pool['kharej_server']['ip'], pool['client_ports'], internal_sock)

        progress('نود Candy-Spoof فعال شد', 'succeeded')

        def finish(data):
            member = next(n for n in data['pools'][name]['nodes'] if n['node_name'] == node['node_name'])
            member.update(provisioning=False, status='active')
        atomic_update(finish)
        return True, 'نود Candy-Spoof فعال شد'

    except Exception as failure:
        errors = []
        try:
            for ssh, svc, role in (
                (iran, _service_name(node, 'c'), 'client'),
                (kharej, _service_name(node, 's'), 'server'),
            ):
                if ssh is None:
                    continue
                if role == 'client':
                    for p in pool.get('client_ports', []):
                        try:
                            _remove_relay(ssh, p)
                        except Exception as e:
                            errors.append(str(e))
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
        iran = connect(node)
        kharej = connect(pool['kharej_server'])
        sessions.extend((iran, kharej))
        for ssh, svc in (
            (iran, _service_name(node, 'c')),
            (kharej, _service_name(node, 's')),
        ):
            execute(ssh, f'systemctl disable --now {shlex.quote(svc)} 2>/dev/null || true')
            execute(ssh, f'rm -f {DIRECTORY}/*-{node["node_name"]}.toml /etc/systemd/system/{svc}')
            execute(ssh, 'systemctl daemon-reload')

        for p in pool.get('client_ports', []):
            _remove_relay(iran, p)
        execute(iran, 'systemctl daemon-reload')

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
        sessions = [iran]
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
            return 'DOWN', 'سرویس Candy-Spoof در یکی از سرورها فعال نیست', {}
        socks5_port = int((node.get('candy') or {}).get('socks5_port') or (pool.get('camouflage') or {}).get('socks5_port') or (ports or [0])[0])
        listen_code, _, _ = iran.execute(f'ss -ltn | grep -q ":{socks5_port}\\b"')
        if listen_code != 0:
            details = {p: {'status': 'DEGRADED', 'reason': 'سرویس فعال است اما شنونده SOCKS5 یافت نشد'} for p in ports}
            from core.link_latency import annotate
            annotate(iran, pool['kharej_server']['ip'], details)
            return 'DEGRADED', 'سرویس فعال است اما شنونده SOCKS5 روی نود ایران پیدا نشد', details
        details = {p: {'status': 'HEALTHY', 'reason': 'سرویس Candy-Spoof فعال و شنونده SOCKS5 در دسترس است'} for p in ports}
        from core.link_latency import annotate
        annotate(iran, pool['kharej_server']['ip'], details)
        return 'HEALTHY', 'سرویس Candy-Spoof فعال است', details
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
        internal_sock = int(pool['camouflage'].get('socks5_port_internal') or 1080)
        socks5_port = int(ports[0])
        for node in pool['nodes']:
            ir_ssh = connect(node)
            kh_ssh = connect(pool['kharej_server'])
            sessions.append((ir_ssh, kh_ssh))
            profile = dict(pool['camouflage'], socks5_port=internal_sock,
                           interface=(node.get('candy') or {}).get('interface_iran') or pool['camouflage'].get('interface') or _detect_interface(ir_ssh))
            ir_cfg = f'{DIRECTORY}/client-{node["node_name"]}.toml'
            write(ir_ssh, ir_cfg, _client_config(node['ip'], pool['kharej_server']['ip'], profile))
            execute(ir_ssh, f'systemctl restart {shlex.quote(_service_name(node, "c"))}')
            _sync_relays(ir_ssh, pool['kharej_server']['ip'], ports, internal_sock)

        def commit(data):
            data['pools'][name]['client_ports'] = ports
            for member in data['pools'][name]['nodes']:
                if member.get('candy'):
                    member['candy']['socks5_port'] = socks5_port
                    member['candy']['relay_ports'] = [int(p) for p in ports]
        atomic_update(commit)
        return True, 'پورت‌های سرویس و relayهای شفاف به‌روزرسانی شدند'
    except Exception as failure:
        return False, str(failure)
    finally:
        for ir_ssh, kh_ssh in sessions:
            ir_ssh.close()
            kh_ssh.close()
