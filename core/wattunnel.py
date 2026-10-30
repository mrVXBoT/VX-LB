"""Managed lifecycle for WatTunnel (JohnWatsoon/WatTunnel).

Iran runs `wattun` in client mode and publishes the pool's service ports.
Kharej runs it in server mode and forwards those ports only to 127.0.0.1.
The carrier between the two sides is one of WatTunnel's transports, or the
fortress bond of several of them. Traffic on that leg is encrypted; the
published service is whatever the operator forwards.

Health reads the client's loopback `/stats`. The connection monitor on Iran
watches the same published ports, and the dashboard log view shows both the
unit journal and that monitor.
"""
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import tempfile
import time
import urllib.request

from core.storage import get_pools, save_pool, delete_pool, atomic_update
from core.validation import validate_pool_name, validate_ports, validate_port
from core.transport_change import connect
from core.gre import write

ENGINE = 'wattunnel'
DIRECTORY = '/etc/vxlb/wattunnel'
BINARY = '/usr/local/bin/wattun'
PROFILES = (
    'icmp', 'udp', 'udp-dns', 'tcp', 'tls', 'ws', 'wss', 'h2', 'h2c', 'grpc', 'fortress',
)
FORWARD_PROTOS = ('tcp', 'udp', 'both')
ICMP_TYPES = ('echo', 'timestamp', 'info', 'mask')
FAKE_MODES = ('seq', 'ttl', 'sum', 'seqsum', 'rst', 'synrst', 'split', 'hlen0', 'fakeip', 'paws', 'all', 'ff', 'auto')
FINGERPRINTS = ('go', 'chrome', 'firefox', 'safari', 'edge', 'random')
POOL_PROFILES = ('tcp', 'tls', 'ws', 'wss', 'h2', 'h2c', 'grpc')
HTTP_PROFILES = ('ws', 'wss', 'h2', 'h2c', 'grpc')
TLS_PROFILES = ('tls', 'wss', 'h2', 'grpc')
# wattun injects a fake ClientHello on these dialers. ws and h2c are not in that set.
FAKE_SNI_PROFILES = ('tcp', 'tls', 'wss', 'h2', 'grpc', 'fortress')
# Reverse ICMP, UDP and fortress bind one shared socket on Kharej, so a second Iran node cannot join.
REVERSE_SINGLE_NODE = ('icmp', 'udp', 'udp-dns', 'fortress')
PROFILE_LABELS = {
    'icmp': 'ICMP — only ping has to pass',
    'udp': 'UDP — lowest latency when UDP passes',
    'udp-dns': 'UDP shaped like DNS on port 53',
    'tcp': 'TCP with a TLS-shaped hello',
    'tls': 'TLS — looks like HTTPS',
    'ws': 'WebSocket',
    'wss': 'WebSocket over TLS',
    'h2': 'HTTP/2',
    'h2c': 'HTTP/2 cleartext',
    'grpc': 'gRPC',
    'fortress': 'Bond of ICMP, TCP, TLS, WSS and UDP',
}
_SAFE = re.compile(r'^[A-Za-z0-9_./:+\[\]-]{1,200}$')
_NAME = re.compile(r'^[A-Za-z0-9.-]{1,253}$')
_PATH = re.compile(r'^/[A-Za-z0-9._~/-]{0,120}$')


def execute(ssh, command, timeout=30):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or 'WatTunnel command failed')
    return out


def _yaml_scalar(value):
    if isinstance(value, bool):
        return 'true' if value else 'false'
    text = str(value)
    if any(char in text for char in '\n\r'):
        raise ValueError('WatTunnel config values cannot contain a newline')
    if _SAFE.fullmatch(text) and text.lower() not in {'true', 'false', 'null', 'yes', 'no', 'on', 'off'}:
        return text
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _host(ip):
    address = ipaddress.ip_address(str(ip).strip())
    if address.is_unspecified or address.is_multicast:
        raise ValueError('WatTunnel peer address is not usable')
    return str(address)


def _hostport(ip, port):
    host = _host(ip)
    if ':' in host:
        return f'[{host}]:{int(port)}'
    return f'{host}:{int(port)}'


def _optional_name(value, label):
    text = str(value or '').strip()
    if not text:
        return ''
    if not _NAME.fullmatch(text):
        raise ValueError(f'Invalid WatTunnel {label}')
    return text


def normalize_settings(settings):
    """Return the stored carrier settings. Missing secrets are generated."""
    raw = dict(settings or {})
    profile = str(raw.get('profile') or 'tcp').strip().lower()
    if profile not in PROFILES:
        raise ValueError(f'Invalid WatTunnel profile: {profile}')
    proto = str(raw.get('proto') or 'tcp').strip().lower()
    if proto not in FORWARD_PROTOS:
        raise ValueError('WatTunnel forward protocol must be tcp, udp or both')
    reverse = bool(raw.get('reverse'))
    key = str(raw.get('key') or secrets.token_hex(24))
    if len(key) < 16 or any(char in key for char in '\n\r'):
        raise ValueError('کلید WatTunnel باید حداقل ۱۶ نویسه و بدون خط جدید باشد')
    default_listen = 53 if profile == 'udp-dns' else (None if profile == 'icmp' else 4443)
    listen_raw = raw.get('listen')
    if listen_raw in (None, '') and default_listen is None:
        listen = None
    else:
        listen = int(validate_port(default_listen if listen_raw in (None, '') else listen_raw))
        if profile == 'fortress' and listen > 65532:
            raise ValueError('پورت پایه Fortress باید سه پورت بعدی را هم آزاد بگذارد')
    icmp_type = str(raw.get('icmp_type') or 'echo').strip().lower()
    if icmp_type not in ICMP_TYPES:
        raise ValueError('Invalid WatTunnel ICMP type')
    fake_mode = str(raw.get('fake_mode') or 'seq').strip().lower()
    if fake_mode not in FAKE_MODES:
        raise ValueError('Invalid WatTunnel fake-sni mode')
    fingerprint = str(raw.get('fp') or 'chrome').strip().lower()
    if fingerprint not in FINGERPRINTS:
        raise ValueError('Invalid WatTunnel TLS fingerprint')
    path = str(raw.get('path') or '/wat').strip() or '/wat'
    if not _PATH.fullmatch(path):
        raise ValueError('WatTunnel path must start with / and stay within a short URL path')
    return {
        'profile': profile,
        'proto': proto,
        'reverse': reverse,
        'key': key,
        'listen': listen,
        'sni': _optional_name(raw.get('sni'), 'SNI'),
        'path': path,
        'fake_sni': _optional_name(raw.get('fake_sni'), 'fake SNI'),
        'fake_mode': fake_mode,
        'icmp_type': icmp_type,
        'fp': fingerprint,
    }


def carrier_name(profile):
    if profile == 'udp-dns':
        return 'udp'
    if profile == 'fortress':
        return 'icmp+tcp+tls+wss+udp'
    return profile


def _port_items(ports, proto):
    items = []
    for port in validate_ports(ports):
        if proto in ('tcp', 'both'):
            items.append(str(int(port)))
        if proto in ('udp', 'both'):
            items.append(f'{int(port)}/udp')
    return items


def _listen_map(settings):
    base = settings.get('listen')
    if settings['profile'] != 'fortress' or base is None:
        return {}
    return {'udp': base, 'tcp': base + 1, 'tls': base + 2, 'wss': base + 3}


def _listen_text(profile, own_ip, port):
    """UDP-DNS must bind the host's own address. A wildcard `:53` collides with systemd-resolved."""
    if profile == 'udp-dns':
        return _hostport(own_ip, port)
    return ':%d' % int(port)


def _dialing(role, reverse):
    return (role == 'client' and not reverse) or (role == 'server' and reverse)


def _endpoint_lines(role, settings, iran_ip, kharej_ip):
    """Peer and listen keys for one side.

    ICMP peer is a bare IP. Every other carrier dials host:port. Reverse ICMP
    keeps a peer on both sides. Reverse UDP listens on both sides and the
    Kharej puncher also gets peer host:port. A fortress bond puts the bare IP
    in `peer` and overrides UDP with `peer-udp`, because UDP would otherwise
    inherit the ICMP address and fail to resolve.
    """
    profile = settings['profile']
    reverse = settings['reverse']
    own = kharej_ip if role == 'server' else iran_ip
    other = iran_ip if role == 'server' else kharej_ip
    mapped = _listen_map(settings)
    lines = []

    def port_of(carrier):
        if profile == 'fortress':
            return mapped.get(carrier)
        return settings.get('listen')

    def add_peer(carrier, text):
        key = 'peer' if profile != 'fortress' or carrier == 'icmp' else f'peer-{carrier}'
        lines.append(f'{key}: {_yaml_scalar(text)}')

    def add_listen(carrier, text):
        if profile == 'fortress':
            if carrier == 'udp':
                lines.append(f'listen: {_yaml_scalar(text)}')
            lines.append(f'listen-{carrier}: {_yaml_scalar(text)}')
        else:
            lines.append(f'listen: {_yaml_scalar(text)}')

    if profile in ('icmp', 'fortress') and (reverse or role == 'client'):
        add_peer('icmp', _host(other))

    if profile in ('udp', 'udp-dns', 'fortress'):
        port = port_of('udp')
        if port:
            if reverse and role == 'server':
                add_listen('udp', _listen_text(profile, own, port))
                add_peer('udp', _hostport(other, port))
            elif reverse or role == 'server':
                add_listen('udp', _listen_text(profile, own, port))
            else:
                add_peer('udp', _hostport(other, port))

    if profile == 'fortress':
        pools = ('tcp', 'tls', 'wss')
    elif profile in POOL_PROFILES:
        pools = (profile,)
    else:
        pools = ()
    for carrier in pools:
        port = port_of(carrier)
        if not port:
            continue
        if _dialing(role, reverse):
            add_peer(carrier, _hostport(other, port))
        else:
            add_listen(carrier, _listen_text(profile, own, port))
    return lines


def _lines(role, settings, iran_ip, kharej_ip, ports, metrics_port):
    profile = settings['profile']
    reverse = settings['reverse']
    lines = [
        f'mode: {role}',
        f'key-file: {_yaml_scalar(DIRECTORY + "/key")}',
        f'carrier: {_yaml_scalar(carrier_name(profile))}',
        'hdr-mask: true',
        'shape: true',
        f'metrics: {_yaml_scalar("127.0.0.1:%d" % int(metrics_port))}',
    ]
    if reverse:
        lines.append('reverse: true')
    # pool-rotate is honoured by the dialer: the client, or the server when reverse.
    if _dialing(role, reverse) and (profile in POOL_PROFILES or profile == 'fortress'):
        lines.append('pool-rotate: 30m')
    if profile in ('tcp', 'fortress'):
        lines.append('tcp-mimic: true')
    if profile == 'udp-dns':
        lines.append('udp-dns: true')
    if profile in ('icmp', 'fortress'):
        lines.append(f'icmp-type: {settings["icmp_type"]}')
    if profile in TLS_PROFILES or profile == 'fortress':
        lines.append(f'fp: {settings["fp"]}')
        if settings['sni']:
            lines.append(f'sni: {_yaml_scalar(settings["sni"])}')
    if profile in HTTP_PROFILES or profile == 'fortress':
        lines.append(f'path: {_yaml_scalar(settings["path"])}')
    if settings['fake_sni'] and profile in FAKE_SNI_PROFILES:
        lines.append(f'fake-sni: {_yaml_scalar(settings["fake_sni"])}')
        lines.append(f'fake-mode: {settings["fake_mode"]}')
    lines.extend(_endpoint_lines(role, settings, iran_ip, kharej_ip))
    lines.append('ports:')
    for item in _port_items(ports, settings['proto']):
        lines.append(f'  - {item}')
    return '\n'.join(lines) + '\n'


def render_config(role, settings, iran_ip, kharej_ip, ports, metrics_port, key_path):
    if role not in ('client', 'server'):
        raise ValueError('WatTunnel role must be client or server')
    text = _lines(role, settings, iran_ip, kharej_ip, ports, metrics_port)
    return text.replace(DIRECTORY + '/key', key_path, 1)


def metrics_ports(node_name):
    slot = int(str(node_name)[-4:], 16) % 200
    server = 19800 + slot * 2
    return server, server + 1


def server_metrics_port(pool_name):
    """Even loopback port for the one Kharej server of a direct pool."""
    slot = int(hashlib.sha256(str(pool_name).encode()).hexdigest()[:4], 16) % 200
    return 19800 + slot * 2


def _shared_server(settings):
    """Direct mode is one Kharej listener and many Iran dialers. Reverse dials a specific Iran."""
    return not settings['reverse']


def _unit_active(ssh, unit):
    code, _, _ = ssh.execute(f'systemctl is-active --quiet {shlex.quote(unit)}', timeout=15)
    return code == 0


def _unit(role, config_path):
    return f'''[Unit]
Description=VX-LB WatTunnel {role}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={BINARY} -config {config_path}
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
'''


def client_unit(node_name):
    return f'vxlb-wattun-c-{node_name}.service'


def server_unit(node_name):
    return f'vxlb-wattun-s-{node_name}.service'


def _local_binary_path(arch_dir):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, 'bin', arch_dir, 'wattun')


def _ensure_local_binary(arch_dir, source_url, expected):
    """Return a depot path whose bytes match the pinned release checksum."""
    from core.dependency_manifest import verify_file_sha256
    candidate = _local_binary_path(arch_dir)
    if os.path.isfile(candidate) and verify_file_sha256(candidate, expected):
        return candidate, ''
    if not source_url:
        return '', f'WatTunnel binary is not in the offline depot ({candidate}) and the manifest has no release URL'
    os.makedirs(os.path.dirname(candidate), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='wattun-', dir=os.path.dirname(candidate))
    os.close(fd)
    try:
        request = urllib.request.Request(source_url, headers={'User-Agent': 'vxlb-wattunnel'})
        with urllib.request.urlopen(request, timeout=120) as response, open(tmp, 'wb') as target:
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                target.write(chunk)
        if not verify_file_sha256(tmp, expected):
            return '', f'WatTunnel release checksum mismatch for {source_url}'
        os.chmod(tmp, 0o755)
        os.replace(tmp, candidate)
        return candidate, ''
    except Exception as error:
        return '', f'WatTunnel release could not be fetched ({source_url}): {error}. Place the pinned binary at {candidate}'
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def install_binary(ssh):
    """Install wattun only when its SHA-256 matches the pinned v3.1.2 release.

    An executable that is already on the host is accepted only when that hash
    matches. A different binary is replaced from the offline depot or, if the
    depot is empty, from the release URL after the same check.
    """
    from core.dependency_manifest import get_dependency_manifest, verify_file_sha256
    code, _, _ = ssh.execute('test "$(id -u)" = 0 && command -v systemctl')
    if code != 0:
        return False, 'WatTunnel install needs root and systemd'
    manifest = get_dependency_manifest(ENGINE)
    _, arch_raw, _ = ssh.execute('uname -m')
    remote_arch = (arch_raw or '').strip().lower()
    arch_dir = 'x86_64' if remote_arch in ('x86_64', 'amd64') else 'aarch64' if remote_arch in ('aarch64', 'arm64') else remote_arch
    artifact = (manifest.architectures.get(arch_dir, {}) if manifest else {})
    expected = str(artifact.get('sha256') or '').lower()
    if not manifest or not expected or not artifact.get('is_verified'):
        return False, f'WatTunnel manifest has no verified checksum for {arch_dir}'
    code, out, _ = ssh.execute(
        f'if [ -x {shlex.quote(BINARY)} ]; then sha256sum {shlex.quote(BINARY)} | awk \'{{print $1}}\'; fi'
    )
    if code == 0 and out.strip().lower() == expected:
        return True, 'WatTunnel binary verified'
    candidate, message = _ensure_local_binary(arch_dir, artifact.get('source_url'), expected)
    if not candidate:
        return False, message
    if not verify_file_sha256(candidate, expected):
        return False, f'WatTunnel binary checksum mismatch for {candidate}'
    if not hasattr(ssh, 'upload_binary'):
        return False, 'SSH manager cannot upload the WatTunnel binary'
    if not ssh.upload_binary(candidate, BINARY, mode=0o755):
        return False, 'Failed to upload the WatTunnel binary'
    code, out, err = ssh.execute(
        f'sha256sum {shlex.quote(BINARY)} | awk \'{{print $1}}\'; test -x {shlex.quote(BINARY)} && command -v systemctl'
    )
    if code != 0 or expected not in out.lower():
        return False, f'WatTunnel post-install checksum failed: {err or out}'
    return True, 'WatTunnel binary verified'


def interpret_stats(payload):
    """Map a `/stats` document to the watchdog status vocabulary."""
    if not isinstance(payload, dict):
        return 'DOWN', 'پاسخ آمار WatTunnel نامعتبر است', {}
    alive = payload.get('alive') is True
    age = payload.get('last_rx_age_ms')
    srtt = payload.get('srtt_ms')
    loss = payload.get('loss_pct')
    latency = round(float(srtt), 1) if isinstance(srtt, (int, float)) else None
    link_status = 'HEALTHY' if alive else 'DEGRADED'
    details = {'link': {
        'status': link_status,
        'alive': alive,
        'last_rx_age_ms': age if isinstance(age, (int, float)) else None,
        'latency_ms': latency,
        'loss_pct': loss if isinstance(loss, (int, float)) else None,
        'streams': payload.get('streams'),
        'reason': 'آمار لوکال WatTunnel',
    }}
    rtt = f'{latency} ms' if latency is not None else 'نامشخص'
    # -1 is wattun's "no authenticated packet yet". A missing age is not proof the link is up.
    if isinstance(age, bool) or not isinstance(age, (int, float)):
        details['link']['status'] = 'DEGRADED'
        return 'DEGRADED', 'آمار WatTunnel سن آخرین دریافت را ندارد', details
    if age < 0:
        details['link']['status'] = 'DOWN'
        return 'DOWN', 'لینک WatTunnel هنوز هیچ بستهٔ معتبری نگرفته است', details
    if alive and age < 45000:
        return 'HEALTHY', f'لینک WatTunnel برقرار است؛ RTT {rtt}', details
    if alive:
        return 'DEGRADED', f'لینک WatTunnel زنده است اما آخرین دریافت {int(age)} میلی‌ثانیه پیش بوده', details
    if age > 120000:
        details['link']['status'] = 'DOWN'
        return 'DOWN', 'لینک WatTunnel قطع است؛ پاسخی از سمت مقابل نمی‌رسد', details
    return 'DEGRADED', 'سرویس WatTunnel فعال است اما نشست هنوز برقرار نشده', details


def create(name, kharej, servers, ports, settings, callback=None):
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        stored = normalize_settings(settings)
        if not ports or not servers or name in get_pools():
            raise ValueError('یک نام استخر بلااستفاده، حداقل یک پورت و سرورهای ایران الزامی است')
        if len({server['ip'] for server in servers}) != len(servers):
            raise ValueError('سرور تکراری مجاز نیست')
        if any(server['ip'] == kharej['ip'] for server in servers):
            raise ValueError('دو سمت تونل باید متفاوت باشند')
        _host(kharej['ip'])
        for server in servers:
            _host(server['ip'])
    except (ValueError, TypeError) as error:
        return False, str(error), {}

    save_pool(name, {
        'name': name,
        'transport': ENGINE,
        'engine': ENGINE,
        'wattunnel_profile': stored['profile'],
        'camouflage': stored,
        'kharej_server': kharej,
        'client_ports': ports,
        'nodes': [],
    })
    results = [add(name, server, callback) for server in servers]
    pool = get_pools()[name]
    failures = [message for ok, message in results if not ok]
    if failures:
        return False, '؛ '.join(failures), pool
    return True, 'نتیجهٔ نصب هر نود در کارت استخر ثبت شد', pool


def add(name, server, callback=None):
    pool = get_pools().get(name)
    if not pool:
        return False, 'استخر یافت نشد'
    if any(node['ip'] == server['ip'] for node in pool['nodes']):
        return False, 'سرور قبلاً عضو استخر است'

    sessions = []
    settings = normalize_settings(pool.get('camouflage') or {})
    blocked = ''
    if settings['reverse'] and pool['nodes'] and settings['profile'] in REVERSE_SINGLE_NODE:
        blocked = 'حالت معکوس این حامل فقط یک نود ایران دارد، چون خارج یک سوکت مشترک می‌بندد'
    if blocked:
        return False, blocked
    node = dict(server, node_name='wt' + secrets.token_hex(8), engine=ENGINE, transport=ENGINE, provisioning=True)
    iran = kharej = None
    shared = _shared_server(settings)
    server_name = name if shared else node['node_name']

    def progress(message, status='running', error=''):
        def update(data):
            data['pools'][name].setdefault('node_additions', {}).setdefault(server['ip'], {}).update({
                'ip': server['ip'], 'name': server.get('name'), 'status': status,
                'message': message, 'error': error, 'updated_at': time.time(),
            })
        atomic_update(update)
        if callback:
            callback(message)

    try:
        progress('اتصال به سرورها و بررسی WatTunnel')
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool['kharej_server'])
        sessions.append(kharej)
        for ssh in sessions:
            ok, message = install_binary(ssh)
            if not ok:
                raise RuntimeError(message)
        if hasattr(iran, 'ensure_conn_monitor_installed'):
            ok_mon, msg_mon = iran.ensure_conn_monitor_installed()
            if not ok_mon:
                progress('پایشگر اتصال روی ایران آماده نیست: ' + str(msg_mon))

        server_metrics = server_metrics_port(name) if shared else metrics_ports(node['node_name'])[0]
        client_metrics = metrics_ports(node['node_name'])[1]
        iran_key = f'{DIRECTORY}/key-{node["node_name"]}'
        kharej_key = f'{DIRECTORY}/key-{server_name}'
        server_svc = server_unit(server_name)
        node['wattunnel'] = {
            'profile': settings['profile'],
            'proto': settings['proto'],
            'reverse': settings['reverse'],
            'listen': settings['listen'],
            'client_metrics': client_metrics,
            'server_metrics': server_metrics,
            'server_unit': server_svc,
        }
        node['tunnel_port'] = settings['listen'] or client_metrics

        def reserve(data):
            data['pools'][name]['nodes'].append(node)
        atomic_update(reserve)

        client_cfg = render_config('client', settings, node['ip'], pool['kharej_server']['ip'],
                                   pool['client_ports'], client_metrics, iran_key)
        server_cfg = render_config('server', settings, node['ip'], pool['kharej_server']['ip'],
                                   pool['client_ports'], server_metrics, kharej_key)
        client_path = f'{DIRECTORY}/client-{node["node_name"]}.yml'
        server_path = f'{DIRECTORY}/server-{server_name}.yml'
        client_svc = client_unit(node['node_name'])
        for ssh in (iran, kharej):
            execute(ssh, f'mkdir -p {shlex.quote(DIRECTORY)} && chmod 700 {shlex.quote(DIRECTORY)}')
        write(iran, iran_key, settings['key'] + '\n')
        write(iran, client_path, client_cfg)
        write(iran, f'/etc/systemd/system/{client_svc}', _unit('client', client_path))
        # A direct pool already has one Kharej listener. Restarting it would drop the other Iran nodes.
        if not shared or not _unit_active(kharej, server_svc):
            write(kharej, kharej_key, settings['key'] + '\n')
            write(kharej, server_path, server_cfg)
            write(kharej, f'/etc/systemd/system/{server_svc}', _unit('server', server_path))
            execute(kharej, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(server_svc)}')
        execute(iran, f'systemctl daemon-reload && systemctl enable --now {shlex.quote(client_svc)}')
        progress('نود WatTunnel فعال شد', 'succeeded')

        def finish(data):
            member = next(item for item in data['pools'][name]['nodes'] if item['node_name'] == node['node_name'])
            member.update(provisioning=False, status='active')
        atomic_update(finish)
        return True, 'نود WatTunnel فعال شد'
    except Exception as failure:
        errors = []
        try:
            others = [item for item in get_pools().get(name, {}).get('nodes', []) if item.get('node_name') != node['node_name']]
            stop_server = kharej is not None and (not shared or not others)
            pairs = [(iran, client_unit(node['node_name']), node['node_name'])]
            if stop_server:
                pairs.append((kharej, server_unit(server_name), server_name))
            for ssh, svc, owner in pairs:
                if ssh is None:
                    continue
                try:
                    execute(ssh, f'systemctl disable --now {shlex.quote(svc)} 2>/dev/null || true')
                    execute(ssh, 'rm -f ' + ' '.join(shlex.quote(path) for path in (
                        f'{DIRECTORY}/client-{owner}.yml', f'{DIRECTORY}/server-{owner}.yml',
                        f'{DIRECTORY}/key-{owner}', f'/etc/systemd/system/{svc}',
                    )))
                    execute(ssh, 'systemctl daemon-reload')
                except Exception as error:
                    errors.append(str(error))
            if not errors:
                def discard(data):
                    data['pools'][name]['nodes'] = [item for item in data['pools'][name]['nodes'] if item.get('node_name') != node['node_name']]
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
    node = next((item for item in pool.get('nodes', []) if item['ip'] == ip), None)
    if not node:
        return False, 'نود یافت نشد'
    sessions = []
    try:
        sessions = [connect(node), connect(pool['kharej_server'])]
        info = node.get('wattunnel') or {}
        shared = not info.get('reverse', (pool.get('camouflage') or {}).get('reverse'))
        server_name = name if shared else node['node_name']
        server_svc = info.get('server_unit') or server_unit(server_name)
        others = [item for item in pool.get('nodes', []) if item.get('ip') != ip]
        client_svc = client_unit(node['node_name'])
        execute(sessions[0], f'systemctl disable --now {shlex.quote(client_svc)} 2>/dev/null || true')
        execute(sessions[0], 'rm -f ' + ' '.join(shlex.quote(path) for path in (
            f'{DIRECTORY}/client-{node["node_name"]}.yml', f'{DIRECTORY}/key-{node["node_name"]}',
            f'/etc/systemd/system/{client_svc}',
        )))
        execute(sessions[0], 'systemctl daemon-reload')
        if not shared or not others:
            execute(sessions[1], f'systemctl disable --now {shlex.quote(server_svc)} 2>/dev/null || true')
            execute(sessions[1], 'rm -f ' + ' '.join(shlex.quote(path) for path in (
                f'{DIRECTORY}/server-{server_name}.yml', f'{DIRECTORY}/key-{server_name}',
                f'/etc/systemd/system/{server_svc}',
            )))
            execute(sessions[1], 'systemctl daemon-reload')
        def commit(data):
            data['pools'][name]['nodes'] = [item for item in data['pools'][name]['nodes'] if item['ip'] != ip]
        atomic_update(commit)
        if callback:
            callback('نود WatTunnel حذف شد')
        return True, 'نود حذف شد'
    except Exception as failure:
        return False, str(failure)
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
    sessions = []
    if node.get('provisioning'):
        return 'DOWN', 'نصب یا پاک‌سازی نود کامل نشده است', {}
    try:
        pool = get_pools()[name]
        sessions = [connect(node), connect(pool['kharej_server'])]
        info = node.get('wattunnel') or {}
        shared = not info.get('reverse', (pool.get('camouflage') or {}).get('reverse'))
        server_svc = info.get('server_unit') or server_unit(name if shared else node['node_name'])
        units = (client_unit(node['node_name']), server_svc)
        for ssh, unit in zip(sessions, units):
            code, _, _ = ssh.execute(f'systemctl is-active --quiet {shlex.quote(unit)}')
            if code != 0:
                return 'DOWN', 'سرویس WatTunnel در یکی از سرورها فعال نیست', {}
        metrics = (node.get('wattunnel') or {}).get('client_metrics')
        if not metrics:
            return 'DEGRADED', 'سرویس فعال است اما پورت آمار کلاینت ثبت نشده', {}
        code, out, err = sessions[0].execute(
            'curl -fsS --max-time 3 ' + shlex.quote(f'http://127.0.0.1:{int(metrics)}/stats'),
            timeout=8,
        )
        if code != 0 or not out.strip():
            return 'DEGRADED', 'سرویس فعال است اما آمار لوکال WatTunnel خوانده نشد', {}
        status, reason, details = interpret_stats(json.loads(out))
        for port in ports or []:
            details.setdefault(str(port), {'status': status, 'reason': reason, 'latency_ms': details.get('link', {}).get('latency_ms')})
        return status, reason, details
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
        settings = normalize_settings(pool.get('camouflage') or {})
        shared = _shared_server(settings)
        kharej_ip = pool['kharej_server']['ip']
        if shared and pool['nodes']:
            kharej = connect(pool['kharej_server'])
            sessions.append((kharej,))
            server_metrics = server_metrics_port(name)
            kharej_key = f'{DIRECTORY}/key-{name}'
            server_cfg = render_config('server', settings, pool['nodes'][0]['ip'], kharej_ip,
                                       ports, server_metrics, kharej_key)
            write(kharej, f'{DIRECTORY}/server-{name}.yml', server_cfg)
            execute(kharej, f'systemctl restart {shlex.quote(server_unit(name))}')
        for node in pool['nodes']:
            iran = connect(node)
            sessions.append((iran,))
            info = node.get('wattunnel') or {}
            iran_key = f'{DIRECTORY}/key-{node["node_name"]}'
            client_metrics = info.get('client_metrics') or metrics_ports(node['node_name'])[1]
            client_cfg = render_config('client', settings, node['ip'], kharej_ip, ports, client_metrics, iran_key)
            write(iran, f'{DIRECTORY}/client-{node["node_name"]}.yml', client_cfg)
            execute(iran, f'systemctl restart {shlex.quote(client_unit(node["node_name"]))}')
            if not shared:
                kharej = connect(pool['kharej_server'])
                sessions.append((kharej,))
                server_name = node['node_name']
                server_metrics = info.get('server_metrics') or metrics_ports(server_name)[0]
                kharej_key = f'{DIRECTORY}/key-{server_name}'
                server_cfg = render_config('server', settings, node['ip'], kharej_ip, ports, server_metrics, kharej_key)
                write(kharej, f'{DIRECTORY}/server-{server_name}.yml', server_cfg)
                execute(kharej, f'systemctl restart {shlex.quote(info.get("server_unit") or server_unit(server_name))}')
        def commit(data):
            data['pools'][name]['client_ports'] = ports
        atomic_update(commit)
        return True, 'پورت‌ها به‌روزرسانی شدند'
    except Exception as failure:
        return False, str(failure)
    finally:
        for pair in sessions:
            for ssh in pair:
                ssh.close()


def log_units(node_name):
    """Journal units the Iran log view should read. The client runs on Iran."""
    if not node_name:
        return ['vxlb-wattun-c*.service']
    return [client_unit(node_name)]
