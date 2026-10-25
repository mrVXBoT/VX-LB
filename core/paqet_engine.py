"""Paqet engine for VX-LB, faithful to the upstream architecture.

Upstream references:
  - Installer / topology: https://github.com/g3ntrix/paqet-tunnel
  - Core binary:         https://github.com/hanselime/paqet (v1.0.0-alpha.21)

The pool uses the same two-role model as the source installer:
  - Kharej (abroad) = paqet **server** (role "server"); listens on the tunnel
    port, and the V2Ray/X-UI service is expected on 127.0.0.1:<client port>.
  - Iran (entry)    = paqet **client** (role "client"); accepts user traffic on
    its public client ports and forwards it through the tunnel to the server.

Pairing follows the source "connection string" (`paqet://<url-safe-b64>`)
carrying `ip;port;key;fwd[;ver]`, and the protocol is version-locked: both
ends must run the exact same paqet binary (we pin v1.0.0-alpha.21).

Config files are the verbatim YAML templates the installer emits (`role`,
`listen`, `forward`, `server`, `network` {interface, ipv4.addr, router_mac,
tcp.local_flag/remote_flag, pcap.sockbuf}, `transport` {protocol: kcp, conn,
kcp.mode/key/mtu}). iptables protection mirrors the installer (raw NOTRACK +
mangle RST DROP + tcp_rfc1337), and the systemd unit uses
`ExecStart=paqet run -c <config>` with an `ExecStartPre` firewall hook.
"""
import ipaddress
import os
import re
import secrets
import shlex
import time
from core.storage import get_pools, save_pool, delete_pool, atomic_update
from core.validation import validate_pool_name, validate_ports, validate_port, shquote
from core.transport_change import connect
from core.gre import write

DIRECTORY = '/etc/vxlb/paqet'
BINARY = '/usr/local/bin/paqet'
VERSION = 'v1.0.0-alpha.21'

KCP_MODES = ('normal', 'fast', 'fast2', 'fast3')

_IFACE_RE = re.compile(r'^[a-zA-Z0-9_.\-]{1,32}$')
_MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')


def execute(ssh, command, timeout=40):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or 'Paqet command failed')
    return out


def validate_kcp_mode(mode):
    if mode not in KCP_MODES:
        raise ValueError(f'حالت KCP نامعتبر: {mode}')
    return mode


def validate_interface(iface):
    clean = str(iface or '').strip()
    if not _IFACE_RE.fullmatch(clean):
        raise ValueError(f'Invalid interface name {iface!r}')
    return clean


def validate_mac(mac):
    clean = str(mac or '').strip().lower().replace('-', ':')
    if not _MAC_RE.fullmatch(clean):
        raise ValueError(f'Invalid MAC address {mac!r}')
    return clean


def generate_secret(length: int = 32) -> str:
    return secrets.token_urlsafe(length)[:length]


# --- Network auto-detection (mirrors the installer's detect_and_confirm) ------

def detect_network(ssh):
    """Return {interface, local_ip, gateway_mac} for the remote host."""
    try:
        iface = execute(ssh, "ip route | grep default | awk '{print $5}' | head -1").strip()
    except Exception:
        iface = ''
    if not iface:
        iface = 'eth0'
    local_ip = ''
    try:
        local_ip = execute(
            ssh, f"ip -4 addr show {shquote(iface)} 2>/dev/null | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}' | head -1"
        ).strip()
    except Exception:
        pass
    gateway_mac = ''
    try:
        gw = execute(ssh, "ip route | grep default | awk '{print $3}' | head -1").strip()
        if gw:
            execute(ssh, f"ping -c 1 -W 1 {shquote(gw)} >/dev/null 2>&1 || true", timeout=15)
            gateway_mac = execute(
                ssh, f"ip neigh show {shquote(gw)} 2>/dev/null | grep -oE '([0-9a-fA-F]{{2}}:){{5}}[0-9a-fA-F]{{2}}' | head -1"
            ).strip()
    except Exception:
        pass
    return {"interface": validate_interface(iface), "local_ip": local_ip,
            "gateway_mac": gateway_mac}


# --- Connection string (verbatim source format) --------------------------------

def encode_connection_string(ip, port, key, fwd, version=None):
    import base64
    payload = f"ip={ip};port={port};key={key};fwd={fwd}"
    if version:
        payload += f";ver={version}"
    b64 = base64.urlsafe_b64encode(payload.encode('utf-8')).decode('ascii').rstrip('=')
    return f"paqet://{b64}"


def decode_connection_string(s):
    import base64
    s = str(s or '').strip()
    if s.startswith('paqet://'):
        s = s[len('paqet://'):]
    if not s:
        return None
    b64 = s.replace('-', '+').replace('_', '/')
    pad = (-len(b64)) % 4
    b64 += '=' * pad
    try:
        payload = base64.urlsafe_b64decode(b64).decode('utf-8')
    except Exception:
        return None
    def _get(key):
        m = re.search(rf'{key}=([^;]+)', payload)
        return m.group(1) if m else ''
    ip, port, key, fwd, ver = _get('ip'), _get('port'), _get('key'), _get('fwd'), _get('ver')
    if not (ip and port and key and fwd):
        return None
    return {"ip": ip, "port": port, "key": key, "fwd": fwd, "version": ver or None}


# --- Config templates (verbatim source YAML) -----------------------------------

def build_server_config(tunnel_port, secret, network, kcp_mode='fast', conn=1, mtu=1280):
    return f'''# paqet Server Configuration (VX-LB)
role: "server"

log:
  level: "info"

listen:
  addr: ":{int(tunnel_port)}"

network:
  interface: "{network['interface']}"
  ipv4:
    addr: "{network['local_ip']}:{int(tunnel_port)}"
    router_mac: "{network['gateway_mac']}"
  tcp:
    local_flag: ["PA"]
    remote_flag: ["PA"]
  pcap:
    sockbuf: 8388608

transport:
  protocol: "kcp"
  conn: {int(conn)}
  kcp:
    mode: "{kcp_mode}"
    key: "{secret}"
    mtu: {int(mtu)}
'''


def build_client_config(server_ip, tunnel_port, secret, ports, network,
                        kcp_mode='fast', conn=1, mtu=1280):
    forward_blocks = []
    for p in ports:
        p = int(p)
        forward_blocks.append(
            f'  - listen: "0.0.0.0:{p}"\n'
            f'    target: "127.0.0.1:{p}"\n'
            f'    protocol: "tcp"\n'
        )
    return f'''# paqet Client Configuration (VX-LB)
role: "client"

log:
  level: "info"

forward:
{"".join(forward_blocks)}network:
  interface: "{network['interface']}"
  ipv4:
    addr: "{network['local_ip']}:0"
    router_mac: "{network['gateway_mac']}"
  tcp:
    local_flag: ["PA"]
    remote_flag: ["PA"]
  pcap:
    sockbuf: 4194304

server:
  addr: "{server_ip}:{int(tunnel_port)}"

transport:
  protocol: "kcp"
  conn: {int(conn)}
  kcp:
    mode: "{kcp_mode}"
    key: "{secret}"
    mtu: {int(mtu)}
'''


# --- iptables protection (mirrors installer setup/teardown) --------------------

def _server_firewall_lines(port):
    return [
        f"iptables -t raw -A PREROUTING -p tcp --dport {int(port)} -j NOTRACK",
        f"iptables -t raw -A OUTPUT -p tcp --sport {int(port)} -j NOTRACK",
        f"iptables -t mangle -A OUTPUT -p tcp --sport {int(port)} --tcp-flags RST RST -j DROP",
        f"iptables -t mangle -A PREROUTING -p tcp --dport {int(port)} --tcp-flags RST RST -j DROP",
    ]


def _client_firewall_lines(server_ip, port):
    return [
        f"iptables -t raw -A OUTPUT -p tcp -d {server_ip} --dport {int(port)} -j NOTRACK",
        f"iptables -t raw -A PREROUTING -p tcp -s {server_ip} --sport {int(port)} -j NOTRACK",
        f"iptables -t mangle -A OUTPUT -p tcp -d {server_ip} --dport {int(port)} --tcp-flags RST RST -j DROP",
        f"iptables -t mangle -A PREROUTING -p tcp -s {server_ip} --sport {int(port)} --tcp-flags RST RST -j DROP",
    ]


def _teardown_lines(role, server_ip, port):
    if role == 'server':
        rules = [
            ("raw", "PREROUTING", f"--dport {int(port)}"),
            ("raw", "OUTPUT", f"--sport {int(port)}"),
            ("mangle", "OUTPUT", f"--sport {int(port)} --tcp-flags RST RST"),
            ("mangle", "PREROUTING", f"--dport {int(port)} --tcp-flags RST RST"),
        ]
    else:
        rules = [
            ("raw", "OUTPUT", f"-d {server_ip} --dport {int(port)}"),
            ("raw", "PREROUTING", f"-s {server_ip} --sport {int(port)}"),
            ("mangle", "OUTPUT", f"-d {server_ip} --dport {int(port)} --tcp-flags RST RST"),
            ("mangle", "PREROUTING", f"-s {server_ip} --sport {int(port)} --tcp-flags RST RST"),
        ]
    cmds = []
    for table, chain, match in rules:
        cmds.append(f"iptables -t {table} -D {chain} -p tcp {match} -j NOTRACK 2>/dev/null || true")
        cmds.append(f"iptables -t {table} -D {chain} -p tcp {match} -j DROP 2>/dev/null || true")
    return cmds


def firewall_hook_script(role, server_ip, port):
    lines = ["#!/bin/sh", "set -e"]
    lines += _teardown_lines(role, server_ip, port)
    lines += _server_firewall_lines(port) if role == 'server' else _client_firewall_lines(server_ip, port)
    return "\n".join(lines) + "\n"


def setup_iptables(ssh, role, server_ip, port):
    lines = _server_firewall_lines(port) if role == 'server' else _client_firewall_lines(server_ip, port)
    for line in lines:
        try:
            execute(ssh, line, timeout=15)
        except Exception:
            pass
    try:
        execute(ssh, "echo 'net.ipv4.tcp_rfc1337=1' > /etc/sysctl.d/99-vxlb-paqet.conf && sysctl -w net.ipv4.tcp_rfc1337=1 >/dev/null 2>&1 || true", timeout=15)
    except Exception:
        pass


# --- systemd unit -----------------------------------------------------------------

def unit_file(role, cfg_path, hook_path):
    return f'''[Unit]
Description=paqet Raw Packet Tunnel ({role})
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStartPre={hook_path}
ExecStart={BINARY} run -c {cfg_path}
Restart=always
RestartSec=5
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
'''


def service_name(node, role):
    return f'vxlb-paqet{role}-{node["node_name"]}.service'


# --- install --------------------------------------------------------------------

def install_paqet(ssh):
    code, _, _ = ssh.execute(f'test -x {shquote(BINARY)} && command -v systemctl')
    if code == 0:
        return True, 'Paqet binary verified'
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _, arch_raw, _ = ssh.execute('uname -m')
        arch = arch_raw.strip().lower()
        arch_dir = 'x86_64' if arch in ('x86_64', 'amd64') else 'aarch64' if arch in ('aarch64', 'arm64') else arch
        candidate = os.path.join(base_dir, 'bin', arch_dir, 'paqet')
        from core.dependency_manifest import get_dependency_manifest, verify_file_sha256
        manifest = get_dependency_manifest('paqet')
        expected = (manifest.architectures.get(arch_dir, {}) if manifest else {}).get('sha256')
        if not os.path.isfile(candidate):
            return False, f'Paqet binary not in offline depot: {candidate}'
        if not expected or not verify_file_sha256(candidate, expected):
            return False, f'Paqet binary checksum mismatch for {arch_dir}'
        if not ssh.upload_binary(candidate, BINARY, mode=0o755):
            return False, 'Failed to upload paqet binary'
        ssh.write_file('/opt/paqet/.paqet-version', VERSION + '\n')
        code, _, err = ssh.execute(f'test -x {shquote(BINARY)}')
        if code != 0:
            return False, f'Paqet post-install check failed: {err}'
    except Exception as e:
        return False, f'Paqet install error: {e}'
    return True, 'Paqet binary verified'


# --- lifecycle ------------------------------------------------------------------

def create(name, kharej, servers, ports, settings, callback=None):
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        tunnel_port = int(validate_port((settings or {}).get('port', 8888)))
        kcp_mode = validate_kcp_mode((settings or {}).get('kcp_mode', 'fast'))
        secret = str((settings or {}).get('key') or generate_secret())
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
        'transport': 'paqet',
        'engine': 'paqet',
        'paqet_port': tunnel_port,
        'camouflage': {
            'mode': 'forward', 'port': tunnel_port, 'key': secret,
            'kcp_mode': kcp_mode, 'conn': int((settings or {}).get('conn', 1)),
            'mtu': int((settings or {}).get('mtu', 1280)),
        },
        'kharej_server': kharej,
        'client_ports': ports,
        'paqet_server_deployed': False,
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
    node = dict(server, node_name='paq' + secrets.token_hex(8), engine='paqet', transport='paqet', provisioning=True)

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
        progress('اتصال به سرورها و بررسی Paqet')
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool['kharej_server'])
        sessions.append(kharej)

        for ssh in sessions:
            ok, msg = install_paqet(ssh)
            if not ok:
                raise RuntimeError(msg)

        tunnel_port = int(validate_port(prof['port']))
        secret = prof['key']
        kcp_mode = prof['kcp_mode']
        conn = int(prof.get('conn', 1))
        mtu = int(prof.get('mtu', 1280))
        kh_ip = pool['kharej_server']['ip']

        # Deploy the shared server on Kharej once per pool.
        if not pool.get('paqet_server_deployed'):
            progress('پیکربندی سرور Paqet روی سرور خارج')
            kh_net = detect_network(kharej)
            server_cfg = build_server_config(tunnel_port, secret, kh_net, kcp_mode, conn, mtu)
            srv_cfg_path = f'{DIRECTORY}/server.yaml'
            hook_path = f'{DIRECTORY}/firewall-server.sh'
            execute(kharej, f'mkdir -p {DIRECTORY}')
            write(kharej, srv_cfg_path, server_cfg)
            write(kharej, hook_path, firewall_hook_script('server', kh_ip, tunnel_port))
            setup_iptables(kharej, 'server', kh_ip, tunnel_port)
            srv_svc = 'vxlb-paqet-server.service'
            write(kharej, f'/etc/systemd/system/{srv_svc}', unit_file('server', srv_cfg_path, hook_path))
            execute(kharej, f'systemctl daemon-reload && systemctl enable --now {shquote(srv_svc)}')
            def mark_server(data):
                data['pools'][name]['paqet_server_deployed'] = True
            atomic_update(mark_server)

        node['paqet'] = {'id': node['node_name'], 'port': tunnel_port, 'key': secret,
                          'kcp_mode': kcp_mode, 'conn': conn, 'mtu': mtu}
        node['tunnel_port'] = tunnel_port

        def reserve(data):
            data['pools'][name]['nodes'].append(node)
        atomic_update(reserve)

        # Deploy a client on Iran for this node.
        progress('پیکربندی کلاینت Paqet روی سرور ایران')
        ir_net = detect_network(iran)
        client_cfg = build_client_config(kh_ip, tunnel_port, secret, pool['client_ports'],
                                         ir_net, kcp_mode, conn, mtu)
        cli_cfg_path = f'{DIRECTORY}/client-{node["node_name"]}.yaml'
        hook_path = f'{DIRECTORY}/firewall-client-{node["node_name"]}.sh'
        execute(iran, f'mkdir -p {DIRECTORY}')
        write(iran, cli_cfg_path, client_cfg)
        write(iran, hook_path, firewall_hook_script('client', kh_ip, tunnel_port))
        setup_iptables(iran, 'client', kh_ip, tunnel_port)
        cli_svc = service_name(node, 'c')
        write(iran, f'/etc/systemd/system/{cli_svc}', unit_file('client', cli_cfg_path, hook_path))
        execute(iran, f'systemctl daemon-reload && systemctl enable --now {shquote(cli_svc)}')

        progress('نود Paqet فعال شد', 'succeeded')
        def finish(data):
            member = next(n for n in data['pools'][name]['nodes'] if n['node_name'] == node['node_name'])
            member.update(provisioning=False, status='active')
        atomic_update(finish)
        return True, 'نود Paqet فعال شد'

    except Exception as failure:
        errors = []
        try:
            for ssh, svc in ((iran, service_name(node, 'c')),):
                try:
                    execute(ssh, f'systemctl disable --now {shquote(svc)} 2>/dev/null || true')
                    execute(ssh, f'rm -f {DIRECTORY}/client-{node["node_name"]}.yaml /etc/systemd/system/{svc}')
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
        sessions.append(iran)
        cli_svc = service_name(node, 'c')
        execute(iran, f'systemctl disable --now {shquote(cli_svc)} 2>/dev/null || true')
        execute(iran, f'rm -f {DIRECTORY}/client-{node["node_name"]}.yaml /etc/systemd/system/{cli_svc}')
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
    pool = get_pools().get(name, {})
    for node in list(pool.get('nodes', [])):
        ok, error = remove(name, node['ip'], callback)
        if not ok:
            return ok, error
    if pool.get('paqet_server_deployed'):
        try:
            kh = connect(pool['kharej_server'])
            try:
                execute(kh, 'systemctl disable --now vxlb-paqet-server.service 2>/dev/null || true')
                execute(kh, f'rm -f {DIRECTORY}/server.yaml /etc/systemd/system/vxlb-paqet-server.service')
                execute(kh, 'systemctl daemon-reload')
            finally:
                kh.close()
        except Exception:
            pass
    delete_pool(name)
    return True, 'استخر حذف شد'


def health(name, node, ports):
    if node.get('provisioning'):
        return 'DOWN', 'نصب یا پاک‌سازی نود کامل نشده است', {}
    try:
        pool = get_pools()[name]
        iran = connect(node)
        kharej = connect(pool['kharej_server'])
        try:
            ok = True
            code, _, _ = iran.execute(f'systemctl is-active --quiet {shquote(service_name(node, "c"))}')
            ok = ok and code == 0
            code, _, _ = kharej.execute('systemctl is-active --quiet vxlb-paqet-server.service')
            ok = ok and code == 0
            if not ok:
                return 'DOWN', 'سرویس Paqet در یکی از سرورها فعال نیست', {}
            details = {p: {'status': 'HEALTHY', 'reason': 'سرویس Paqet فعال است'} for p in ports}
            return 'HEALTHY', 'سرویس Paqet فعال است', details
        finally:
            iran.close()
            kharej.close()
    except Exception as error:
        return 'DOWN', str(error), {}


def change_ports(name, ports, recovery=False):
    pool = get_pools()[name]
    sessions = []
    try:
        ports = validate_ports(ports)
        if not ports:
            raise ValueError('حداقل یک پورت باید باقی بماند')
        kh_ip = pool['kharej_server']['ip']
        for node in pool['nodes']:
            iran = connect(node)
            sessions.append(iran)
            info = node['paqet']
            ir_net = detect_network(iran)
            client_cfg = build_client_config(kh_ip, info['port'], info['key'], ports,
                                             ir_net, info['kcp_mode'], info['conn'], info['mtu'])
            cli_cfg_path = f'{DIRECTORY}/client-{node["node_name"]}.yaml'
            write(iran, cli_cfg_path, client_cfg)
            execute(iran, f'systemctl restart {shquote(service_name(node, "c"))}')
        def commit(data):
            data['pools'][name]['client_ports'] = ports
        atomic_update(commit)
        return True, 'پورت‌ها به‌روزرسانی شدند'
    except Exception as failure:
        return False, str(failure)
    finally:
        for ssh in sessions:
            ssh.close()
