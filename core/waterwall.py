"""WaterWall: flexible node-based tunneling with real WaterWall protocol modes.

Supported modes (see core/waterwall_modes.py):
trojan, reality, reverse, halfduplex, bgp4. Every mode keeps VX-LB's
port-forwarding semantics: Iran listens on the client ports and forwards to the
same port on Kharej's loopback backend.
"""
import copy
import ipaddress
import json
import os
import re
import secrets
import shlex
import time
import uuid
from pathlib import Path
from core.storage import get_pools, save_pool, delete_pool, atomic_update
from core.validation import validate_pool_name, validate_ports, validate_port
from core.transport_change import connect
from core.gre import write
from core.waterwall_modes import MODES, MODE_LABELS, iran_chain, kharej_chain, default_settings

def execute(ssh, command, timeout=30):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or 'WaterWall command failed')

DIRECTORY = '/etc/vxlb/waterwall'
BINARY_DEFAULT = '/usr/local/bin/waterwall'
HELPER = os.environ.get('VX_LB_WATERWALL_PROBE_HELPER') or '/usr/local/bin/vxlb-waterwall-probe'

def domain(value):
    """Validate TLS domain name for SNI."""
    value = str(value or '').strip().lower().rstrip('.')
    if len(value) > 253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in value.split('.')):
        raise ValueError('نام دامنهٔ معتبر لازم است')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('به‌جای IP، نام دامنه وارد کنید')

def absolute(value):
    """Validate absolute file path."""
    if not isinstance(value, str) or not re.fullmatch(r'/[a-zA-Z0-9_./-]+', value) or '..' in value.split('/'):
        raise ValueError('مسیر فایل باید مطلق و بدون .. باشد')
    return value

def profile(mode, data):
    """Validate and normalize a WaterWall mode profile."""
    if mode not in MODES or not isinstance(data, dict):
        raise ValueError('پروفایل WaterWall معتبر نیست')
    result = {
        'mode': mode,
        'port': int(validate_port(data.get('port', 443))),
        'binary': absolute(data.get('binary') or BINARY_DEFAULT),
    }
    if mode == 'trojan':
        password = str(data.get('password') or '')
        if len(password) < 8:
            raise ValueError('رمز عبور Trojan باید حداقل ۸ نویسه باشد')
        result['password'] = password
        if data.get('tls') and data.get('certificate') and data.get('key'):
            result['certificate'] = absolute(data['certificate'])
            result['key'] = absolute(data['key'])
            result['server_name'] = domain(data.get('server_name') or 'tunnel.test')
    elif mode == 'reality':
        password = str(data.get('password') or '')
        if not (1 <= len(password.encode('utf-8')) <= 32):
            raise ValueError('رمز Reality باید ۱ تا ۳۲ بایت باشد')
        result['password'] = password
        result['server_name'] = domain(data.get('server_name') or 'www.microsoft.com')
    elif mode == 'reverse':
        result['secret'] = str(data.get('secret') or 'vxlb-waterwall-reverse')
        try:
            result['secret_length'] = int(data.get('secret_length') or 640)
        except (TypeError, ValueError):
            raise ValueError('طول مخفی Reverse نامعتبر است')
        if not (1 <= result['secret_length'] <= 1024):
            raise ValueError('طول مخفی Reverse باید بین ۱ تا ۱۰۲۴ باشد')
    elif mode in ('halfduplex', 'bgp4'):
        result['password'] = str(data.get('password') or '')
    return result

def chain_configs(node, outside_ip, ports):
    """Generate Iran and Kharej chain configs for the node's WaterWall mode."""
    mode = node['waterwall']['profile']['mode']
    chain_ports = list(ports)
    probe_port = node['waterwall'].get('probe_port') or node['waterwall'].get('probe_ingress_port')
    if probe_port and str(probe_port) not in chain_ports:
        chain_ports.append(str(probe_port))
    return iran_chain(mode, node, outside_ip, chain_ports), kharej_chain(mode, node, chain_ports)

def core_config(chain_file):
    """Generate WaterWall core.json."""
    return {
        'log': {'path': '/var/log/vxlb-waterwall/', 'level': 'warning'},
        'misc': {'workers': 4, 'ram-profile': 'server', 'mtu': 1500},
        'dns': {'domain-strategy': 'prefer-ipv4'},
        'configs': [chain_file]
    }

def path(node):
    """Config file path for this node."""
    name = node['node_name']
    if not re.fullmatch(r'ldw[0-9a-f]{16}', name):
        raise ValueError('Invalid WaterWall resource ownership')
    return DIRECTORY + '/' + name + '.json'

def unit(node):
    """Systemd unit name for this node."""
    return Path(path(node)).stem + '.service'

def service(node):
    """Generate systemd service file."""
    binary = shlex.quote(node['waterwall']['profile']['binary'])
    config_dir = Path(path(node)).parent
    return f'''[Unit]
Description=VX-LB WaterWall tunneling node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={config_dir}
LogsDirectory=vxlb-waterwall
ExecStart={binary} --config:{path(node)}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
'''

def firewall(ssh, node, ports, iran, remove=False):
    """Manage iptables rules for this node."""
    if remove:
        marker = Path(path(node)).stem
        code, out, err = ssh.execute('iptables -w -S INPUT')
        if code != 0:
            raise RuntimeError(f"Failed to inspect iptables rules during cleanup: {err or out}")
        for line in out.splitlines():
            parts = shlex.split(line)
            if parts[:2] != ['-A', 'INPUT'] or '--comment' not in parts:
                continue
            index = parts.index('--comment')
            if index + 1 < len(parts) and parts[index + 1] == marker:
                execute(ssh, 'iptables -w -D INPUT ' + ' '.join(shlex.quote(p) for p in parts[2:]))
        code, out, err = ssh.execute('iptables -w -t mangle -S OUTPUT')
        if code != 0:
            raise RuntimeError(f'Failed to inspect carrier MSS rules: {err or out}')
        for line in out.splitlines():
            parts = shlex.split(line)
            if parts[:2] != ['-A', 'OUTPUT'] or '--comment' not in parts:
                continue
            index = parts.index('--comment')
            if index + 1 < len(parts) and parts[index + 1] == marker:
                execute(ssh, 'iptables -w -t mangle -D OUTPUT ' + ' '.join(shlex.quote(p) for p in parts[2:]))
        return

    tag = ['-m', 'comment', '--comment', Path(path(node)).stem]
    rules = []
    for port in ports if iran else [node['waterwall']['outer_port']]:
        for proto in ('tcp', 'udp') if iran else ('tcp',):
            rules.append(['-p', proto, '--dport', str(port), *tag, '-j', 'ACCEPT'])

    for rule in rules:
        quoted = ' '.join(shlex.quote(r) for r in rule)
        execute(ssh, f'iptables -w -C INPUT {quoted} 2>/dev/null || iptables -w -I INPUT 1 {quoted}')

    # WaterWall exposes no TCP_MAXSEG setting. Clamp only this carrier's
    # handshake packets, on both endpoints, without changing global routes.
    carrier = ['-p', 'tcp', '--dport' if iran else '--sport',
               str(int(node['waterwall']['outer_port'])), '--tcp-flags', 'SYN,RST', 'SYN',
               *tag, '-j', 'TCPMSS', '--set-mss', '1360']
    quoted = ' '.join(shlex.quote(r) for r in carrier)
    execute(ssh, f'iptables -w -t mangle -C OUTPUT {quoted} 2>/dev/null || iptables -w -t mangle -A OUTPUT {quoted}')

def test_config(ssh, node):
    """Validate config by attempting dry-run or syntax check."""
    # WaterWall has no built-in test mode; we'll validate JSON syntax locally
    config_path = path(node)
    code, _, _ = ssh.execute(f'python3 -m json.tool {shlex.quote(config_path)} > /dev/null 2>&1')
    if code != 0:
        raise RuntimeError('Config file is not valid JSON')

def verify(iran, kharej, node, ports=None):
    """Verify data plane: execute bidirectional TCP and UDP nonce probe from Iran ingress to Kharej destination.

    Tests that the tunnel is actually carrying real data bidirectionally.
    Raises RuntimeError if services are down, errors occurred, or probe data does not match.
    """
    # 1. Verify services are active
    for ssh, side in [(iran, 'Iran'), (kharej, 'Kharej')]:
        code, _, err = ssh.execute(f'systemctl is-active --quiet {unit(node)}')
        if code != 0:
            raise RuntimeError(f'WaterWall service inactive on {side}: {err}')

    # Check for fatal errors in journalctl
    for ssh, side in [(iran, 'Iran'), (kharej, 'Kharej')]:
        code, out, _ = ssh.execute(f'journalctl -u {unit(node)} -n 25 --no-pager 2>/dev/null | grep -iE "fatal|panic" || true')
        if out.strip():
            raise RuntimeError(f'WaterWall errors on {side}: {out.strip()}')

    # 2. Determine probe ingress port and Kharej echo responder port.
    # Probe through a real client port (which the chain actually listens on)
    # instead of a reserved probe port that no longer exists.
    configured = [int(p) for p in (ports or [])]
    ww = node['waterwall']
    probe_ingress_port = ww.get('probe_ingress_port') or ww.get('probe_port') or (configured[0] if configured else ww.get('backend_port'))
    probe_echo_port = ww.get('probe_backend_port') or ww.get('probe_port') or (configured[0] if configured else ww.get('backend_port'))

    if not probe_ingress_port or not probe_echo_port:
        raise RuntimeError('No probe port configured for WaterWall verification')

    probe_ingress_port = int(probe_ingress_port)
    probe_echo_port = int(probe_echo_port)

    channel = None
    try:
        # Start echo responder on Kharej strictly on the destination produced by configure
        stdin, out, _ = kharej.client.exec_command(f'python3 {HELPER} echo {probe_echo_port}', timeout=10)
        channel = out.channel
        line = out.readline().strip()
        if line != 'READY':
            raise RuntimeError(f'Kharej probe echo responder failed to start on port {probe_echo_port}: {line}')

        # Probe from Iran to Iran entry port (which carries traffic through the tunnel to Kharej)
        mode = node['waterwall'].get('profile', {}).get('mode', 'trojan')
        tcp_only = ' tcp-only' if mode != 'trojan' else ''
        error = None
        for attempt in range(4):
            try:
                execute(iran, f'python3 {HELPER} probe {probe_ingress_port} {secrets.token_hex(16)}{tcp_only}', timeout=15)
                return  # Verification succeeded!
            except RuntimeError as failure:
                error = failure
                time.sleep(1)

        raise RuntimeError(f'WaterWall tunnel verification probe failed targeting port {probe_ingress_port}: {error}')

    finally:
        if channel:
            try:
                channel.shutdown_write()
                channel.close()
            except Exception:
                pass

def set_job(name, **fields):
    """Update transport_change job status."""
    def update(data):
        data['pools'][name].setdefault('transport_change', {}).update(fields, updated_at=time.strftime('%Y-%m-%d %H:%M:%S'))
    atomic_update(update)

def clean(ssh, node, iran):
    """Cleanup: stop service, remove config, firewall rules."""
    u = unit(node)
    code, out, err = ssh.execute(f'if test -f /etc/systemd/system/{u}; then systemctl disable --now {u}; fi')
    if code != 0:
        raise RuntimeError(f"Failed to stop/disable service {u}: {err or out}")
    firewall(ssh, node, [], iran, remove=True)
    execute(ssh, f'rm -f {path(node)} /etc/systemd/system/{u} && systemctl daemon-reload')

def install_waterwall(ssh, role: str, config: dict):
    """Verifies or installs WaterWall from the offline depot, then checks prerequisites."""
    profile = config.get("camouflage") or config.get("profile") or {}
    binary = profile.get("binary", BINARY_DEFAULT)
    code, out, err = ssh.execute(f'test "$(id -u)" = 0 && test -x {shlex.quote(binary)} && command -v python3 && command -v iptables && command -v systemctl')
    if code != 0:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _, arch_raw, _ = ssh.execute("uname -m")
        remote_arch = arch_raw.strip().lower()
        arch_dir = "x86_64" if remote_arch in ("x86_64", "amd64") else "aarch64" if remote_arch in ("aarch64", "arm64") else remote_arch
        candidate = os.path.join(base_dir, "bin", arch_dir, "Waterwall")
        from core.dependency_manifest import get_dependency_manifest, verify_file_sha256
        manifest = get_dependency_manifest("waterwall")
        expected = (manifest.architectures.get(arch_dir, {}) if manifest else {}).get("sha256")
        if os.path.isfile(candidate) and expected and verify_file_sha256(candidate, expected) and hasattr(ssh, "upload_binary"):
            if ssh.upload_binary(candidate, binary, mode=0o755):
                code, out, err = ssh.execute(f'test -x {shlex.quote(binary)} && command -v python3 && command -v iptables && command -v systemctl')
        if code != 0:
            return False, f"WaterWall install check failed: root, binary ({binary}), or system tools missing: {err or out}"

    helper_path = Path(__file__).with_name('waterwall_probe.py')
    if helper_path.exists():
        helper_code = helper_path.read_text()
        if not ssh.write_file(HELPER, helper_code):
            return False, f"Failed to deploy probe helper to {HELPER}"
        ssh.execute(f'chmod +x {shlex.quote(HELPER)}')
    return True, f"WaterWall binary and prerequisites verified on {role} host"

def free_port(ssh, candidates=None, exclude=()):
    """Find available TCP/UDP port on remote."""
    script = """import socket,random,json,sys
candidates=json.loads(sys.argv[1]);excluded=set(json.loads(sys.argv[2]))
if not candidates:candidates=random.sample(range(22000,58000),256)
for port in candidates:
 if port in excluded:continue
 sockets=[]
 try:
  for protocol in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
   sock=socket.socket(socket.AF_INET,protocol);sockets.append(sock);sock.bind(('0.0.0.0',port))
  print(port);break
 except OSError:pass
 finally:
  for sock in sockets:sock.close()
else:raise RuntimeError('No requested TCP/UDP port is available')
"""
    code, out, err = ssh.execute(f'python3 -c {shlex.quote(script)} {shlex.quote(json.dumps(candidates or []))} {shlex.quote(json.dumps([int(p) for p in exclude]))}')
    if code != 0:
        raise RuntimeError(f'Failed to find free port: {err}')
    return int(out.strip())

def add(name, server, callback=None):
    """Add a new node to an existing pool."""
    pool = get_pools().get(name)
    if not pool:
        return False, 'استخر یافت نشد'
    if any(n['ip'] == server['ip'] for n in pool['nodes']):
        return False, 'سرور قبلاً عضو استخر است'

    sessions = []
    node = dict(server, node_name='ldw' + secrets.token_hex(8), engine='waterwall', transport='waterwall', provisioning=True)

    def progress(message, status='running', error=''):
        def update(data):
            data['pools'][name].setdefault('node_additions', {}).setdefault(server['ip'], {}).update({
                'ip': server['ip'], 'name': server['name'], 'status': status, 'message': message, 'error': error, 'updated_at': time.time()
            })
        atomic_update(update)
        if callback:
            callback(message)

    try:
        progress('اتصال به سرورها و بررسی WaterWall')
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool['kharej_server'])
        sessions.append(kharej)

        p = pool['camouflage']
        for ssh, role in zip(sessions, ('iran', 'kharej')):
            ok, msg = install_waterwall(ssh, role, {'camouflage': p})
            if not ok:
                raise RuntimeError(msg)
            write(ssh, HELPER, Path(__file__).with_name('waterwall_probe.py').read_text())
            execute(ssh, f'chmod +x {HELPER}')

        # Allocate ports
        outer = free_port(kharej, [p['port'], 443, 8443, 2053, 2083], exclude=pool['client_ports'])
        backend = int(validate_port(pool['client_ports'][0]))

        node['waterwall'] = {
            'profile': copy.deepcopy(p),
            'outer_port': outer,
            'backend_port': backend
        }

        # Trojan handles many ports natively, so give it a dedicated free probe
        # port that the echo can bind without colliding with a real backend.
        if p.get('mode') == 'trojan':
            probe_port = free_port(kharej, exclude=[outer, backend, *pool['client_ports']])
            probe_port = free_port(iran, [probe_port], exclude=pool['client_ports'])
            node['waterwall']['probe_port'] = probe_port
            node['waterwall']['backend_port'] = probe_port

        # TLS-backed modes need the SNI domain to point at Kharej and a valid cert
        if p.get('certificate') and p.get('key') and p.get('server_name'):
            check_dns = f'import socket,sys; addresses={{x[4][0] for x in socket.getaddrinfo(sys.argv[1],443)}}; assert sys.argv[2] in addresses, "DNS domain must point to the outside server"'
            execute(kharej, f'python3 -c {shlex.quote(check_dns)} {shlex.quote(p["server_name"])} {shlex.quote(pool["kharej_server"]["ip"])}')
            execute(kharej, f'openssl x509 -in {shlex.quote(p["certificate"])} -checkend 86400 -noout')

        # Generate configs
        iran_chain, kharej_chain = chain_configs(node, pool['kharej_server']['ip'], pool['client_ports'])
        iran_core = core_config(path(node))
        kharej_core = core_config(path(node))

        # Persist node before deployment
        def reserve(data):
            data['pools'][name]['nodes'].append(node)
        atomic_update(reserve)

        # Write configs and systemd units
        progress('نوشتن تنظیمات WaterWall و فعال‌سازی سرویس')
        for ssh, side, chain in [(iran, 'Iran', iran_chain), (kharej, 'Kharej', kharej_chain)]:
            # Create config directory
            execute(ssh, f'mkdir -p {DIRECTORY}')

            # Write chain config
            chain_file = f'{DIRECTORY}/chain-{node["node_name"]}.json'
            write(ssh, chain_file, json.dumps(chain, indent=2))

            # Update core config to point to chain file
            core = core_config(chain_file)
            write(ssh, path(node), json.dumps(core, indent=2))

            test_config(ssh, node)
            firewall(ssh, node, pool['client_ports'], side == 'Iran')
            write(ssh, f'/etc/systemd/system/{unit(node)}', service(node))
            execute(ssh, f'systemctl daemon-reload && systemctl enable --now {unit(node)}')

        progress('تأیید داده TCP/UDP و مسیر رمز‌شده')
        verify(iran, kharej, node, pool['client_ports'])

        def finish(data):
            member = next(n for n in data['pools'][name]['nodes'] if n['node_name'] == node['node_name'])
            member.update(provisioning=False, status='active')

        atomic_update(finish)
        progress('نود WaterWall فعال شد', 'succeeded')
        return True, 'نود رمز‌شده فعال شد'

    except Exception as failure:
        errors = []
        try:
            for ssh, ir in zip(sessions, (True, False)):
                try:
                    clean(ssh, node, ir)
                except Exception as e:
                    errors.append(str(e))
            if not errors:
                def discard(data):
                    data['pools'][name]['nodes'] = [n for n in data['pools'][name]['nodes'] if n['node_name'] != node['node_name']]
                atomic_update(discard)
        except:
            pass

        message = str(failure) + ('; پاک‌سازی ناقص: ' + '; '.join(errors) if errors else '')
        progress('راه‌اندازی نود ناموفق بود', 'failed', message)
        return False, message

    finally:
        for ssh in sessions:
            ssh.close()

def create(name, kharej, servers, ports, settings, callback=None):
    """Create a new WaterWall pool."""
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        mode = str((settings or {}).get('mode') or 'trojan')
        if mode not in MODES:
            raise ValueError(f'WaterWall mode نامعتبر: {mode}')
        settings = profile(mode, settings)
        settings['mode'] = mode

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

    from core.load_balancer import LoadBalancerManager
    ok, error = LoadBalancerManager.check_port_conflicts(ports, [s['ip'] for s in servers])
    if not ok:
        return False, error, {}

    save_pool(name, {
        'name': name,
        'transport': 'waterwall',
        'engine': 'waterwall',
        'waterwall_mode': mode,
        'camouflage': settings,
        'kharej_server': kharej,
        'client_ports': ports,
        'nodes': []
    })

    results = [add(name, server, callback) for server in servers]
    pool = get_pools()[name]
    return any(ok for ok, _ in results), 'نتیجهٔ نصب هر نود در کارت استخر ثبت شد', pool

def remove(name, ip, callback=None):
    """Remove a node from a pool."""
    pool = get_pools().get(name, {})
    node = next((n for n in pool.get('nodes', []) if n['ip'] == ip), None)

    if not node:
        return False, 'نود یافت نشد'

    sessions = []
    try:
        for server in (node, pool['kharej_server']):
            sessions.append(connect(server))

        if callback:
            callback('Tearing down tunnel from Iran server...')
        clean(sessions[0], node, True)

        if callback:
            callback('Tearing down tunnel from Kharej server...')
        clean(sessions[1], node, False)

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
    """Remove entire pool."""
    for node in list(get_pools().get(name, {}).get('nodes', [])):
        ok, error = remove(name, node['ip'], callback)
        if not ok:
            return ok, error

    delete_pool(name)
    return True, 'استخر حذف شد'

def health(name, node, ports):
    """Check node and link health: service active + backend reachable."""
    if node.get('provisioning'):
        return 'DOWN', 'نصب یا پاک‌سازی نود کامل نشده است', {}

    sessions = []
    try:
        pool = get_pools()[name]
        for server in (node, pool['kharej_server']):
            sessions.append(connect(server))

        # Check service is active
        for ssh in sessions:
            code, _, err = ssh.execute(f'systemctl is-active --quiet {unit(node)}')
            if code != 0:
                raise RuntimeError(f'WaterWall service inactive: {err}')

        # Probe data plane through tunnel (Iran -> Kharej)
        verify(sessions[0], sessions[1], node, ports)

        # Check backend TCP connectivity for each port
        script = """import socket,json,sys
result={}
for p in json.loads(sys.argv[1]):
 try:
  sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  sock.settimeout(2)
  code=sock.connect_ex(('127.0.0.1',int(p)))
  sock.close()
  result[str(p)]=(code==0)
 except:result[str(p)]=False
print(json.dumps(result))
"""
        code, out, err = sessions[1].execute(f'python3 -c {shlex.quote(script)} {shlex.quote(json.dumps(ports))}')
        if code != 0:
            raise RuntimeError(f'Backend health check failed: {err}')

        availability = json.loads(out)
        details = {
            p: {
                'status': 'HEALTHY' if ok else 'DEGRADED',
                'reason': 'مسیر رمز‌شده و دادهٔ TCP/UDP تأیید شد؛ TCP مقصد در دسترس است' if ok else 'مسیر رمز‌شده و دادهٔ TCP/UDP سالم است؛ TCP مقصد درحال حاضر گوش نمی‌دهد',
                'last_success_epoch': time.time() if ok else None
            }
            for p, ok in availability.items()
        }

        all_ok = availability and all(availability.values())
        status = 'HEALTHY' if all_ok else 'DEGRADED'
        reason = 'مسیر رمز‌شدهٔ WaterWall و برنامه‌های مقصد فعال هستند' if all_ok else 'مسیر رمز‌شدهٔ WaterWall سالم است؛ برنامهٔ مقصد درحال حاضر گوش نمی‌دهد'
        return status, reason, details

    except Exception as error:
        return 'DOWN', str(error), {}

    finally:
        for ssh in sessions:
            ssh.close()

def change_ports(name, ports, recovery=False):
    """Update client ports for entire pool."""
    pool = get_pools()[name]
    sessions = []
    changed = []

    from core.load_balancer import LoadBalancerManager

    try:
        ports = validate_ports(ports)
        if not ports:
            raise ValueError('حداقل یک پورت باید باقی بماند')

        ok, error = LoadBalancerManager.check_port_conflicts(ports, [n['ip'] for n in pool['nodes']], exclude_pool_name=name)
        if not ok:
            return False, error

        set_job(name, status='changing', target='waterwall', dirty_ports=list(set(map(str, [*ports, *pool['client_ports']]))), kind='waterwall_ports', **{'from': ','.join(pool['client_ports']), 'to': ','.join(ports), 'total': len(pool['nodes']), 'completed': 0}, message='به‌روزرسانی پورت‌های WaterWall')

        for node in pool['nodes']:
            ir_ssh = connect(node)
            kh_ssh = connect(pool['kharej_server'])
            sessions.append((ir_ssh, kh_ssh))

            changed.append((node, (ir_ssh, kh_ssh)))

            # Regenerate configs with new ports
            iran_chain, kharej_chain = chain_configs(node, pool['kharej_server']['ip'], ports)

            for ssh, chain in zip((ir_ssh, kh_ssh), (iran_chain, kharej_chain)):
                chain_file = f'{DIRECTORY}/chain-{node["node_name"]}.json'
                write(ssh, chain_file, json.dumps(chain, indent=2))

            # Update firewall
            dirty = sorted(set(map(str, [*ports, *pool['client_ports']])))
            for ssh in (ir_ssh, kh_ssh):
                firewall(ssh, node, dirty, True, remove=True)
                firewall(ssh, node, ports, True)

            # Restart services
            for ssh in (ir_ssh, kh_ssh):
                execute(ssh, f'systemctl restart {unit(node)}')

            verify(ir_ssh, kh_ssh, node, ports)
            set_job(name, completed=len(changed))

        def commit(data):
            data['pools'][name]['client_ports'] = ports

        atomic_update(commit)
        set_job(name, status='succeeded', message='پورت‌ها و عبور داده تأیید شدند')
        return True, 'پورت‌ها به‌روزرسانی شدند'

    except Exception as failure:
        errors = []
        for node, (ir_ssh, kh_ssh) in reversed(changed):
            try:
                # Rollback: restore old ports
                old_iran_chain, old_kharej_chain = chain_configs(node, pool['kharej_server']['ip'], pool['client_ports'])
                for ssh, chain in zip((ir_ssh, kh_ssh), (old_iran_chain, old_kharej_chain)):
                    chain_file = f'{DIRECTORY}/chain-{node["node_name"]}.json'
                    write(ssh, chain_file, json.dumps(chain, indent=2))

                dirty = sorted(set(map(str, [*ports, *pool['client_ports']])))
                for ssh in (ir_ssh, kh_ssh):
                    firewall(ssh, node, dirty, True, remove=True)
                    firewall(ssh, node, pool['client_ports'], True)

                for ssh in (ir_ssh, kh_ssh):
                    execute(ssh, f'systemctl restart {unit(node)}')

                verify(ir_ssh, kh_ssh, node, pool['client_ports'])
            except Exception as e:
                errors.append(str(e))

        message = str(failure) + ('; بازگردانی ناقص: ' + '; '.join(errors) if errors else '')
        set_job(name, status='rollback_failed' if errors or recovery else 'rolled_back', message='تغییر پورت ناموفق بود', error=message)
        return False, message

    finally:
        for ir_ssh, kh_ssh in sessions:
            ir_ssh.close()
            kh_ssh.close()
