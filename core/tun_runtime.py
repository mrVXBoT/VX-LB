"""Managed Linux TUN links using BackPack's authenticated UDP/Noise L3 engine."""
import copy
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shlex
import time
from core.storage import get_pools, save_pool, delete_pool, atomic_update
from core.transport_change import connect, mutation_lock
from core.validation import validate_pool_name, validate_ports, toml_basic_string
from core.gre import write
from core.kernel_relay_ports import node_credentials, verify_listeners
from core.ipv6_tunnel_tools import render_relay_service
from core.private_link_health import probe_pair
from core.tunnel_probe import reserve_probe_port

DEFAULT_MTU = 1280
DIRECTORY = '/etc/vxlb/tun'
FIREWALL = '/usr/local/libexec/vxlb-tun-firewall.py'


def validate_mtu(value):
    if str(value).strip().isdigit() and 1200 <= int(value) <= 1420:
        return int(value)
    raise ValueError('TUN MTU must be an integer between 1200 and 1420')


def execute(ssh, command, timeout=30):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or 'TUN remote command failed')
    return out.strip()


def config_text(*, mode, address, token, interface, local_private, peer_private, mtu):
    if mode not in {'dial', 'listen'} or not re.fullmatch(r'lbt[0-9a-f]{10}', interface):
        raise ValueError('Invalid TUN configuration identity')
    if not re.fullmatch(r'[0-9a-f]{64}', token):
        raise ValueError('Invalid TUN shared credential')
    ipaddress.IPv4Interface(local_private)
    ipaddress.IPv4Address(peer_private)
    mtu = validate_mtu(mtu)
    values = dict(mode=mode, addr=address, token=token, carrier='udp', encap='gre', iface=interface,
                  local_ip=local_private, peer_ip=peer_private)
    return '[l3]\n' + ''.join(f'{key} = "{toml_basic_string(value)}"\n' for key, value in values.items()) + f'mtu = {mtu}\nauto_mtu = false\nmss_clamp = -1\n'


def allocate(server, kharej, mtu, port):
    local, remote = str(ipaddress.IPv4Address(server['ip'])), str(ipaddress.IPv4Address(kharej['ip']))
    if local == remote:
        raise ValueError('TUN endpoints must be different servers')
    used = {node.get('tun', {}).get('local_private') for pool in get_pools().values() for node in pool.get('nodes', [])}
    start = secrets.randbelow(16384)
    block = int(ipaddress.IPv4Address('10.210.0.0'))
    for offset in range(16384):
        base = block + ((start + offset) % 16384) * 4
        private, peer = str(ipaddress.IPv4Address(base + 1)), str(ipaddress.IPv4Address(base + 2))
        if private not in used and peer not in used:
            break
    else:
        raise ValueError('TUN private subnet exhausted')
    iface = 'lbt' + secrets.token_hex(5)
    return dict(ip=local, name=server.get('name', local), node_name=iface, engine='tun', transport='tun',
                provisioning=True, status='PROVISIONING', tunnel_port=port,
                tun=dict(interface=iface, mtu=validate_mtu(mtu), local_private=private, remote_private=peer,
                         outer_local=local, outer_remote=remote, tunnel_port=port, token=secrets.token_hex(32)))


def artifacts(node, role, ports):
    if role not in ['iran', 'kharej']:
        raise ValueError('Invalid TUN endpoint role')
    meta = node['tun']
    iface = meta['interface']
    iran = role == 'iran'
    private, peer = (meta['local_private'], meta['remote_private']) if iran else (meta['remote_private'], meta['local_private'])
    local, remote = (meta['outer_local'], meta['outer_remote']) if iran else (meta['outer_remote'], meta['outer_local'])
    base = f'{DIRECTORY}/{iface}'
    toml = config_text(mode='dial' if iran else 'listen', address=f'{remote if iran else local}:{meta["tunnel_port"]}',
                       token=meta['token'], interface=iface, local_private=private+'/30', peer_private=peer, mtu=meta['mtu'])
    service = f'vxlb-tun-{iface}.service'
    unit = f'''[Unit]
Description=VX-LB authenticated TUN link ({iface})
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStartPre=/usr/bin/python3 {FIREWALL} apply {base}.json
ExecStart=/usr/local/bin/backpack -c {base}.toml
ExecStopPost=/usr/bin/python3 {FIREWALL} remove {base}.json
Restart=on-failure
RestartSec=2
TimeoutStopSec=20
[Install]
WantedBy=multi-user.target
'''
    files = {base+'.toml': toml, base+'.json': json.dumps(dict(interface=iface, role=role, remote_ip=remote,
             peer_private=peer, port=meta['tunnel_port'], mtu=meta['mtu'])), '/etc/systemd/system/'+service: unit}
    services = [service]
    if iran and ports:
        relay_service = f'vxlb-tun-{iface}-relay.service'
        script, relay = render_relay_service(relay_service, iface, peer, ports)
        files[f'/etc/vxlb/{iface}-relay.py'] = script
        files['/etc/systemd/system/'+relay_service] = relay
        services.append(relay_service)
    return files, services


def install(ssh):
    execute(ssh, 'test "$(id -u)" = 0 && modprobe tun && test -c /dev/net/tun && command -v python3 ip iptables systemctl')
    ok, message = ssh.ensure_backpack_installed()
    if not ok:
        raise RuntimeError(message)
    write(ssh, FIREWALL, Path(__file__).with_name('tun_firewall_agent.py').read_text())


def deploy(ssh, files, services):
    for path, content in files.items():
        write(ssh, path, content)
    names = ' '.join(map(shlex.quote, services))
    execute(ssh, f'systemctl daemon-reload && systemctl enable {names} && systemctl restart {names}')
    for service in services:
        if execute(ssh, 'systemctl is-active '+shlex.quote(service)) != 'active':
            raise RuntimeError('TUN service did not remain active')


def cleanup(ssh, node, role, ports):
    files, services = artifacts(node, role, ports)
    iface = node['tun']['interface']
    for service in reversed(services):
        quoted = shlex.quote(service)
        execute(ssh, f'systemctl stop {quoted} 2>/dev/null || true; systemctl disable {quoted} 2>/dev/null || true; if systemctl is-active --quiet {quoted}; then exit 1; fi')
    # ExecStopPost may not run for an interrupted/never-started unit.
    write(ssh, FIREWALL, Path(__file__).with_name('tun_firewall_agent.py').read_text())
    metadata_path = f'{DIRECTORY}/{iface}.json'
    write(ssh, metadata_path, files[metadata_path])
    execute(ssh, f'python3 {FIREWALL} remove '+shlex.quote(metadata_path))
    execute(ssh, f'if ip link show dev {iface} >/dev/null 2>&1; then ip link del dev {iface}; fi')
    for path in files:
        execute(ssh, 'rm -f '+shlex.quote(path))
    execute(ssh, f'systemctl daemon-reload && ! ip link show dev {iface} >/dev/null 2>&1')


def create(name, kharej, servers, ports, mtu=DEFAULT_MTU, callback=None):
    with mutation_lock():
        try:
            name, ports, mtu = validate_pool_name(name), validate_ports(ports), validate_mtu(mtu)
            ipaddress.IPv4Address(kharej['ip'])
            if not ports or not servers or name in get_pools() or len({server['ip'] for server in servers}) != len(servers):
                raise ValueError('Select unique Iran servers and an unused pool name')
            for server in servers:
                ipaddress.IPv4Address(server['ip'])
            from core.load_balancer import LoadBalancerManager
            ok, message = LoadBalancerManager.check_port_conflicts(ports, [s['ip'] for s in servers])
            if not ok:
                return False, message, {}
        except ValueError as error:
            return False, str(error), {}
        pool = dict(name=name, engine='tun', transport='tun', tun_mtu=mtu, mtu=mtu, client_ports=ports,
                    kharej_server=copy.deepcopy(kharej), nodes=[], created_at=time.strftime('%Y-%m-%d %H:%M:%S'))
        save_pool(name, pool)
        failures = []
        for server in servers:
            ok, message = add(name, server, callback)
            if not ok:
                failures.append(message)
        pool = get_pools()[name]
        ready = any(not node.get('provisioning') for node in pool['nodes'])
        return ready, ('TUN TCP/UDP link verified' if ready else '; '.join(failures)), pool


def add(name, server, callback=None):
    with mutation_lock():
        pool = get_pools().get(name)
        if not pool or pool.get('engine') != 'tun':
            return False, 'TUN pool not found'
        if any(node['ip'] == server['ip'] for node in pool['nodes']):
            return False, 'Iran server already belongs to TUN pool'
        from core.load_balancer import LoadBalancerManager
        ok, message = LoadBalancerManager.check_port_conflicts(pool['client_ports'], [server['ip']], exclude_pool_name=name)
        if not ok:
            return False, message
        sessions, node = [], None
        try:
            if ipaddress.IPv4Address(server['ip']) == ipaddress.IPv4Address(pool['kharej_server']['ip']):
                raise ValueError('TUN endpoints must be different servers')
            if callback:
                callback('Preparing authenticated TUN runtime on both servers')
            iran, kharej = connect(server), None
            sessions.append((iran, 'iran'))
            kharej = connect(pool['kharej_server'])
            sessions.append((kharej, 'kharej'))
            for ssh, _ in sessions:
                install(ssh)
            port = reserve_probe_port(kharej, list(map(int, pool['client_ports'])), bind_host=pool['kharej_server']['ip'])
            node = allocate(server, pool['kharej_server'], pool['tun_mtu'], port)
            atomic_update(lambda data: data['pools'][name]['nodes'].append(node))
            for ssh, role in reversed(sessions):
                files, services = artifacts(node, role, pool['client_ports'])
                deploy(ssh, files, services)
            if pool["client_ports"]:
                verify_listeners(iran, f'vxlb-tun-{node["tun"]["interface"]}-relay.service', pool["client_ports"])
            # A fresh Noise session needs time to complete its first handshake.
            result = None
            for attempt in range(3):
                try:
                    result = probe_pair(iran, kharej, node['tun']['local_private'], node['tun']['remote_private'], node['tun']['interface'])
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    time.sleep(1)
            def commit(data):
                for entry in data['pools'][name]['nodes']:
                    if entry['node_name'] == node['node_name']:
                        entry.update(provisioning=False, status='HEALTHY', reason='Authenticated TUN TCP 64KiB/UDP verified', latency_ms=result['latency_ms'])
            atomic_update(commit)
            return True, 'TUN forwarding verified'
        except Exception as error:
            failures = []
            if node:
                for ssh, role in sessions:
                    try:
                        cleanup(ssh, node, role, pool['client_ports'])
                    except Exception as failure:
                        failures.append(str(failure))
                def record(data):
                    nodes = data['pools'][name]['nodes']
                    if failures:
                        for entry in nodes:
                            if entry['node_name'] == node['node_name']:
                                entry.update(status='FAILED', provisioning=True, reason=str(error), cleanup_error='; '.join(failures))
                    else:
                        data['pools'][name]['nodes'] = [entry for entry in nodes if entry['node_name'] != node['node_name']]
                atomic_update(record)
            return False, str(error) + ('; cleanup required: '+'; '.join(failures) if failures else '')
        finally:
            for ssh, _ in sessions:
                ssh.close()


def remove(name, ip, callback=None):
    with mutation_lock():
        pool = get_pools().get(name, {})
        node = next((node for node in pool.get('nodes', []) if node['ip'] == ip), None)
        if not node:
            return False, 'TUN member not found'
        sessions = []
        try:
            for role, server in [('iran', node_credentials(node)), ('kharej', pool['kharej_server'])]:
                ssh = connect(server)
                sessions.append(ssh)
                cleanup(ssh, node, role, pool['client_ports'])
            def discard(data):
                data['pools'][name]['nodes'] = [entry for entry in data['pools'][name]['nodes'] if entry['ip'] != ip]
            atomic_update(discard)
            return True, 'Owned TUN resources removed'
        except Exception as error:
            return False, str(error)
        finally:
            for ssh in sessions:
                ssh.close()


def remove_pool(name, callback=None):
    with mutation_lock():
        pool = get_pools().get(name)
        if not pool:
            return False, 'TUN pool not found'
        for node in list(pool['nodes']):
            ok, message = remove(name, node['ip'], callback)
            if not ok:
                return False, message
        delete_pool(name)
        return True, 'TUN pool removed'


def health(name, node, ports):
    from core.private_link_health import health as check_health
    return check_health(name, node, ports)
