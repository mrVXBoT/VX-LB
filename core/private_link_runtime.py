"""Real standalone link deployment. Initial driver: IPv4 WireGuard.

A link becomes active only after a bidirectional TCP/UDP private-path challenge.
No user port relay, default route, NAT or global sysctl change is installed.
"""
import hashlib
import ipaddress
import re
import shlex
import time
from pathlib import Path

from core.storage import load_data, atomic_update
from core.transport_change import mutation_lock, busy, connect
from core.private_link_health import probe_pair
from core.wireguard_adapter import WireGuardAdapter


def save(name, **fields):
    def update(data):
        data['custom_links'][name].update(fields, updated_at=time.time())
    atomic_update(update)


def endpoint(data, ip, role):
    servers = data.get('iran_servers' if role == 'iran' else 'kharej_servers', [])
    if isinstance(servers, dict):
        servers = servers.values()
    server = next((server for server in servers if server.get('ip') == ip), None)
    if not server:
        raise ValueError('Link endpoint SSH credentials were not found')
    return server


def checked(ssh, command):
    code, out, err = ssh.execute(command, timeout=30)
    if code:
        detail = (err or out).strip()
        raise RuntimeError('Private-link remote operation failed'+(': '+detail if detail else ''))


def spec(link):
    if link.get('engine_id') != 'wireguard':
        raise ValueError('Standalone runtime driver is currently implemented for WireGuard only')
    iface = str(link['interface'])
    identity = str(link['link_id'])
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', iface) or not re.fullmatch(r'link-[0-9a-f]{8}', identity):
        raise ValueError('Invalid private-link resource identity')
    for role in ('iran', 'kharej'):
        ipaddress.IPv4Address(link[role+'_server']['ip'])
    network = ipaddress.IPv4Network(link['private_subnet'])
    subnet = str(network)
    if network.prefixlen != 30:
        raise ValueError('Standalone WireGuard requires a reserved /30')
    hosts = list(network.hosts())
    for index, role in enumerate(('iran', 'kharej')):
        if ipaddress.IPv4Address(link[role+'_server']['private_ip']) != hosts[index]:
            raise ValueError('Private endpoint address does not match its reservation')
    cfg = WireGuardAdapter().configure({'ip': link['iran_server']['ip'], 'node_name': iface},
        {'ip': link['kharej_server']['ip']}, dict(interface=iface, ipv4_subnet=subnet,
        tunnel_port=link['tunnel_port'], mtu=link['mtu'], enable_psk=True))
    guard_path='/etc/wireguard/ldbp-'+identity+'-guard.py'
    guard_service='ldbp-'+identity+'-route-guard.service'
    dropin='/etc/systemd/system/'+cfg['service_name']+'.d/ldbp-route-guard.conf'
    guard_source=Path(__file__).with_name('private_route_guard.py').read_text()
    guard_unit=('[Unit]\nDescription=LD-BP private route guard\nBefore=network-pre.target\n'
                '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 '+guard_path+' ensure '+subnet+'\n'
                '[Install]\nWantedBy=multi-user.target\n')
    cfg['guard_files']={guard_path:guard_source, '/etc/systemd/system/'+guard_service:guard_unit,
                        dropin:'[Unit]\nRequires='+guard_service+'\nAfter='+guard_service+'\n'}
    cfg['guard_service']=guard_service
    cfg['guard_subnet']=subnet
    tag = 'ldbp-pl:'+identity
    for role, peer in (('iran', 'kharej'), ('kharej', 'iran')):
        remote = link[peer+'_server']
        rules = [f'-p udp -s {remote["ip"]} --dport {cfg["tunnel_port"]} -m comment --comment {tag} -j ACCEPT',
                 f'-i {iface} -s {remote["private_ip"]}/32 -m comment --comment {tag} -j ACCEPT']
        # Cap TCP MSS well below tunnel MTU: the underlay path may not carry
        # full-size inner frames, and blackholed PMTUD silently drops large TCP.
        mss = max(576, int(link['mtu']) - 100)
        mangle = f'-o {iface} -p tcp --tcp-flags SYN,RST SYN -m comment --comment {tag} -j TCPMSS --set-mss {mss}'
        hooks = 'PreUp = /usr/bin/python3 '+guard_path+' ensure '+subnet+'\n'
        hooks += ''.join('PostUp = iptables -w 5 -C INPUT '+rule+' || iptables -w 5 -I INPUT '+rule+'\n' for rule in rules)
        hooks += 'PostUp = iptables -w 5 -t mangle -C POSTROUTING '+mangle+' || iptables -w 5 -t mangle -I POSTROUTING '+mangle+'\n'
        hooks += ''.join('PostDown = iptables -w 5 -C INPUT '+rule+' && iptables -w 5 -D INPUT '+rule+' || true\n' for rule in rules)
        hooks += 'PostDown = iptables -w 5 -t mangle -C POSTROUTING '+mangle+' && iptables -w 5 -t mangle -D POSTROUTING '+mangle+' || true\n'
        # Hooks belong to the interface, not to a peer block.
        cfg[role+'_config'] = cfg[role+'_config'].replace('[Peer]', hooks+'\n[Peer]', 1)
    return cfg


def provision(name):
    peers = {}
    with mutation_lock():
        try:
            data = load_data()
            if busy(data):
                return False, 'Another runtime mutation is active'
            link = data.get('custom_links', {}).get(name)
            if not link or link.get('status') != 'planned':
                return False, 'A planned private link is required; clean partial resources before retrying'
            if link.get('port_forwarding_rules'):
                return False, 'Standalone forwarding rules need a separate relay driver'
            cfg = spec(link)
            reservation = data.get('resource_reservations', {}).get(link['reservation_owner'], {})
            if reservation.get('interfaces') != [cfg['interface']] or reservation.get('ipv4_subnet') != cfg['ipv4_subnet']:
                raise ValueError('Private-link reservation does not match runtime configuration')
            servers = {role: endpoint(data, link[role+'_server']['ip'], role) for role in ('iran','kharej')}
            for role, server in servers.items():
                ssh = peers[role] = connect(server)
                code, _, _ = ssh.execute('command -v wg >/dev/null && command -v wg-quick >/dev/null && command -v iptables >/dev/null')
                if code:
                    ok, msg = WireGuardAdapter().install(ssh, role, {'auto_install': True})
                    if not ok:
                        raise RuntimeError(msg)
                checked(ssh, 'command -v wg >/dev/null && command -v wg-quick >/dev/null && command -v iptables >/dev/null && test ! -e '+shlex.quote(cfg['config_path'])+' && ! ip link show '+shlex.quote(cfg['interface']))
            preflight = """import ipaddress,json,socket,subprocess,sys
subnet=ipaddress.ip_network(sys.argv[1]);port=int(sys.argv[2])
for route in json.loads(subprocess.check_output(['ip','-j','route','show','table','all'],text=True)):
 destination=route.get('dst')
 if not destination or destination=='default':continue
 try:existing=ipaddress.ip_network(destination,strict=False)
 except ValueError:continue
 if existing.version==subnet.version and existing.overlaps(subnet):raise RuntimeError('Reserved subnet overlaps an existing host route')
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as check:check.bind(('0.0.0.0',port))
"""
            for ssh in peers.values():
                checked(ssh, 'python3 -c '+shlex.quote(preflight)+' '+shlex.quote(cfg['ipv4_subnet'])+' '+str(cfg['tunnel_port']))
            ownership = {role: dict(path=cfg['config_path'], service=cfg['service_name'],
                                   sha256=hashlib.sha256(cfg[role+'_config'].encode()).hexdigest(), state='pending',
                                   guard_service=cfg['guard_service'], guard_subnet=cfg['guard_subnet'],
                                   guard_files={path:hashlib.sha256(content.encode()).hexdigest() for path,content in cfg['guard_files'].items()}) for role in peers}
            save(name, status='provisioning', runtime=dict(driver='wireguard', interface=cfg['interface'], endpoints=ownership))
            for role, ssh in peers.items():
                for artifact, content in cfg['guard_files'].items():
                    staged=artifact+'.stage-'+link['link_id']
                    try:
                        if not ssh.write_file(staged,content):
                            raise RuntimeError('Could not stage private route protection')
                        mode='644' if artifact.endswith(('.service','.conf')) else '600'
                        checked(ssh,'chmod '+mode+' '+shlex.quote(staged)+' && ln -- '+shlex.quote(staged)+' '+shlex.quote(artifact))
                    finally:
                        ssh.execute('rm -f -- '+shlex.quote(staged))
                checked(ssh,'systemctl daemon-reload && systemctl enable '+shlex.quote(cfg['guard_service'])+' && systemctl start '+shlex.quote(cfg['guard_service']))
                path = cfg['config_path']
                stage = path+'.stage-'+link['link_id']
                try:
                    if not ssh.write_file(stage, cfg[role+'_config']):
                        raise RuntimeError('Could not stage private-link configuration')
                    checked(ssh, 'chmod 600 '+shlex.quote(stage)+' && ln -- '+shlex.quote(stage)+' '+shlex.quote(path))
                finally:
                    ssh.execute('rm -f -- '+shlex.quote(stage))
                checked(ssh, 'systemctl enable '+shlex.quote(cfg['service_name'])+' && systemctl start '+shlex.quote(cfg['service_name']))
                checked(ssh, 'ip link show '+shlex.quote(cfg['interface']))
                ownership[role]['state'] = 'started'
                save(name, runtime=dict(driver='wireguard', interface=cfg['interface'], endpoints=ownership))
            result = probe_pair(peers['iran'], peers['kharej'], link['iran_server']['private_ip'], link['kharej_server']['private_ip'], cfg['interface'])
            if result.get('passed') is not True or result.get('protocols') != ['tcp', 'udp'] or result.get('directions') != ['iran_to_kharej', 'kharej_to_iran']:
                raise RuntimeError('Private-link data challenge failed')
            save(name, status='active', health=result, error='')
            return True, 'Standalone WireGuard link installed; bidirectional TCP/UDP data verified'
        except Exception as error:
            # Credentials and private keys are never copied into runtime records.
            detail = str(error) or 'Private-link deployment incomplete'
            if peers and load_data().get('custom_links', {}).get(name, {}).get('status') == 'provisioning':
                save(name, status='failed', error=detail+'; private-link deployment incomplete, owned remote resources must be cleaned before retry')
            return False, detail
        finally:
            for ssh in peers.values():
                ssh.close()


def delete(name):
    peers = {}
    with mutation_lock():
        try:
            data = load_data()
            if busy(data):
                return False, 'Another runtime mutation is active'
            link = data.get('custom_links', {}).get(name)
            if not link:
                return False, 'Private link not found'
            if link.get('dependents') or link.get('port_forwarding_rules'):
                return False, 'Remove dependent relays/engines before deleting this private link'
            runtime = link.get('runtime')
            if runtime:
                iface = str(link['interface'])
                identity = str(link['link_id'])
                if not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', iface) or not re.fullmatch(r'link-[0-9a-f]{8}', identity):
                    raise ValueError('Invalid private-link cleanup identity')
                path, service = '/etc/wireguard/'+iface+'.conf', 'wg-quick@'+iface+'.service'
                tag = 'ldbp-pl:'+identity
                for role in ('iran','kharej'):
                    owner = runtime['endpoints'][role]
                    if owner.get('state') == 'cleaned':
                        continue
                    if owner.get('path') != path or owner.get('service') != service or not re.fullmatch(r'[0-9a-f]{64}', str(owner.get('sha256',''))):
                        raise ValueError('Private-link cleanup metadata does not match owned artifacts')
                    peers[role] = ssh = connect(endpoint(data, link[role+'_server']['ip'], role))
                    code, output, _ = ssh.execute('if test -f '+shlex.quote(path)+'; then sha256sum -- '+shlex.quote(path)+'; fi')
                    if code or (output.strip() and output.split()[0] != owner['sha256']):
                        raise RuntimeError('Configuration ownership changed; no foreign file was removed')
                    if not output.strip():
                        checked(ssh, '! ip link show '+shlex.quote(iface))
                    ssh.execute('systemctl stop '+shlex.quote(service)+' || true; systemctl disable '+shlex.quote(service)+' || true')
                    checked(ssh, '! ip link show '+shlex.quote(iface))
                    # Delete only exact owned rules, preserving unrelated INPUT/POSTROUTING.
                    for table, chain in (('filter','INPUT'),('mangle','POSTROUTING')):
                        code, rows, _ = ssh.execute('iptables -w 5 -t '+table+' -S '+chain)
                        if code:
                            raise RuntimeError('Could not inspect owned firewall rules')
                        for row in rows.splitlines():
                            args = shlex.split(row)
                            if args[:2] != ['-A',chain] or '--comment' not in args:
                                continue
                            position = args.index('--comment')
                            if position+1 < len(args) and args[position+1] == tag:
                                checked(ssh, 'iptables -w 5 -t '+table+' -D '+ ' '.join(map(shlex.quote,args[1:])))
                    if owner.get('guard_service'):
                        guard_service='ldbp-'+identity+'-route-guard.service'
                        guard_path='/etc/wireguard/ldbp-'+identity+'-guard.py'
                        expected={guard_path,'/etc/systemd/system/'+guard_service,'/etc/systemd/system/'+service+'.d/ldbp-route-guard.conf'}
                        if owner['guard_service']!=guard_service or set(owner.get('guard_files',{}))!=expected or owner.get('guard_subnet')!=link['private_subnet']:
                            raise ValueError('Private route guard ownership is invalid')
                        for artifact,digest in owner['guard_files'].items():
                            if not re.fullmatch(r'[0-9a-f]{64}',str(digest)):
                                raise ValueError('Invalid route guard artifact fingerprint')
                            code, value, _=ssh.execute('if test -f '+shlex.quote(artifact)+'; then sha256sum -- '+shlex.quote(artifact)+'; fi')
                            if code or (value.strip() and value.split()[0]!=digest):
                                raise RuntimeError('Route guard artifact changed; ownership retained')
                        # Missing artifacts after an incomplete upload are safe:
                        # stop only an installed unit, then remove the exact route.
                        code,state,_=ssh.execute('systemctl show -p LoadState --value '+shlex.quote(guard_service))
                        if code:raise RuntimeError('Cannot inspect private route guard service')
                        if state.strip()!='not-found':
                            checked(ssh,'systemctl stop '+shlex.quote(guard_service)+' && systemctl disable '+shlex.quote(guard_service))
                        source=Path(__file__).with_name('private_route_guard.py').read_text()
                        checked(ssh,'python3 -c '+shlex.quote(source)+' remove '+shlex.quote(link['private_subnet']))
                        checked(ssh,'rm -f -- '+' '.join(shlex.quote(value) for value in expected)+' && systemctl daemon-reload')
                    checked(ssh, 'rm -f -- '+shlex.quote(path)+' '+shlex.quote(path+'.stage-'+identity))
                    owner['state'] = 'cleaned'
                    save(name, status='deleting', runtime=runtime)
            elif link.get('status') != 'planned':
                raise ValueError('Cannot delete a deployed link without resource ownership evidence')
            def erase(current):
                current.get('resource_reservations', {}).pop(link['reservation_owner'], None)
                current.get('custom_links', {}).pop(name, None)
            atomic_update(erase)
            return True, 'Private-link resources removed and reservations released'
        except Exception as error:
            if load_data().get('custom_links', {}).get(name, {}).get('runtime'):
                save(name, status='cleanup_failed', error='Private-link cleanup incomplete; inventory and reservations retained')
            return False, str(error)
        finally:
            for ssh in peers.values():
                ssh.close()
