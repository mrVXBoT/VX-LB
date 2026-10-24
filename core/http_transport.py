"""Owned HTTP/HTTPS CONNECT deployment with end-to-end mTLS TCP/UDP framing."""
import copy
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import time
import paramiko
from core.storage import get_pools, save_pool, delete_pool, atomic_update, DATA_DIR
from core.transport_change import connect, mutation_lock
from core.validation import validate_pool_name, validate_ports
from core.gre import write
from core.kernel_relay_ports import node_credentials, verify_listeners
from core.tunnel_probe import reserve_probe_port
from core.private_link_health import ECHO, PROBE
from core.slipstream_deploy import identity_material

DIRECTORY = '/etc/vxlb/http'
MODES = {'http', 'https'}


def execute(ssh, command, timeout=30):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or 'HTTP tunnel remote command failed')
    return out.strip()


def unit(name, script, config, parent=None):
    dependency = f'After={parent}\nRequires={parent}\nPartOf={parent}\n' if parent else ''
    return f'''[Unit]
Description=VX-LB HTTP CONNECT {name}
After=network-online.target
Wants=network-online.target
{dependency}[Service]
Type=simple
ExecStart=/usr/bin/python3 {script} {config}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
UMask=0077
TimeoutStopSec=20
[Install]
WantedBy=multi-user.target
'''


def plan(node, pool):
    meta = node['http_connect']
    identity = meta['id']
    if not re.fullmatch(r'[0-9a-f]{32}', identity) or node['transport'] not in MODES:
        raise ValueError('Invalid owned HTTP identity')
    base = DIRECTORY+'/'+identity
    security = meta['security']
    ports = list(map(int, validate_ports(pool['client_ports'])))
    probe_port = int(meta['probe_port'])
    reserved = {int(meta[key]) for key in ['probe_port','public_port','relay_backend_port','carrier_local_port']}
    if reserved.intersection(ports):
        raise ValueError('Client port overlaps a reserved HTTP carrier/probe port')
    allowed = ports + [probe_port]
    carrier = dict(id=identity, token=meta['token'], tls=node['transport']=='https', server_name='vxlb-http')
    server_carrier = dict(carrier, role='server', listen_host=str(ipaddress.IPv4Address(pool['kharej_server']['ip'])),
                          listen_port=meta['public_port'], backend_port=meta['relay_backend_port'],
                          cert=base+'/server.crt', key=base+'/server.key', peer_cert=base+'/client.crt')
    client_carrier = dict(carrier, role='client', listen_host='127.0.0.1', listen_port=meta['carrier_local_port'],
                          remote_host=pool['kharej_server']['ip'], remote_port=meta['public_port'],
                          cert=base+'/client.crt', key=base+'/client.key', peer_cert=base+'/server.crt')
    server_relay = dict(role='server', listen_port=meta['relay_backend_port'], ports=allowed, target_host='127.0.0.1',
                        cert=base+'/server.crt', key=base+'/server.key', peer_cert=base+'/client.crt')
    client_relay = dict(role='client', carrier_port=meta['carrier_local_port'], ports=allowed, loopback_ports=[probe_port],
                        server_name='vxlb-http', cert=base+'/client.crt', key=base+'/client.key', peer_cert=base+'/server.crt')
    common = {base+'/relay.py': Path(__file__).with_name('slipstream_secure_relay.py').read_text(),
              base+'/carrier.py': Path(__file__).with_name('http_connect_agent.py').read_text(),
              base+'/firewall.py': Path(__file__).with_name('http_firewall_agent.py').read_text()}
    server_files = dict(common)
    server_files.update({base+'/server.crt':security['server_cert'], base+'/server.key':security['server_key'],
                         base+'/client.crt':security['client_cert'], base+'/server.json':json.dumps(server_relay),
                         base+'/server-carrier.json':json.dumps(server_carrier)})
    client_files = dict(common)
    client_files.update({base+'/client.crt':security['client_cert'], base+'/client.key':security['client_key'],
                         base+'/server.crt':security['server_cert'], base+'/client.json':json.dumps(client_relay),
                         base+'/client-carrier.json':json.dumps(client_carrier)})
    server_firewall = f'vxlb-http-{identity}-server-firewall.service'
    client_firewall = f'vxlb-http-{identity}-client-firewall.service'
    common_firewall=dict(id=identity,ports=ports,public_port=meta['public_port'],relay_backend_port=meta['relay_backend_port'],
                         carrier_local_port=meta['carrier_local_port'],probe_port=probe_port)
    server_files[base+'/server-firewall.json']=json.dumps(dict(common_firewall,role='server',peer=node['ip']))
    client_files[base+'/client-firewall.json']=json.dumps(dict(common_firewall,role='client'))
    for files,name,role in [(server_files,server_firewall,'server'),(client_files,client_firewall,'client')]:
        files['/etc/systemd/system/'+name]=f'[Unit]\nDescription=VX-LB HTTP owned firewall\nAfter=network-online.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 {base}/firewall.py apply {base}/{role}-firewall.json\nExecStopPost=/usr/bin/python3 {base}/firewall.py remove {base}/{role}-firewall.json\n[Install]\nWantedBy=multi-user.target\n'
    server_secure = f'vxlb-http-{identity}-server.service'
    server_proxy = f'vxlb-http-{identity}-server-carrier.service'
    client_proxy = f'vxlb-http-{identity}-client-carrier.service'
    client_secure = f'vxlb-http-{identity}-client.service'
    for files, name, script, config, parent in [
        (server_files,server_secure,'relay.py','server.json',server_firewall),
        (server_files,server_proxy,'carrier.py','server-carrier.json',server_secure),
        (client_files,client_proxy,'carrier.py','client-carrier.json',client_firewall),
        (client_files,client_secure,'relay.py','client.json',client_proxy)]:
        files['/etc/systemd/system/'+name] = unit(name,base+'/'+script,base+'/'+config,parent)
    return dict(base=base,server_files=server_files,client_files=client_files,
                server_services=[server_firewall,server_secure,server_proxy],client_services=[client_firewall,client_proxy,client_secure])


def install(ssh):
    execute(ssh, 'test "$(id -u)" = 0 && command -v python3 systemctl ss && python3 -c '+shlex.quote('import ssl;assert ssl.HAS_TLSv1_3'))


def deploy(ssh, files, services):
    for path, content in files.items():
        write(ssh,path,content)
    names = ' '.join(map(shlex.quote,services))
    execute(ssh,f'systemctl daemon-reload && systemctl enable {names} && systemctl restart {names}')
    for service in services:
        if execute(ssh,'systemctl is-active '+shlex.quote(service)) != 'active':
            raise RuntimeError('HTTP service did not remain active')


def cleanup(ssh, files, services, extra_cleanup=None):
    for service in reversed(services):
        path='/etc/systemd/system/'+service
        execute(ssh,f'if test -f {shlex.quote(path)}; then systemctl stop {shlex.quote(service)} && systemctl disable {shlex.quote(service)} || exit $?; fi; if systemctl is-active --quiet {shlex.quote(service)}; then exit 1; fi')
    if extra_cleanup is not None:extra_cleanup(ssh)
    for path in files:
        if path.endswith('-firewall.json'):
            script=path.rsplit('/',1)[0]+'/firewall.py'
            execute(ssh,f'if test -f {shlex.quote(path)}; then python3 {shlex.quote(script)} remove {shlex.quote(path)}; fi')
    execute(ssh,'rm -f '+' '.join(map(shlex.quote,files))+' && systemctl daemon-reload')


@contextmanager
def probe_lock(identity):
    if not re.fullmatch(r'[0-9a-f]{32}',identity):
        raise ValueError('Invalid HTTP probe identity')
    os.makedirs(DATA_DIR,mode=0o700,exist_ok=True)
    descriptor=os.open(os.path.join(DATA_DIR,'http-probe-'+identity+'.lock'),os.O_CREAT|os.O_RDWR,0o600)
    try:
        fcntl.flock(descriptor,fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def open_echo(kharej, command):
    """Reconnect once when the SSH control channel cannot be opened.

    No payload probe has run at this point. Do not repeat failed data checks,
    authentication failures, rejected host keys or administrative denials.
    Closing the old SSH session also closes stdin of any uncertain echo start.
    """
    for attempt in range(2):
        try:
            return kharej.client.exec_command(command,timeout=10)
        except (paramiko.AuthenticationException,paramiko.BadHostKeyException,paramiko.ChannelException):
            raise
        except (paramiko.SSHException,OSError,EOFError):
            if attempt:raise
            kharej.close()
            ok,_=kharej.connect()
            if not ok:raise RuntimeError('HTTP probe SSH reconnection failed')


def verify(iran, kharej, node):
    meta=node['http_connect'];port=int(meta['probe_port']);channel=None;stdin=None
    with probe_lock(meta['id']):
        try:
            stdin,stdout,_=open_echo(kharej,'python3 -u -c '+shlex.quote(ECHO)+' 127.0.0.1 '+str(port))
            channel=stdout.channel;channel.settimeout(10)
            if stdout.readline().strip()!=str(port):
                raise RuntimeError('HTTP probe echo could not bind its reserved loopback port')
            output=execute(iran,'python3 -c '+shlex.quote(PROBE)+' 127.0.0.1 '+str(port)+' '+secrets.token_hex(24)+" ''",timeout=40)
            result=json.loads(output)
            if result.get('passed') is not True or result.get('protocols')!=['tcp','udp']:
                raise RuntimeError('HTTP TCP/UDP nonce challenge failed')
            return result
        finally:
            if stdin:
                stdin.close()  # EOF asks the owned echo process to release its port.
            if channel:
                deadline=time.monotonic()+3
                while not channel.exit_status_ready() and time.monotonic()<deadline:
                    time.sleep(0.05)
                channel.close()


def allocate(iran, kharej, server, pool):
    excluded=set(map(int,pool['client_ports']))
    for saved in get_pools().values():
        for node in saved.get('nodes',[]):
            meta=node.get('http_connect',{})
            excluded.update(int(meta[key]) for key in ['probe_port','public_port','relay_backend_port','carrier_local_port'] if key in meta)
    public=reserve_probe_port(kharej,list(excluded),preferred=443,bind_host=pool['kharej_server']['ip']);excluded.add(public)
    backend=reserve_probe_port(kharej,list(excluded));excluded.add(backend)
    local=reserve_probe_port(iran,list(excluded));excluded.add(local)
    for _ in range(32):
        candidate=reserve_probe_port(kharej,list(excluded));excluded.add(candidate)
        if reserve_probe_port(iran,list(excluded-{candidate}),preferred=candidate)==candidate:
            break
    else:raise RuntimeError('No shared HTTP loopback probe port available')
    identity=secrets.token_hex(16)
    return dict(ip=server['ip'],name=server.get('name',server['ip']),node_name='http-'+identity,
                engine=pool['transport'],transport=pool['transport'],provisioning=True,status='PROVISIONING',
                http_connect=dict(id=identity,token=secrets.token_hex(32),public_port=public,relay_backend_port=backend,
                                  carrier_local_port=local,probe_port=candidate,security=identity_material('vxlb-http')))


def create(name, kharej, servers, ports, transport='http', callback=None):
    with mutation_lock():
        try:
            name,ports=validate_pool_name(name),validate_ports(ports)
            if transport not in MODES or not ports or not servers or name in get_pools():
                raise ValueError('Select an HTTP/HTTPS mode, unused pool name, ports and Iran servers')
            outside=ipaddress.IPv4Address(kharej['ip'])
            if len({server['ip'] for server in servers})!=len(servers):raise ValueError('Duplicate Iran server')
            for server in servers:
                if ipaddress.IPv4Address(server['ip'])==outside:raise ValueError('HTTP endpoints must be different hosts')
            from core.load_balancer import LoadBalancerManager
            ok,message=LoadBalancerManager.check_port_conflicts(ports,[s['ip'] for s in servers])
            if not ok:return False,message,{}
        except ValueError as error:return False,str(error),{}
        pool=dict(name=name,engine=transport,transport=transport,client_ports=ports,kharej_server=copy.deepcopy(kharej),nodes=[],http_runtime_version=1)
        save_pool(name,pool);failures=[]
        for server in servers:
            ok,message=add(name,server,callback)
            if not ok:failures.append(message)
        pool=get_pools()[name];ready=any(not n.get('provisioning') for n in pool['nodes'])
        return ready,('HTTP CONNECT/mTLS TCP 64KiB and UDP verified' if ready else '; '.join(failures)),pool


def add(name, server, callback=None):
    with mutation_lock():
        pool=get_pools().get(name)
        if not pool or pool.get('transport') not in MODES:return False,'HTTP pool not found'
        if any(n['ip']==server['ip'] for n in pool['nodes']):return False,'Iran server already belongs to HTTP pool'
        sessions=[];node=None;configuration=None
        try:
            if ipaddress.IPv4Address(server['ip'])==ipaddress.IPv4Address(pool['kharej_server']['ip']):raise ValueError('HTTP endpoints must be different hosts')
            from core.load_balancer import LoadBalancerManager
            ok,message=LoadBalancerManager.check_port_conflicts(pool['client_ports'],[server['ip']],exclude_pool_name=name)
            if not ok:return False,message
            if callback:callback('Preparing owned HTTP CONNECT/mTLS services')
            iran=connect(server);sessions.append((iran,'client'))
            kharej=connect(pool['kharej_server']);sessions.append((kharej,'server'))
            for ssh,_ in sessions:install(ssh)
            node=allocate(iran,kharej,server,pool)
            atomic_update(lambda data:data['pools'][name]['nodes'].append(copy.deepcopy(node)))
            configuration=plan(node,pool)
            for ssh,role in reversed(sessions):deploy(ssh,configuration[role+'_files'],configuration[role+'_services'])
            verify_listeners(iran,configuration['client_services'][-1],pool['client_ports'])
            if callback:callback('Verifying HTTP TCP 64KiB and UDP transport')
            result=None
            for attempt in range(3):
                try:result=verify(iran,kharej,node);break
                except Exception:
                    if attempt==2:raise
                    time.sleep(1)
            def commit(data):
                for entry in data['pools'][name]['nodes']:
                    if entry['node_name']==node['node_name']:
                        entry.update(provisioning=False,status='HEALTHY',reason='HTTP CONNECT/mTLS TCP 64KiB/UDP verified',latency_ms=result['latency_ms'])
            atomic_update(commit)
            return True,'HTTP CONNECT tunnel verified'
        except Exception as error:
            failures=[]
            if node:
                if configuration:
                    for ssh,role in sessions:
                        try:cleanup(ssh,configuration[role+'_files'],configuration[role+'_services'])
                        except Exception as failure:failures.append(str(failure))
                def record(data):
                    nodes=data['pools'][name]['nodes']
                    if failures:
                        for entry in nodes:
                            if entry['node_name']==node['node_name']:entry.update(status='FAILED',provisioning=True,reason=str(error),cleanup_error='; '.join(failures))
                    else:data['pools'][name]['nodes']=[entry for entry in nodes if entry['node_name']!=node['node_name']]
                atomic_update(record)
            return False,str(error)+('; cleanup required: '+'; '.join(failures) if failures else '')
        finally:
            for ssh,_ in sessions:ssh.close()


def remove(name, ip, callback=None):
    with mutation_lock():
        pool=get_pools().get(name,{})
        node=next((n for n in pool.get('nodes',[]) if n['ip']==ip),None)
        if not node:return False,'HTTP member not found'
        sessions=[]
        try:
            configuration=plan(node,pool)
            for role,server in [('client',node_credentials(node)),('server',pool['kharej_server'])]:
                ssh=connect(server);sessions.append(ssh)
                cleanup(ssh,configuration[role+'_files'],configuration[role+'_services'])
            def discard(data):data['pools'][name]['nodes']=[n for n in data['pools'][name]['nodes'] if n['ip']!=ip]
            atomic_update(discard)
            return True,'Owned HTTP services removed'
        except Exception as error:return False,str(error)
        finally:
            for ssh in sessions:ssh.close()


def remove_pool(name, callback=None):
    with mutation_lock():
        pool=get_pools().get(name)
        if not pool:return False,'HTTP pool not found'
        for node in list(pool['nodes']):
            ok,message=remove(name,node['ip'],callback)
            if not ok:return False,message
        delete_pool(name);return True,'HTTP pool removed'


def change_ports(name, requested, transport=None):
    with mutation_lock():
        sessions=[];touched=[];pairs=[]
        try:
            ports=validate_ports(requested)
            if not ports:raise ValueError('At least one application port is required')
            old=get_pools().get(name)
            if not old or old.get('transport') not in MODES:raise ValueError('HTTP pool not found')
            if any(n.get('provisioning') for n in old['nodes']):raise ValueError('HTTP provisioning/cleanup must finish first')
            from core.load_balancer import LoadBalancerManager
            ok,message=LoadBalancerManager.check_port_conflicts(ports,[n['ip'] for n in old['nodes']],exclude_pool_name=name)
            if not ok:return False,message
            changed=copy.deepcopy(old);changed['client_ports']=ports
            if transport is not None:
                if transport not in MODES:raise ValueError('Invalid HTTP mode')
                changed.update(transport=transport,engine=transport)
                for entry in changed['nodes']:entry.update(transport=transport,engine=transport)
            # Validate every proposed plan before touching any host.
            plans=[(node,plan(node,old),plan(new_node,changed)) for node,new_node in zip(old['nodes'],changed['nodes'])]
            for node,previous,new in plans:
                iran=connect(node_credentials(node));sessions.append(iran)
                kharej=connect(old['kharej_server']);sessions.append(kharej)
                pairs.append((iran,kharej,node))
                for ssh,role in [(kharej,'server'),(iran,'client')]:
                    touched.append((ssh,role,previous))
                    deploy(ssh,new[role+'_files'],new[role+'_services'])
                verify_listeners(iran,new['client_services'][-1],ports)
                verify(iran,kharej,node)
            def commit(data):
                saved=data['pools'][name]
                saved.update(client_ports=ports,transport=changed['transport'],engine=changed['engine'])
                for entry in saved['nodes']:entry.update(transport=changed['transport'],engine=changed['engine'])
            atomic_update(commit)
            return True,'HTTP CONNECT mode/ports verified and saved'
        except Exception as error:
            failures=[]
            for ssh,role,previous in reversed(touched):
                try:deploy(ssh,previous[role+'_files'],previous[role+'_services'])
                except Exception as failure:failures.append(str(failure))
            if not failures:
                for iran,kharej,node in pairs:
                    try:verify(iran,kharej,node)
                    except Exception as failure:failures.append(str(failure))
            detail='rollback unverified: '+'; '.join(failures) if failures else 'previous ports restored' if touched else 'ports unchanged'
            return False,f'HTTP port change failed ({detail}): {error}'
        finally:
            for ssh in sessions:ssh.close()


def health(name, node, ports):
    if node.get('provisioning'):return 'DOWN','HTTP deployment/cleanup is incomplete',{}
    sessions=[]
    try:
        pool=get_pools()[name];configuration=plan(node,pool)
        iran=connect(node_credentials(node));sessions.append(iran)
        kharej=connect(pool['kharej_server']);sessions.append(kharej)
        verify_listeners(iran,configuration['client_services'][-1],ports)
        result=verify(iran,kharej,node)
        program='''import socket,json,sys
result={}
for port in json.loads(sys.argv[1]):
 try:
  with socket.create_connection(('127.0.0.1',int(port)),timeout=2):result[str(port)]=True
 except OSError:result[str(port)]=False
print(json.dumps(result))
'''
        destinations=json.loads(execute(kharej,'python3 -c '+shlex.quote(program)+' '+shlex.quote(json.dumps(ports)),timeout=max(15,len(ports)*3)))
        details={str(port):dict(status='HEALTHY' if destinations.get(str(port)) else 'DOWN',path_verified=True,
                 destination_tcp=bool(destinations.get(str(port))),udp_application='UNVERIFIED',latency_ms=result['latency_ms']) for port in ports}
        count=sum(d['status']=='HEALTHY' for d in details.values())
        return ('HEALTHY' if count==len(ports) else 'DEGRADED' if count else 'DOWN'),f'{count}/{len(ports)} TCP destinations ready; HTTP/mTLS TCP/UDP transport verified',details
    except Exception as error:return 'DOWN','HTTP/mTLS data verification failed: '+str(error),{}
    finally:
        for ssh in sessions:ssh.close()


def change_mode(name, mode):
    pool=get_pools().get(name,{})
    if mode not in MODES or pool.get('transport') not in MODES:return False,'HTTP/HTTPS pool and mode required'
    return change_ports(name,pool['client_ports'],transport=mode)
