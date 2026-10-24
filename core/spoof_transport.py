"""Managed lifecycle for five packet profiles; frontend gate remains separate.

A node is accepted only after the real mTLS TCP/UDP challenge, owned queue
traffic and profile-specific wire evidence all succeed. No DPI-bypass verdict
is inferred from successful data transfer.
"""
import copy
import ipaddress
import json
import secrets
import shlex
import time
from core.storage import get_pools,save_pool,delete_pool,atomic_update
from core.transport_change import connect,mutation_lock
from core.validation import validate_pool_name,validate_ports
from core.gre import write
from core.kernel_relay_ports import node_credentials,verify_listeners
from core.tunnel_probe import reserve_probe_port
from core.nfqws2_profiles import MODES,hostname,number
from core import http_transport as http
from core import nfqws2_install
from core.spoof_managed_plan import plan
from core.private_link_health import ECHO,PROBE

execute=http.execute
deploy=http.deploy


def install(ssh,allow_download=False):
    http.install(ssh)
    nfqws2_install.install(ssh,allow_download=allow_download)


def allocate(iran,kharej,server,pool):
    shadow=copy.deepcopy(pool);shadow['transport']='https'
    node=http.allocate(iran,kharej,server,shadow)
    output=execute(iran,"python3 -c 'from pathlib import Path;print(Path(\"/proc/net/netfilter/nfnetlink_queue\").read_text())'")
    used={int(row.split()[0]) for row in output.splitlines() if row.strip()}
    excluded=set(map(int,pool['client_ports']))
    for saved in get_pools().values():
        for entry in saved.get('nodes',[]):
            packet=entry.get('spoof',{})
            if packet.get('queue'):used.add(int(packet['queue']))
            if packet.get('record_port'):excluded.add(int(packet['record_port']))
            meta=entry.get('http_connect',{})
            excluded.update(int(meta[key]) for key in ['probe_port','public_port','relay_backend_port','carrier_local_port'] if key in meta)
    seed=20000+secrets.randbelow(40000)
    queue=next((20000+(seed-20000+offset)%40000 for offset in range(40000) if 20000+(seed-20000+offset)%40000 not in used),None)
    if queue is None:raise RuntimeError('No unused packet queue available')
    node.update(engine='spoof',transport=pool['transport'],node_name='spoof-'+node['http_connect']['id'])
    node['spoof']=dict(profile=pool['transport'],queue=queue,fake_sni=pool['fake_sni'],ttl_delta=pool['ttl_delta'])
    if pool['transport']=='split-tls':
        excluded.update(int(node['http_connect'][key]) for key in ['probe_port','public_port','relay_backend_port','carrier_local_port'])
        node['spoof']['record_port']=reserve_probe_port(iran,list(excluded))
    return node


def cleanup(ssh,files,services):
    configurations=[path for path in files if path.endswith('/queue.json')]
    def remove_queue(session):
        for path in configurations:
            script=path.rsplit('/',1)[0]+'/queue-agent.py'
            # Restore only owned cleanup inputs if interrupted provisioning
            # never wrote them. Neither action starts a service or data path.
            write(session,script,files[script]);write(session,path,files[path])
            execute(session,'python3 '+shlex.quote(script)+' remove '+shlex.quote(path))
    http.cleanup(ssh,files,services,extra_cleanup=remove_queue if configurations else None)


def queue_status(iran,node):
    identity=node['http_connect']['id']
    if len(identity)!=32 or any(c not in '0123456789abcdef' for c in identity):raise ValueError('Invalid packet ownership identity')
    base='/etc/vxlb/spoof/'+identity
    return json.loads(execute(iran,'python3 '+shlex.quote(base+'/queue-agent.py')+' status '+shlex.quote(base+'/queue.json')))


def finish_process(stdin,channel):
    if stdin is not None:stdin.close()
    if channel is not None:
        deadline=time.monotonic()+3
        while not channel.exit_status_ready() and time.monotonic()<deadline:time.sleep(.05)
        channel.close()


def verify(iran,kharej,node):
    meta=node['http_connect'];port=int(meta['probe_port']);streams=[]
    with http.probe_lock(meta['id']):
        try:
            stdin,stdout,_=http.open_echo(kharej,'python3 -u -c '+shlex.quote(ECHO)+' 127.0.0.1 '+str(port))
            streams.append((stdin,stdout.channel));stdout.channel.settimeout(10)
            if stdout.readline().strip()!=str(port):raise RuntimeError('Packet probe echo could not bind')
            before=queue_status(iran,node)
            base='/etc/vxlb/spoof/'+meta['id']
            trace_in,trace_out,_=iran.client.exec_command('python3 -u '+shlex.quote(base+'/wire.py')+' '+shlex.quote(base+'/wire.json'),timeout=10)
            streams.append((trace_in,trace_out.channel));trace_out.channel.settimeout(25)
            if trace_out.readline().strip()!='READY':raise RuntimeError('Packet wire observer did not start')
            result=json.loads(execute(iran,'python3 -c '+shlex.quote(PROBE)+' 127.0.0.1 '+str(port)+' '+secrets.token_hex(24)+" ''",timeout=40))
            trace_in.close()
            wire=json.loads(trace_out.readline())
            after=queue_status(iran,node)
            if before.get('verified') is not True or after.get('verified') is not True:raise RuntimeError('Packet queue ownership was not verified')
            if result.get('passed') is not True or result.get('protocols')!=['tcp','udp']:raise RuntimeError('Packet profile TCP/UDP nonce challenge failed')
            if before.get('owner_pid')!=after.get('owner_pid') or (int(after['seen'])-int(before['seen']))%(1<<32)==0:
                raise RuntimeError('Packet profile probe did not cross a stable owned queue')
            if after['kernel_dropped']>before['kernel_dropped'] or after['user_dropped']>before['user_dropped']:
                raise RuntimeError('Managed queue dropped packets during verification')
            if wire.get('profile')!=node['transport'] or wire.get('passed') is not True:
                raise RuntimeError('Required packet transformation was not observed: '+json.dumps(wire.get('observations',{}),sort_keys=True))
            return dict(result,wire=wire,queue=after)
        finally:
            for stdin,channel in reversed(streams):finish_process(stdin,channel)


def create(name, kharej, servers, ports, transport='fake-sni', callback=None, fake_sni='www.shaparak.ir', auto_ttl_delta=3, **kwargs):
    with mutation_lock():
        try:
            name,ports=validate_pool_name(name),validate_ports(ports)
            fake_sni=hostname(fake_sni);delta=number(auto_ttl_delta,1,15,'TTL delta')
            if transport!='hop-ttl-injection' and delta!=3:raise ValueError('TTL delta applies only to the Hop profile')
            if transport not in ('fake-sni','hop-ttl-injection') and fake_sni!='www.shaparak.ir':raise ValueError('Selected profile does not inject a fake SNI')
            if transport=='hop-ttl-injection' and fake_sni=='vxlb-http':raise ValueError('Fake SNI must differ from the authenticated carrier identity')
            if any(kwargs.get(key) for key in ['spoof_ips','peer_spoof_ip','dns_resolvers','send_domains','fake_send_ip','fake_send_port','info_encryption_pass','knock_key','mode']):raise ValueError('Raw source/DNS options do not apply to this packet profile')
            if transport not in MODES or not ports or not servers or name in get_pools():
                raise ValueError('Select a packet profile mode, unused pool name, ports and Iran servers')
            outside=ipaddress.IPv4Address(kharej['ip'])
            if len({server['ip'] for server in servers})!=len(servers):raise ValueError('Duplicate Iran server')
            for server in servers:
                if ipaddress.IPv4Address(server['ip'])==outside:raise ValueError('Packet endpoints must be different hosts')
            from core.load_balancer import LoadBalancerManager
            ok,message=LoadBalancerManager.check_port_conflicts(ports,[s['ip'] for s in servers])
            if not ok:return False,message,{}
        except ValueError as error:return False,str(error),{}
        pool=dict(name=name,engine='spoof',transport=transport,client_ports=ports,kharej_server=copy.deepcopy(kharej),nodes=[],spoof_runtime_version=1,fake_sni=fake_sni,ttl_delta=delta)
        save_pool(name,pool);failures=[]
        for server in servers:
            ok,message=add(name,server,callback)
            if not ok:failures.append(message)
        pool=get_pools()[name];ready=any(not n.get('provisioning') for n in pool['nodes'])
        return ready,('Packet profile/mTLS TCP 64KiB and UDP verified' if ready else '; '.join(failures)),pool


def add(name, server, callback=None):
    with mutation_lock():
        pool=get_pools().get(name)
        if not pool or pool.get('transport') not in MODES or pool.get('spoof_runtime_version')!=1:return False,'Managed packet pool not found'
        if any(n['ip']==server['ip'] for n in pool['nodes']):return False,'Iran server already belongs to Packet pool'
        sessions=[];node=None;configuration=None
        try:
            if ipaddress.IPv4Address(server['ip'])==ipaddress.IPv4Address(pool['kharej_server']['ip']):raise ValueError('Packet endpoints must be different hosts')
            from core.load_balancer import LoadBalancerManager
            ok,message=LoadBalancerManager.check_port_conflicts(pool['client_ports'],[server['ip']],exclude_pool_name=name)
            if not ok:return False,message
            if callback:callback('Installing owned packet-profile services')
            iran=connect(server);sessions.append((iran,'client'))
            kharej=connect(pool['kharej_server']);sessions.append((kharej,'server'))
            for ssh,_ in sessions:install(ssh)
            node=allocate(iran,kharej,server,pool)
            atomic_update(lambda data:data['pools'][name]['nodes'].append(copy.deepcopy(node)))
            configuration=plan(node,pool)
            for ssh,role in reversed(sessions):deploy(ssh,configuration[role+'_files'],configuration[role+'_services'])
            verify_listeners(iran,configuration['client_services'][-1],pool['client_ports'])
            if callback:callback('Verifying packet transformation and TCP 64KiB/UDP data')
            result=None
            for attempt in range(3):
                try:result=verify(iran,kharej,node);break
                except Exception:
                    if attempt==2:raise
                    time.sleep(1)
            def commit(data):
                for entry in data['pools'][name]['nodes']:
                    if entry['node_name']==node['node_name']:
                        entry.update(provisioning=False,status='HEALTHY',reason='mTLS TCP/UDP and packet transformation verified',latency_ms=result['latency_ms'])
                        entry['spoof']['wire_evidence']=result['wire']
                        entry['spoof']['queue_pid']=result['queue']['owner_pid']
            atomic_update(commit)
            return True,'Packet profile tunnel verified'
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
        if pool.get('spoof_runtime_version')!=1 or pool.get('transport') not in MODES:return False,'Managed packet pool not found'
        node=next((n for n in pool.get('nodes',[]) if n['ip']==ip),None)
        if not node:return False,'Packet member not found'
        sessions=[]
        try:
            configuration=plan(node,pool)
            for role,server in [('client',node_credentials(node)),('server',pool['kharej_server'])]:
                ssh=connect(server);sessions.append(ssh)
                cleanup(ssh,configuration[role+'_files'],configuration[role+'_services'])
            def discard(data):data['pools'][name]['nodes']=[n for n in data['pools'][name]['nodes'] if n['ip']!=ip]
            atomic_update(discard)
            return True,'Owned packet services removed'
        except Exception as error:return False,str(error)
        finally:
            for ssh in sessions:ssh.close()


def remove_pool(name, callback=None):
    with mutation_lock():
        pool=get_pools().get(name)
        if not pool or pool.get('spoof_runtime_version')!=1 or pool.get('transport') not in MODES:return False,'Managed packet pool not found'
        for node in list(pool['nodes']):
            ok,message=remove(name,node['ip'],callback)
            if not ok:return False,message
        delete_pool(name);return True,'Packet pool removed'


def change_ports(name, requested, transport=None):
    with mutation_lock():
        sessions=[];touched=[];pairs=[]
        try:
            ports=validate_ports(requested)
            if not ports:raise ValueError('At least one application port is required')
            old=get_pools().get(name)
            if not old or old.get('transport') not in MODES or old.get('spoof_runtime_version')!=1:raise ValueError('Packet pool not found')
            if any(n.get('provisioning') for n in old['nodes']):raise ValueError('Packet provisioning/cleanup must finish first')
            from core.load_balancer import LoadBalancerManager
            ok,message=LoadBalancerManager.check_port_conflicts(ports,[n['ip'] for n in old['nodes']],exclude_pool_name=name)
            if not ok:return False,message
            changed=copy.deepcopy(old);changed['client_ports']=ports
            if transport is not None:
                if transport!=old['transport']:raise ValueError('Packet-profile migration requires a separate pool')
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
            return True,'Packet profile mode/ports verified and saved'
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
            return False,f'Packet port change failed ({detail}): {error}'
        finally:
            for ssh in sessions:ssh.close()


def health(name, node, ports):
    if node.get('provisioning'):return 'DOWN','Packet deployment/cleanup is incomplete',{}
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
        return ('HEALTHY' if count==len(ports) else 'DEGRADED' if count else 'DOWN'),f'{count}/{len(ports)} TCP destinations ready; Packet/mTLS TCP/UDP transport verified',details
    except Exception as error:return 'DOWN','Packet/mTLS data verification failed: '+str(error),{}
    finally:
        for ssh in sessions:ssh.close()
