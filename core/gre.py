"""GRE IPv4 pool adapter: private /30 links and stdlib TCP/UDP relays."""
import copy
import ipaddress
import json
import secrets
import shlex
import time
from pathlib import Path
from core.gre_agent import validate
from core.storage import load_data, atomic_update, get_pools, save_pool, delete_pool
from core.validation import validate_pool_name, validate_ports
from core.transport_change import connect

AGENT = '/usr/local/libexec/vxlb-gre-v1.py'
CONFIG_DIR = '/etc/vxlb/gre'


def validate_mtu(value):
    if str(value).strip().isdigit() and 576 <= int(value) <= 1400: return int(value)
    raise ValueError('GRE MTU must be an integer between 576 and 1400')


def execute(ssh, command, timeout=30):
    code, out, error = ssh.execute(command, timeout=timeout)
    if code: raise RuntimeError(error.strip() or out.strip() or 'GRE remote command failed')
    return out.strip()


def install_agent(ssh):
    try:
        execute(ssh, 'command -v python3 && command -v ip && command -v iptables && command -v systemctl && systemctl cat strongswan.service >/dev/null && test "$(id -u)" = 0')
    except RuntimeError as error:
        raise RuntimeError('GRE امن به root، iproute2، iptables و سرویس فعال strongswan.service با VICI نیاز دارد؛ هیچ حالت خامی فعال نشد. '+str(error)) from error
    for file in Path(__file__).with_name('vendor').joinpath('vici').glob('*.py'):
        write(ssh, '/usr/local/libexec/vxlb-gre-vici/vici/'+file.name, file.read_text())
    write(ssh, '/usr/local/libexec/vxlb-gre-vici/LICENSE', Path(__file__).with_name('vendor').joinpath('vici/LICENSE').read_text())
    write(ssh, AGENT, Path(__file__).with_name('gre_agent.py').read_text())


def write(ssh, path, content, exclusive=False):
    staged = path + '.tmp-' + secrets.token_hex(4)
    if not ssh.write_file(staged, content): raise RuntimeError('Writing GRE configuration failed')
    try:
        publish = ('ln '+shlex.quote(staged)+' '+shlex.quote(path)+' && rm -f '+shlex.quote(staged)) if exclusive else ('mv -f '+shlex.quote(staged)+' '+shlex.quote(path))
        execute(ssh, 'chmod 600 ' + shlex.quote(staged) + ' && '+publish)
    except Exception:
        ssh.execute('rm -f '+shlex.quote(staged));raise


def path(node): return CONFIG_DIR + '/' + validate(node['gre']['configs'][0])['interface'] + '.json'


def unit(node, relay=False):
    return 'vxlb-gre-' + validate(node['gre']['configs'][0])['interface'] + ('-relay' if relay else '') + '.service'


def run_agent(ssh, node, action, *args):
    return execute(ssh, 'python3 ' + shlex.quote(AGENT) + ' ' + shlex.quote(action) + ' ' + shlex.quote(path(node)) + ''.join(' ' + shlex.quote(str(arg)) for arg in args), timeout=60 if action == 'secure-start' else 30)


def service(node, relay=False):
    config = path(node); helper = 'python3 ' + AGENT; link_unit = unit(node)
    return f'''[Unit]
Description=VX-LB GRE {'TCP/UDP relay' if relay else 'private link'}
After=network-online.target strongswan.service {link_unit if relay else ''}
Requires=strongswan.service
PartOf=strongswan.service
Wants=network-online.target
{'Requires='+link_unit if relay else ''}
[Service]
Type={'simple' if relay else 'oneshot'}
{'RemainAfterExit=yes' if not relay else 'Restart=on-failure'}
ExecStart=/usr/bin/{helper} {'relay' if relay else 'up'} {config}
{'' if relay else 'ExecStop=/usr/bin/'+helper+' down '+config}
{'' if relay else 'ExecReload=/usr/bin/'+helper+' up '+config}
{'RestartSec=3' if relay else 'TimeoutStartSec=90'}
TimeoutStopSec=30
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
{'ProtectSystem=strict' if relay else ''}
[Install]
WantedBy=multi-user.target
'''


def allocate(server, kharej, ports, mtu):
    local = str(ipaddress.IPv4Address(server['ip'])); remote = str(ipaddress.IPv4Address(kharej['ip']))
    if local == remote: raise ValueError('GRE endpoints must be different servers')
    used = {c['private'] for pool in get_pools().values() for node in pool.get('nodes', []) for c in node.get('gre', {}).get('configs', [])}
    block = ipaddress.IPv4Network('10.203.0.0/16')
    start = secrets.randbelow(16384)
    for index in range(16384):
        base = int(block.network_address) + ((start + index) % 16384) * 4
        private, peer = str(ipaddress.IPv4Address(base+1)), str(ipaddress.IPv4Address(base+2))
        if private not in used and peer not in used: break
    else: raise ValueError('GRE private address pool exhausted')
    interface = 'ldg' + secrets.token_hex(5); key = secrets.randbelow(4294967295) + 1
    for pool in get_pools().values():
        for n in pool.get('nodes', []):
            for c in n.get('gre', {}).get('configs', []):
                if {c['local'], c['remote']} == {local, remote}:
                    raise ValueError('Only one managed IPsec GRE link per endpoint pair is currently supported')
    security = {'mode':'ipsec', 'psk':secrets.token_hex(32), 'reqid':secrets.randbelow(2147483647)+1}
    common = dict(security=security, owner='vxlb-gre-v1', interface=interface, key=key, mtu=validate_mtu(mtu), ports=validate_ports(ports))
    configs = [validate(dict(common, role='iran', local=local, remote=remote, private=private, peer=peer)),
               validate(dict(common, role='kharej', local=remote, remote=local, private=peer, peer=private))]
    return dict(server, server_name=server['name'], node_name=interface, engine='gre', transport='gre',
                status='pending', provisioning=True, gre={'configs':configs, 'mtu':mtu, 'local_private':private, 'remote_private':peer})


def verify(iran, kharej, node):
    for ssh in (iran, kharej): run_agent(ssh,node,'secure-check')
    # Each side initiates TCP+UDP, and every response must match its nonce.
    for source, target in ((iran,kharej),(kharej,iran)):
        channel = None
        try:
            _, stdout, _ = target.client.exec_command('python3 ' + shlex.quote(AGENT) + ' echo ' + shlex.quote(path(node)), timeout=10)
            channel = stdout.channel
            line = stdout.readline().strip()
            if not line.isdigit(): raise RuntimeError('GRE echo endpoint failed to start')
            run_agent(source,node,'probe',int(line),secrets.token_hex(24))
        finally:
            if channel: channel.close()
    return True


def cleanup_endpoint(ssh,node,iran):
    units = [unit(node,True),unit(node)] if iran else [unit(node)]
    for name in units:
        # The stop hook removes only this link's interface and scoped rules.
        execute(ssh, 'if test -f ' + shlex.quote('/etc/systemd/system/'+name) + '; then systemctl disable --now ' + shlex.quote(name) + '; fi', timeout=90)
    run_agent(ssh,node,'down')
    execute(ssh,'rm -f '+ ' '.join(shlex.quote('/etc/systemd/system/'+name) for name in units) + ' ' + shlex.quote(path(node)))
    execute(ssh,'systemctl daemon-reload')


def update_job(pool,target_ip,**fields):
    def write_job(data): data['pools'][pool].setdefault('node_additions',{}).setdefault(target_ip,{}).update(fields,updated_at=time.time())
    atomic_update(write_job)


def add(pool_name, server, callback=None):
    pool = get_pools().get(pool_name)
    if not pool: return False,'GRE pool not found'
    if any(n['ip'] == server['ip'] for n in pool['nodes']): return False,'Server already belongs to this pool'
    from core.load_balancer import LoadBalancerManager
    ok,message = LoadBalancerManager.check_port_conflicts(pool['client_ports'],[server['ip']],exclude_pool_name=pool_name)
    if not ok: return False,message
    try: node = allocate(server,pool['kharej_server'],pool['client_ports'],pool.get('gre_mtu',1400))
    except ValueError as error: return False,str(error)
    sessions=[]; installed=[]; configs_written=[]; committed=False
    def progress(message):
        update_job(pool_name,server['ip'],status='running',ip=server['ip'],name=server['name'],message=message)
        if callback: callback(message)
    try:
        progress('بررسی پیش‌نیازهای GRE و دسترسی دو سرور')
        iran=connect(server);sessions.append(iran);kharej=connect(pool['kharej_server']);sessions.append(kharej)
        for ssh,c in zip(sessions,node['gre']['configs']):
            install_agent(ssh)
            execute(ssh,'test ! -e '+shlex.quote('/etc/systemd/system/'+unit(node))+' && test ! -e '+shlex.quote('/etc/systemd/system/'+unit(node,True)))
            write(ssh,path(node),json.dumps(c),exclusive=True);configs_written.append(ssh);run_agent(ssh,node,'preflight')
        # Persist before remote mutations so an interrupted setup can be removed.
        def reserve(data): data['pools'][pool_name]['nodes'].append(node)
        atomic_update(reserve);committed=True;installed=list(sessions)
        progress('ساخت لینک خصوصی GRE و قواعد اختصاصی فایروال')
        for ssh in sessions:
            write(ssh,'/etc/systemd/system/'+unit(node),service(node))
            execute(ssh,'systemctl daemon-reload');execute(ssh,'systemctl enable --now '+shlex.quote(unit(node)),timeout=90)
        run_agent(iran,node,'secure-start')
        progress('آزمون مستقل TCP و UDP در دو جهت لینک GRE')
        verify(iran,kharej,node)
        progress('راه‌اندازی فوروارد TCP و UDP پورت‌های استخر')
        write(iran,'/etc/systemd/system/'+unit(node,True),service(node,True))
        execute(iran,'systemctl daemon-reload');execute(iran,'systemctl enable --now '+shlex.quote(unit(node,True)),timeout=90)
        # Bind failures occur asynchronously for Type=simple; do not accept an
        # active process before checking that it actually owns all listeners.
        verify_relay(iran,node,pool['client_ports'])
        def finish(data):
            for member in data['pools'][pool_name]['nodes']:
                if member['node_name']==node['node_name']: member.update(provisioning=False,status='active')
        atomic_update(finish)
        update_job(pool_name,server['ip'],status='succeeded',message='لینک GRE و فوروارد پورت‌ها آماده شد',error='')
        return True,'GRE link and TCP/UDP relay verified'
    except Exception as error:
        failures=[]
        for index,ssh in enumerate(sessions):
            if ssh not in installed:
                if ssh in configs_written:
                    try: execute(ssh,'rm -f '+shlex.quote(path(node)))
                    except Exception: pass
                continue
            try: cleanup_endpoint(ssh,node,index==0)
            except Exception as cleanup_error: failures.append(str(cleanup_error))
        if committed and not failures:
            def discard(data): data['pools'][pool_name]['nodes']=[n for n in data['pools'][pool_name]['nodes'] if n['node_name']!=node['node_name']]
            atomic_update(discard)
        message=str(error)+(('; پاک‌سازی کامل نشد: '+'; '.join(failures)) if failures else '')
        update_job(pool_name,server['ip'],status='failed',message='راه‌اندازی GRE کامل نشد',error=message)
        return False,message
    finally:
        for ssh in sessions: ssh.close()


def verify_relay(ssh,node,ports):
    script='''import json,socket,subprocess,sys
unit=sys.argv[1];ports=set(map(int,json.loads(sys.argv[2])))
pid=subprocess.check_output(['systemctl','show',unit,'--property=MainPID','--value'],text=True).strip()
if not pid.isdigit() or int(pid)==0:sys.exit(1)
for kind in ['-ltnp','-lunp']:
 text=subprocess.check_output(['ss',kind],text=True)
 found={int(line.split()[3].rsplit(':',1)[-1]) for line in text.splitlines()[1:] if 'pid='+pid+',' in line}
 if not ports.issubset(found):sys.exit(1)
'''
    command='python3 -c '+shlex.quote(script)+' '+shlex.quote(unit(node,True))+' '+shlex.quote(json.dumps(ports))
    for _ in range(10):
        if ssh.execute(command)[0]==0: return
        time.sleep(.3)
    raise RuntimeError('GRE relay did not bind all TCP and UDP ports; inspect the relay journal')


def create(name,kharej,servers,ports,mtu=1280,callback=None):
    try:
        name=validate_pool_name(name);ports=validate_ports(ports);mtu=validate_mtu(mtu)
        ipaddress.IPv4Address(kharej['ip'])
        if not servers: raise ValueError('Select at least one Iran server')
        for server in servers: ipaddress.IPv4Address(server['ip'])
        if len({s['ip'] for s in servers})!=len(servers): raise ValueError('Duplicate Iran server')
        if name in get_pools(): raise ValueError('Pool name already exists')
        from core.load_balancer import LoadBalancerManager
        ok,message=LoadBalancerManager.check_port_conflicts(ports,[s['ip'] for s in servers])
        if not ok: return False,message,{}
    except ValueError as error: return False,str(error),{}
    pool=dict(name=name,engine='gre',transport='gre',gre_mtu=mtu,client_ports=ports,kharej_server=kharej,nodes=[],created_at=time.strftime('%Y-%m-%d %H:%M:%S'))
    save_pool(name,pool)
    failures=[]
    for server in servers:
        ok,message=add(name,server,callback)
        if not ok: failures.append(server['ip']+': '+message)
    pool=get_pools()[name]
    ready=[n for n in pool['nodes'] if not n.get('provisioning')]
    return bool(ready),('GRE pool ready'+('; failures: '+'; '.join(failures) if failures else '') if ready else '; '.join(failures)),pool


def remove(pool_name,ip,callback=None):
    pool=get_pools().get(pool_name,{})
    node=next((n for n in pool.get('nodes',[]) if n['ip']==ip),None)
    if not node:return False,'GRE node not found'
    sessions=[]
    try:
        # Acquire both connections before removing anything.
        sessions.append(connect(node));sessions.append(connect(pool['kharej_server']))
        for index,ssh in enumerate(sessions):
            if callback: callback('در حال حذف منابع GRE سمت '+('ایران' if index==0 else 'خارج'))
            cleanup_endpoint(ssh,node,index==0)
        def discard(data): data['pools'][pool_name]['nodes']=[n for n in data['pools'][pool_name]['nodes'] if n['ip']!=ip]
        atomic_update(discard)
        return True,'GRE node removed'
    except Exception as error:return False,str(error)
    finally:
        for ssh in sessions:ssh.close()


def remove_pool(name,callback=None):
    pool=get_pools().get(name)
    if not pool:return False,'GRE pool not found'
    for node in pool['nodes']:
        ok,message=remove(name,node['ip'],callback)
        if not ok:return False,message
    delete_pool(name);return True,'GRE pool removed'


def change_ports(name,ports,recovery=False):
    pool=get_pools().get(name)
    try: ports=validate_ports(ports)
    except ValueError as error:return False,str(error)
    if not pool:return False,'GRE pool not found'
    from core.load_balancer import LoadBalancerManager
    ok,message=LoadBalancerManager.check_port_conflicts(ports,[n['ip'] for n in pool['nodes']],exclude_pool_name=name)
    if not ok:return False,message
    try:pool=begin_update(name,'ports',ports,recovery)
    except ValueError as error:return False,str(error)
    updated=[];sessions=[]
    try:
        for node in pool['nodes']:
            if node.get('provisioning'):raise RuntimeError('GRE node requires cleanup before changing ports')
            ssh=connect(node);sessions.append(ssh)
            old=node['gre']['configs'][0];new=dict(old,ports=ports)
            updated.append((ssh,node,old,new))
            run_agent(ssh,node,'unfirewall');write(ssh,path(node),json.dumps(new));run_agent(ssh,node,'firewall')
            execute(ssh,'systemctl restart '+shlex.quote(unit(node,True)),timeout=90);verify_relay(ssh,node,ports)
        def commit(data):
            p=data['pools'][name];p['client_ports']=ports
            for n in p['nodes']: n['gre']['configs'][0]['ports']=list(map(int,ports))
        atomic_update(commit);finish_update(name,'succeeded','پورت‌های TCP و UDP استخر GRE به‌روزرسانی شدند');return True,'GRE TCP/UDP ports updated; existing relay connections may have restarted'
    except Exception as error:
        failures=[]
        for ssh,node,old,new in reversed(updated):
            try:
                run_agent(ssh,node,'unfirewall');write(ssh,path(node),json.dumps(old));run_agent(ssh,node,'firewall')
                execute(ssh,'systemctl restart '+shlex.quote(unit(node,True)),timeout=90);verify_relay(ssh,node,old['ports'])
            except Exception as rollback_error:failures.append(str(rollback_error))
        message=str(error)+(('; rollback incomplete: '+'; '.join(failures)) if failures else '')
        finish_update(name,'rollback_failed' if failures or recovery else 'failed','تغییر پورت GRE ناموفق بود؛ وضعیت بازگردانی را بررسی کنید',message)
        return False,message
    finally:
        for ssh in sessions:ssh.close()


def health(pool_name,node,ports):
    if node.get('provisioning'):return 'DOWN','GRE provisioning interrupted or cleanup required',{}
    pool=get_pools().get(pool_name,{})
    sessions=[]
    try:
        iran=connect(node);sessions.append(iran);kharej=connect(pool['kharej_server']);sessions.append(kharej)
        verify(iran,kharej,node);verify_relay(iran,node,ports)
        script='''import socket,json,sys
host=sys.argv[1];result={}
for port in json.loads(sys.argv[2]):
 item={"tcp":False,"udp":"silent"}
 try:
  with socket.create_connection((host,int(port)),timeout=2):item["tcp"]=True
 except OSError:item["tcp"]=False
 sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.settimeout(1)
 try:
  sock.connect((host,int(port)));sock.send(b"vxlb")
  try:
   sock.recv(64);item["udp"]="reply"
  except socket.timeout:item["udp"]="silent"
 except ConnectionRefusedError:item["udp"]="closed"
 except OSError:item["udp"]="error"
 finally:sock.close()
 result[str(port)]=item
print(json.dumps(result))
'''
        out=execute(iran,'python3 -c '+shlex.quote(script)+' '+shlex.quote(node['gre']['remote_private'])+' '+shlex.quote(json.dumps(ports)))
        availability=json.loads(out)
        details={}
        for port, item in availability.items():
            tcp=bool(item.get('tcp')) if isinstance(item, dict) else bool(item)
            udp=item.get('udp', 'unverified') if isinstance(item, dict) else 'unverified'
            if tcp and udp=='reply':
                reason='GRE tunnel TCP/UDP verified; destination TCP and UDP replied'
            elif tcp and udp=='closed':
                reason='GRE tunnel TCP/UDP verified; destination TCP is up and destination UDP is closed'
            elif tcp:
                reason='GRE tunnel TCP/UDP verified; destination TCP is up; destination UDP did not reply'
            else:
                reason='GRE tunnel passed; TCP destination is not listening'
            details[port]={'status':'HEALTHY' if tcp else 'DOWN','reason':reason,'destination_tcp':tcp,'udp_application':udp,'last_success_epoch':time.time() if tcp else None}
        live=sum(item['status']=='HEALTHY' for item in details.values())
        closed=sum(item.get('udp_application')=='closed' for item in details.values())
        summary='GRE data path verified; %s/%s TCP destinations reachable' % (live, len(ports))
        if closed:
            summary += '; %s destination UDP port(s) closed' % closed
        return ('HEALTHY' if live==len(ports) and live else 'DEGRADED' if live else 'DOWN'), summary, details
    except Exception as error:return 'DOWN','GRE verification failed: '+str(error),{}
    finally:
        for ssh in sessions:ssh.close()


def begin_update(name,kind,target,recovery=False):
    from core.transport_change import busy
    from core.dns_routing import routing_lock
    with routing_lock():
        data=load_data();pool=data.get('pools',{}).get(name)
        if not pool or pool.get('transport')!='gre':raise ValueError('GRE pool not found')
        current=pool.get('gre_update',{})
        if current.get('status')=='rollback_failed' and not recovery:raise ValueError('Restore the previous GRE update before making a new change')
        candidate=copy.deepcopy(data)
        if recovery and current.get('status')=='rollback_failed':candidate['pools'][name]['gre_update']={}
        if busy(candidate):raise ValueError('Another pool operation is in progress')
        def queue(data):data['pools'][name]['gre_update']={'kind':kind,'status':'running','target':target,'message':'در حال اعمال تنظیمات GRE','updated_at':time.time()}
        atomic_update(queue)
    return pool


def finish_update(name,status,message,error=''):
    def finish(data):data['pools'][name]['gre_update'].update(status=status,message=message,error=error,updated_at=time.time())
    atomic_update(finish)


def change_mtu(name,value,recovery=False):
    try:
        mtu=validate_mtu(value);pool=begin_update(name,'mtu',mtu,recovery)
    except ValueError as error:return False,str(error)
    sessions=[];changed=[]
    try:
        for node in pool['nodes']:
            if node.get('provisioning'):raise RuntimeError('GRE node requires cleanup before changing settings')
            pair=[]
            for server,old in zip((node,pool['kharej_server']),node['gre']['configs']):
                ssh=connect(server);sessions.append(ssh);pair.append(ssh)
                new=dict(old,mtu=mtu);changed.append((ssh,node,old))
                write(ssh,path(node),json.dumps(new));run_agent(ssh,node,'mtu')
            verify(*pair,node)
        def commit(data):
            p=data['pools'][name];p['gre_mtu']=mtu
            for node in p['nodes']:
                node['gre']['mtu']=mtu
                for c in node['gre']['configs']:c['mtu']=mtu
        atomic_update(commit);finish_update(name,'succeeded','MTU تمام لینک‌های GRE اعمال و آزمون ترافیک تأیید شد')
        return True,'GRE MTU updated and verified'
    except Exception as error:
        failures=[]
        for ssh,node,old in reversed(changed):
            try:write(ssh,path(node),json.dumps(old));run_agent(ssh,node,'mtu')
            except Exception as rollback_error:failures.append(str(rollback_error))
        # Restoration requires data proof, not just successful ip-link commands.
        for index in range(0,len(sessions),2):
            if index+1>=len(sessions):
                if changed: failures.append('Restored GRE data path could not be verified because the second endpoint is unavailable')
                continue
            try:verify(sessions[index],sessions[index+1],pool['nodes'][index//2])
            except Exception as rollback_error:failures.append(str(rollback_error))
        message=str(error)+('; rollback incomplete: '+'; '.join(failures) if failures else '')
        finish_update(name,'rollback_failed' if failures or recovery else 'failed','بازگردانی GRE نیاز به رسیدگی دارد' if failures or recovery else 'تغییر MTU ناموفق بود؛ تنظیم قبلی بازگردانده شد',message)
        return False,message
    finally:
        for ssh in sessions:ssh.close()


def recover_update(name):
    pool=get_pools().get(name,{})
    job=pool.get('gre_update',{})
    if job.get('status')!='rollback_failed':return False,'No GRE restoration is pending'
    if job.get('kind') == 'slipstream_runtime':
        from core.slipstream_update import recover
        return recover(name)
    if job.get('kind')=='relay_ports':
        from core.kernel_relay_ports import recover_ports
        return recover_ports(name)
    if job.get('kind')=='ports':return change_ports(name,pool['client_ports'],recovery=True)
    return change_mtu(name,pool.get('gre_mtu',1400),recovery=True)


def recover_interrupted():
    def recover(data):
        for pool in data.get('pools',{}).values():
            job=pool.get('gre_update',{})
            if job.get('status')=='running':job.update(status='rollback_failed',message='تنظیم GRE با ری‌استارت پنل قطع شد؛ بازگردانی و آزمون لازم است')
    atomic_update(recover)
