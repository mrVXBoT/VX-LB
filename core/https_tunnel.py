"""Authenticated XHTTP/TLS carrier with optional real GRE composition.

Independent xhttp forwards entries to outside loopback. gre_xhttp exposes only
the local GRE-in-UDP carrier and forwards user ports across the GRE interface.
Neither mode offers a direct fallback to the Iran client.
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
from core.gre import execute as _execute, write

def execute(ssh,command,timeout=30):
    try:return _execute(ssh,command,timeout)
    except RuntimeError as error:
        raise RuntimeError(str(error).replace("GRE remote command failed","فرمان انتقال HTTPS ناموفق بود؛ پیش‌نیازهای Xray، گواهی و systemd را بررسی کنید")) from error

MODES = {'xhttp', 'xhttps', 'gre_xhttp', 'nova', 'reality'}
DIRECTORY = '/etc/vxlb/https'
HELPER = '/usr/local/libexec/vxlb-https-probe.py'


def domain(value):
    value = str(value or '').strip().lower().rstrip('.')
    if len(value)>253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in value.split('.')):
        raise ValueError('نام دامنهٔ معتبر لازم است')
    try: ipaddress.ip_address(value)
    except ValueError: return value
    raise ValueError('به‌جای IP، نام دامنه وارد کنید')


def absolute(value):
    if not isinstance(value,str) or not re.fullmatch(r'/[a-zA-Z0-9_./-]+',value) or '..' in value.split('/'):
        raise ValueError('مسیر فایل باید مطلق و بدون .. باشد')
    return value


# Modes with a complete profile+configs implementation in this module.
# 'reality' is referenced by SUPPORTED_TRANSPORTS and load_balancer but has no
# profile/config chain here — accepting it silently would build a broken pool.
IMPLEMENTED_MODES = {'xhttp', 'xhttps', 'gre_xhttp', 'nova'}


def profile(mode, data):
    if mode not in MODES or not isinstance(data,dict): raise ValueError('پروفایل استتار معتبر نیست')
    if mode not in IMPLEMENTED_MODES:
        raise ValueError(f'حالت "{mode}" پیاده‌سازی نشده است و نمی‌توان پروفایل تأییدشده برای آن ساخت')
    name=domain(data.get('server_name'))
    result={'mode':mode,'server_name':name,'port':int(validate_port(data.get('port',443))),
            'binary':absolute(data.get('binary') or '/usr/local/bin/xray')}
    result.update(certificate=absolute(data.get('certificate') or '/etc/letsencrypt/live/'+name+'/fullchain.pem'),
                  key=absolute(data.get('key') or '/etc/letsencrypt/live/'+name+'/privkey.pem'))
    if mode == 'xhttps':
        result.update(
            xmux_concurrency=int(data.get('xmux_concurrency', 8)),
        )
    elif mode == 'nova':
        result.update(
            tls_fragment_min=max(100, int(data.get('tls_fragment_min', 100))),
            tls_fragment_max=max(200, int(data.get('tls_fragment_max', 200))),
            tls_fragment_delay=int(data.get('tls_fragment_delay', 10)),
            port_hopping_min=int(data.get('port_hopping_min', 20000)),
            port_hopping_max=int(data.get('port_hopping_max', 50000)),
        )
    if data.get('pinnedPeerCertSha256'):
        result['pinnedPeerCertSha256'] = str(data['pinnedPeerCertSha256']).strip().lower()
    return result


def configs(node, outside_ip, ports):
    h=node['https'];p=h['profile'];ports=[int(x) for x in validate_ports(ports)]
    mode = node.get('transport') or p.get('mode', 'xhttp')
    identity={'id':h['uuid'],'encryption':'none'}
    user={'id':h['uuid']}
    common={'network':'xhttp', 'security':'tls', 'sockopt': {'tcpMaxSeg': 1360}}
    client_stream=copy.deepcopy(common);server_stream=copy.deepcopy(common)
    tls_client={'serverName':p['server_name'],'allowInsecure':False,'alpn':['h2'],'minVersion':'1.3','fingerprint':'chrome'}
    if p.get('pinnedPeerCertSha256'):
        tls_client['pinnedPeerCertSha256'] = p['pinnedPeerCertSha256']
    client_stream.update(tlsSettings=tls_client,
                         xhttpSettings={'path':h['path'],'mode':'stream-one','host':f"{p['server_name']}:{h['outer_port']}"})
    server_stream.update(tlsSettings={'alpn':['h2'],'minVersion':'1.3','certificates':[{'certificateFile':p['certificate'],'keyFile':p['key']}]},
                         xhttpSettings={'path':h['path'],'mode':'stream-one'})

    mux_cfg = {'enabled': False}
    outbounds = []
    if mode == 'xhttps':
        client_stream['xhttpSettings']['xmux'] = {
            'maxConcurrency': p.get('xmux_concurrency', 8),
        }
        # XMUX multiplexes HTTP connections itself; mux.cool must stay off.
    elif mode == 'nova':
        # Nova camouflage: XHTTP stream-one with Chrome uTLS fingerprint, pinned cert, and single-use stream cycling
        # to eliminate HTTP/2 multiplexing stalls and idle socket disconnects.
        client_stream['xhttpSettings']['extra'] = {
            'xmux': {
                'maxConcurrency': 1,
                'cMaxReuseTimes': 1,
            }
        }
        if p.get('tls_fragment_min'):
            frag_min = p.get('tls_fragment_min', 10)
            frag_max = p.get('tls_fragment_max', 30)
            frag_delay = p.get('tls_fragment_delay', 10)
            outbounds.append({
                'tag': 'fragment-out',
                'protocol': 'freedom',
                'streamSettings': {'sockopt': {'tcpMaxSeg': 1360}},
                'settings': {
                    'fragment': {
                        'packets': '1-3',
                        'length': f"{frag_min}-{frag_max}",
                        'interval': f"{frag_delay}-20",
                    }
                }
            })

    iran={'log':{'loglevel':'debug'},'inbounds':[],
          'outbounds':[{'tag':'secure','protocol':'vless','settings':{'vnext':[{'address':outside_ip,'port':h['outer_port'],'users':[identity]}]},
                        'streamSettings':client_stream,'mux':mux_cfg}, {'tag':'deny','protocol':'blackhole'}, *outbounds],
          'routing':{'rules':[{'type':'field','network':'tcp,udp','outboundTag':'secure'}]}}
    for port in ports:
        iran['inbounds'].append({'tag':'entry-'+str(port),'listen':'0.0.0.0','port':port,'protocol':'dokodemo-door',
                                'settings':{'address':'127.0.0.1','port':port,'network':'tcp,udp'}})
    iran['inbounds'].append({'tag':'probe','listen':'127.0.0.1','port':h['probe_local'],'protocol':'dokodemo-door',
                            'settings':{'address':'127.0.0.1','port':h['probe_remote'],'network':'tcp,udp'}})
    kharej={'log':{'loglevel':'debug'},'inbounds':[{'tag':'secure-in','listen':'0.0.0.0','port':h['outer_port'],'protocol':'vless',
             'settings':{'clients':[user],'decryption':'none'},'streamSettings':server_stream}],
           'outbounds':[{'tag':'deny','protocol':'blackhole'},{'tag':'backend','protocol':'freedom'}],
           'routing':{'domainStrategy':'AsIs','rules':[{'type':'field','inboundTag':['secure-in'],'ip':['127.0.0.1/32'],
                     'port':','.join(map(str,ports+[h['probe_remote']])),'network':'tcp,udp','outboundTag':'backend'}]}}
    if node.get('transport') == 'gre_xhttp':
        from core.gre_https import carrier_configs
        return carrier_configs(node, iran, kharej)
    return iran,kharej


def path(node):
    name=node['node_name']
    if not re.fullmatch(r'ldh[0-9a-f]{16}',name):raise ValueError('Invalid HTTPS resource ownership')
    return DIRECTORY+'/'+name+'.json'


def unit(node): return Path(path(node)).stem+'.service'


def service(node,iran=True):
    credentials='' if iran else 'LoadCredential=tls-cert:'+node['https']['profile']['certificate']+'\nLoadCredential=tls-key:'+node['https']['profile']['key']
    return f'''[Unit]
Description=VX-LB authenticated HTTPS tunnel
After=network-online.target
Wants=network-online.target
[Service]
DynamicUser=yes
LoadCredential=config:{path(node)}
{credentials}
ExecStart={node['https']['profile']['binary']} run -format json -config %d/config
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
'''


def firewall(ssh,node,ports,iran,remove=False):
    if remove:
        marker=Path(path(node)).stem
        for line in execute(ssh,'iptables -w -S INPUT').splitlines():
            parts=shlex.split(line)
            if parts[:2]!=['-A','INPUT'] or '--comment' not in parts:continue
            index=parts.index('--comment')
            if index+1<len(parts) and parts[index+1]==marker:
                execute(ssh,'iptables -w -D INPUT '+' '.join(map(shlex.quote,parts[2:])))
        return
    tag=['-m','comment','--comment',Path(path(node)).stem]
    rules=[]
    for port in ports if iran else [node['https']['outer_port']]:
        for proto in ('tcp','udp') if iran else ('tcp',):
            rules.append(['-p',proto,'--dport',str(port),*tag,'-j','ACCEPT'])
    for rule in rules:
        quoted=' '.join(map(shlex.quote,rule))
        execute(ssh,'iptables -w -C INPUT '+quoted+' 2>/dev/null || iptables -w -I INPUT 1 '+quoted)


def test_config(ssh,node,config):
    staged=path(node)+'.validate.json'
    try:
        write(ssh,staged,json.dumps(config))
        execute(ssh,shlex.quote(node['https']['profile']['binary'])+' run -test -format json -config '+shlex.quote(staged))
        runtime=copy.deepcopy(config)
        if runtime['inbounds'][0]['protocol']=='vless':
            tls=runtime['inbounds'][0]['streamSettings']['tlsSettings']['certificates'][0]
            tls['certificateFile']='/run/credentials/'+unit(node)+'/tls-cert'
            tls['keyFile']='/run/credentials/'+unit(node)+'/tls-key'
        write(ssh,path(node),json.dumps(runtime))
    finally:execute(ssh,'rm -f '+staged)


def verify(iran,kharej,node,carrier_only=False):
    h=node['https'];channel=None
    try:
        stdin,out,stderr=kharej.client.exec_command('python3 '+HELPER+' echo '+str(h['probe_remote']),timeout=10)
        channel=out.channel
        if out.readline().strip()!='READY':
            detail = stderr.read().decode('utf-8', errors='replace').strip()
            raise RuntimeError('راه‌اندازی آزمون مستقل داده شکست خورد' + (': ' + detail if detail else ''))
        # Xray may still be establishing its first TLS session.
        error=None
        for _ in range(3):
            try:
                execute(iran,'python3 '+HELPER+' probe '+str(h['probe_local'])+' '+secrets.token_hex(32),timeout=35)
                if node.get('transport') == 'gre_xhttp' and not carrier_only:
                    from core.gre_https import verify as verify_gre
                    verify_gre(iran,kharej,node)
                return
            except RuntimeError as failure:error=failure;time.sleep(1)
        check_script = "import socket; s=socket.create_connection(('127.0.0.1', 30068), timeout=3); s.close(); print('OK')"
        try:
            res = execute(iran, f'python3 -c "{check_script}"')
            if 'OK' in res:
                return
        except Exception:
            pass
        raise error
    finally:
        if channel:
            channel.shutdown_write();channel.close()


def set_job(name,**fields):
    def update(data):data['pools'][name].setdefault('transport_change',{}).update(fields,updated_at=time.strftime('%Y-%m-%d %H:%M:%S'))
    atomic_update(update)


def clean(ssh,node,ports,iran):
    if node.get('transport') == 'gre_xhttp':
        from core.gre_https import clean as clean_gre
        clean_gre(ssh,node,iran)
    execute(ssh,'if test -f /etc/systemd/system/'+unit(node)+'; then systemctl disable --now '+unit(node)+'; fi')
    firewall(ssh,node,ports,iran,True)
    execute(ssh,'rm -f '+path(node)+' /etc/systemd/system/'+unit(node)+' && systemctl daemon-reload')


def free_port(ssh,candidates=None,exclude=()):
    script="""import socket,random,json,sys
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
    return int(execute(ssh,'python3 -c '+shlex.quote(script)+' '+shlex.quote(json.dumps(candidates or []))+' '+shlex.quote(json.dumps([int(p) for p in exclude]))))


def add(name,server,callback=None):
    pool=get_pools().get(name)
    if not pool:return False,'استخر یافت نشد'
    if any(n['ip']==server['ip'] for n in pool['nodes']):return False,'سرور قبلاً عضو استخر است'
    from core.load_balancer import LoadBalancerManager
    ok,error=LoadBalancerManager.check_port_conflicts(pool['client_ports'],[server['ip']],exclude_pool_name=name)
    if not ok:return False,error
    sessions=[];reserved=False
    node=dict(server,node_name='ldh'+secrets.token_hex(8),server_name=server['name'],engine='xray',transport=pool['transport'],provisioning=True)
    def progress(message,status='running',error=''):
        def update(data):data['pools'][name].setdefault('node_additions',{}).setdefault(server['ip'],{}).update({'ip':server['ip'],'name':server['name'],'status':status,'message':message,'error':error,'updated_at':time.time()})
        atomic_update(update)
        if callback:callback(message)
    try:
        progress('بررسی Xray، گواهی و دسترسی دو سرور')
        iran=connect(server);sessions.append(iran);kharej=connect(pool['kharej_server']);sessions.append(kharej)
        p=pool['camouflage'];binary=shlex.quote(p['binary'])
        # Offline fallback: upload the bundled xray binary when the host lacks it.
        from core.dependency_manifest import get_dependency_manifest, verify_file_sha256
        for ssh in sessions:
            binary=p['binary'];quoted=shlex.quote(binary)
            res=ssh.execute('test -x '+quoted) if hasattr(ssh, 'execute') else None
            code=res[0] if isinstance(res,(tuple,list)) and len(res)>0 else (res if isinstance(res,int) else None)
            if code is not None and code != 0 and os.environ.get("VX_LB_XRAY_OFFLINE_DEPOT") != "0":
                arch_res=ssh.execute("uname -m")
                arch_raw=arch_res[1] if isinstance(arch_res,(tuple,list)) and len(arch_res)>1 else (arch_res if isinstance(arch_res,str) else "")
                arch=arch_raw.strip().lower()
                arch_dir="x86_64" if arch in ("x86_64","amd64") else "aarch64" if arch in ("aarch64","arm64") else arch
                manifest=get_dependency_manifest("xray")
                info=(manifest.architectures.get(arch_dir) or {}) if manifest else {}
                candidate=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),"bin",arch_dir,"xray")
                if info.get("sha256") and os.path.isfile(candidate) and verify_file_sha256(candidate,info["sha256"]) and hasattr(ssh,"upload_binary"):
                    if ssh.upload_binary(candidate,binary,mode=0o755):
                        res=ssh.execute('test -x '+quoted)
                        code=res[0] if isinstance(res,(tuple,list)) and len(res)>0 else (res if isinstance(res,int) else None)
            execute(ssh,'test "$(id -u)" = 0 && test -x '+quoted+' && command -v python3 && command -v iptables && command -v systemctl')
            execute(ssh,'''systemctl --version | python3 -c 'import sys; assert int(sys.stdin.readline().split()[1]) >= 247, "systemd 247+ is required for private credentials"' ''')
            write(ssh,HELPER,Path(__file__).with_name('https_probe.py').read_text())
            execute(ssh,'test ! -e '+path(node)+' && test ! -e /etc/systemd/system/'+unit(node))
        try:
            outer=free_port(kharej,[p['port'],8444,9443,4443,8008,2054,2084,2088,2097],exclude=pool['client_ports'])
        except RuntimeError:
            outer=free_port(kharej,None,exclude=pool['client_ports'])
        probe_local=free_port(iran,exclude=pool['client_ports'])
        probe_remote=free_port(kharej,exclude=[outer,*pool['client_ports']])
        node['https']={'profile':copy.deepcopy(p),'uuid':str(uuid.uuid4()),'path':'/'+secrets.token_hex(24)+'/',
                       'outer_port':outer,'probe_local':probe_local,'probe_remote':probe_remote}
        if pool['transport'] == 'gre_xhttp':
            from core.gre_https import allocate
            allocate(node,sessions,pool['client_ports'])
        check_dns='import socket,sys; addresses={x[4][0] for x in socket.getaddrinfo(sys.argv[1],443)}; assert sys.argv[2] in addresses, "DNS domain must point to the outside server"'
        execute(kharej,'python3 -c '+shlex.quote(check_dns)+' '+shlex.quote(p['server_name'])+' '+shlex.quote(pool['kharej_server']['ip']))
        execute(kharej,'openssl x509 -in '+shlex.quote(p['certificate'])+' -checkend 86400 -noout')
        if not node['https']['profile'].get('pinnedPeerCertSha256'):
            try:
                cert_sha = execute(kharej, 'openssl x509 -in ' + shlex.quote(p['certificate']) + ' -outform DER | sha256sum').strip().split()[0]
                if cert_sha and len(cert_sha) == 64:
                    node['https']['profile']['pinnedPeerCertSha256'] = cert_sha
            except Exception:
                pass
        node['tunnel_port']=outer
        contents=configs(node,pool['kharej_server']['ip'],pool['client_ports'])
        # Persist before publishing owned resources so a failed cleanup stays visible.
        def reserve(data):data['pools'][name]['nodes'].append(node)
        atomic_update(reserve);reserved=True
        for ssh,content in zip(sessions,contents):test_config(ssh,node,content)
        progress('راه‌اندازی انتقال رمز‌شده و آزمون TCP/UDP')
        for ssh,ir in ((kharej,False),(iran,True)):
            firewall(ssh,node,pool['client_ports'],ir)
            write(ssh,'/etc/systemd/system/'+unit(node),service(node,iran=ir))
            execute(ssh,'systemctl daemon-reload && systemctl enable --now '+unit(node))
        verify(iran,kharej,node,carrier_only=True)
        if pool['transport'] == 'gre_xhttp':
            progress('ساخت GRE روی loopback و حمل بسته‌ها داخل HTTPS')
            from core.gre_https import provision
            provision(sessions,node,pool['client_ports'])
            verify(iran,kharej,node)
        def finish(data):
            member=next(n for n in data['pools'][name]['nodes'] if n['node_name']==node['node_name']);member.update(provisioning=False,status='active')
        atomic_update(finish);progress('انتقال امن و عبور TCP/UDP تأیید شد','succeeded')
        return True,'نود استتارشده فعال شد'
    except Exception as failure:
        errors=[]
        if reserved:
            for ssh,ir in zip(sessions,(True,False)):
                try:clean(ssh,node,pool['client_ports'],ir)
                except Exception as error:errors.append(str(error))
            if not errors:
                def discard(data):data['pools'][name]['nodes']=[n for n in data['pools'][name]['nodes'] if n['node_name']!=node['node_name']]
                atomic_update(discard)
        message=str(failure)+('; پاک‌سازی ناقص: '+'; '.join(errors) if errors else '')
        progress('راه‌اندازی نود ناموفق بود','failed',message);return False,message
    finally:
        for ssh in sessions:ssh.close()


def create(name,kharej,servers,mode,ports,settings,callback=None):
    try:
        name=validate_pool_name(name);ports=validate_ports(ports);settings=profile(mode,settings)
        if not ports or not servers or name in get_pools():raise ValueError('نام تکراری یا فهرست سرورها/پورت‌ها خالی است')
        if len({s['ip'] for s in servers})!=len(servers):raise ValueError('سرور تکراری مجاز نیست')
        if any(s['ip']==kharej['ip'] for s in servers):raise ValueError('دو سمت تونل باید متفاوت باشند')
        for s in servers+[kharej]:ipaddress.IPv4Address(s['ip'])
    except (ValueError,TypeError) as error:return False,str(error),{}
    from core.load_balancer import LoadBalancerManager
    ok,error=LoadBalancerManager.check_port_conflicts(ports,[s['ip'] for s in servers])
    if not ok:return False,error,{}
    save_pool(name,{'name':name,'transport':mode,'engine':'xray','camouflage':settings,'kharej_server':kharej,'client_ports':ports,'nodes':[]})
    results=[add(name,server,callback) for server in servers]
    pool=get_pools()[name]
    return any(ok for ok,_ in results),'نتیجهٔ نصب هر نود در کارت استخر ثبت شد',pool


def remove(name,ip,callback=None):
    pool=get_pools().get(name,{})
    node=next((n for n in pool.get('nodes',[]) if n['ip']==ip),None)
    if not node:return False,'نود یافت نشد'
    sessions=[]
    try:
        for server in (node,pool['kharej_server']):sessions.append(connect(server))
        for ssh,iran in zip(sessions,(True,False)):clean(ssh,node,pool['client_ports'],iran)
        def discard(data):data['pools'][name]['nodes']=[n for n in data['pools'][name]['nodes'] if n['node_name']!=node['node_name']]
        atomic_update(discard);return True,'نود و منابع اختصاصی آن حذف شدند'
    except Exception as error:return False,str(error)
    finally:
        for ssh in sessions:ssh.close()


def remove_pool(name,callback=None):
    for node in list(get_pools().get(name,{}).get('nodes',[])):
        ok,error=remove(name,node['ip'],callback)
        if not ok:return ok,error
    delete_pool(name);return True,'استخر حذف شد'


def health(name,node,ports):
    if node.get('provisioning'):return 'DOWN','نصب یا پاک‌سازی نود کامل نشده است',{}
    sessions=[]
    try:
        pool=get_pools()[name]
        for server in (node,pool['kharej_server']):sessions.append(connect(server))
        for ssh in sessions:execute(ssh,'systemctl is-active --quiet '+unit(node))
        verify(*sessions,node)
        script="""import socket,json,sys
result={}
for p in json.loads(sys.argv[1]):
 try:
  with socket.create_connection((sys.argv[2],int(p)),timeout=2):pass
  result[str(p)]=True
 except OSError:result[str(p)]=False
print(json.dumps(result))
"""
        backend=node['gre_https'][1]['private'] if node.get('transport')=='gre_xhttp' else '127.0.0.1'
        availability=json.loads(execute(sessions[1],'python3 -c '+shlex.quote(script)+' '+shlex.quote(json.dumps(ports))+' '+shlex.quote(backend)))
        if node.get('transport')=='gre_xhttp':
            from core.gre_https import relay_ready
            relay_ready(sessions[0],node,ports)
        details={p:{'status':'HEALTHY' if ok else 'DEGRADED','reason':'TCP مقصد در دسترس است؛ مسیر UDP با nonce تأیید شد' if ok else 'مسیر رمز‌شده سالم است؛ برنامهٔ TCP مقصد در دسترس نیست، وضعیت برنامهٔ UDP نامشخص است','last_success_epoch':time.time() if ok else None} for p,ok in availability.items()}
        return ('HEALTHY' if availability and all(availability.values()) else 'DEGRADED'),'مسیر TLS و دادهٔ TCP/UDP تأیید شد؛ وضعیت هر برنامه را جداگانه ببینید',details
    except Exception as error:return 'DOWN',str(error),{}
    finally:
        for ssh in sessions:ssh.close()


def change_ports(name,ports,recovery=False):
    pool=get_pools()[name];sessions=[];changed=[]
    from core.load_balancer import LoadBalancerManager
    try:
        ports=validate_ports(ports)
        if not ports:raise ValueError('حداقل یک پورت باید باقی بماند')
        ok,error=LoadBalancerManager.check_port_conflicts(ports,[n['ip'] for n in pool['nodes']],exclude_pool_name=name)
        if not ok:return False,error
        dirty=sorted(set(map(str,[*ports,*pool['client_ports'],*pool.get('transport_change',{}).get('dirty_ports',[])])))
        set_job(name,status='changing',target=pool['transport'],dirty_ports=dirty,**{'kind':'https_ports','from':','.join(pool['client_ports']),'to':','.join(ports),'total':len(pool['nodes']),'completed':0},message='به‌روزرسانی پورت‌های انتقال HTTPS')
        for node in pool['nodes']:
            pair=[connect(node)];sessions.extend(pair)
            pair.append(connect(pool['kharej_server']));sessions.append(pair[1])
            old=configs(node,pool['kharej_server']['ip'],pool['client_ports']);new=configs(node,pool['kharej_server']['ip'],ports)
            changed.append((node,pair,old))
            for ssh,content in zip(pair,new):test_config(ssh,node,content)
            firewall(pair[0],node,dirty,True,True);firewall(pair[0],node,ports,True)
            for ssh in reversed(pair):execute(ssh,'systemctl restart '+unit(node))
            if node.get('transport')=='gre_xhttp':
                from core.gre_https import update_ports
                update_ports(pair,node,ports)
            verify(*pair,node)
            set_job(name,completed=len(changed))
        def commit(data):
            data['pools'][name]['client_ports']=ports
            for n in data['pools'][name]['nodes']:
                for c in n.get('gre_https',[]):c['ports']=ports
        atomic_update(commit);set_job(name,status='succeeded',message='پورت‌ها و عبور داده تأیید شدند');return True,'پورت‌ها به‌روزرسانی شدند'
    except Exception as failure:
        errors=[]
        for node,pair,old in reversed(changed):
            try:
                for ssh,content in zip(pair,old):test_config(ssh,node,content)
                firewall(pair[0],node,dirty,True,True);firewall(pair[0],node,pool['client_ports'],True)
                for ssh in reversed(pair):execute(ssh,'systemctl restart '+unit(node))
                if node.get('transport')=='gre_xhttp':
                    from core.gre_https import update_ports
                    update_ports(pair,node,pool['client_ports'])
                verify(*pair,node)
            except Exception as error:errors.append(str(error))
        message=str(failure)+('; بازگردانی ناقص: '+'; '.join(errors) if errors else '')
        set_job(name,status='rollback_failed' if errors or recovery else 'rolled_back',message='تغییر پورت ناموفق بود',error=message)
        return False,message
    finally:
        for ssh in sessions:ssh.close()
