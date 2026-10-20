"""Opt-in real-kernel lab. run(authorized_paramiko_client, verified_xray).

Two temporary network namespaces, no production pool/service/route changes.
Requires preinstalled ip_gre/fou modules and tcpdump on the lab host.
"""
import json
import secrets
import shlex
import subprocess
import tempfile
import uuid
from pathlib import Path
from core import https_tunnel as h


def run(client, binary):
    folder='/var/tmp/ldbp-gre-https-lab-'+secrets.token_hex(8)
    owner='ldh'+secrets.token_hex(8)
    configs=[]
    for i in range(2):
        configs.append(dict(owner=owner, interface='ldc'+owner[3:13], role='iran' if i==0 else 'kharej',
                            private='10.204.0.'+str(i+1), peer='10.204.0.'+str(2-i), key=123456,
                            mtu=1280, receive_port=30001, carrier_port=30002, ports=['22500']))
    node={'node_name':owner,'transport':'gre_xhttp','gre_https':configs,'https':{
        'profile':h.profile('gre_xhttp', {'server_name':'tunnel.test','binary':folder+'/xray',
                                       'certificate':folder+'/cert.pem','key':folder+'/key.pem'}),
        'uuid':str(uuid.uuid4()),'path':'/'+secrets.token_hex(24),'outer_port':24443,'probe_local':22252,'probe_remote':22251}}
    iran,outside=h.configs(node,'192.0.2.2',['22500'])
    script=r'''
import subprocess as s,os,time,json,pathlib,sys
FOLDER=__FOLDER__
workers=[];pids=[]
def run(*args,check=True):
 p=s.run(args,text=True,capture_output=True,timeout=20)
 if check and p.returncode:raise RuntimeError(str(args)+p.stdout+p.stderr)
 return p
def ns(i,*args,check=True):return run('nsenter','-t',pids[i],'-n','--',*args,check=check)
def launch(i,args,env=None):
 log=open(FOLDER+'/process-'+str(len(workers))+'.log','w')
 p=s.Popen(['nsenter','-t',pids[i],'-n','--',*args],stdout=log,stderr=log,env=env);workers.append(p);return p
try:
 for i in range(2):workers.append(s.Popen(['unshare','-n','sleep','100']))
 time.sleep(.2);pids=[str(p.pid) for p in workers]
 assert all(os.readlink('/proc/'+p+'/ns/net')!=os.readlink('/proc/self/ns/net') for p in pids)
 run('ip','link','add','gh-a','type','veth','peer','name','gh-b')
 before=[]
 for i,iface in enumerate(['gh-a','gh-b']):
  run('ip','link','set',iface,'netns',pids[i]);ns(i,'ip','link','set','lo','up');ns(i,'ip','link','set',iface,'up')
  ns(i,'ip','addr','add',f'192.0.2.{i+1}/30','dev',iface)
  before.append(ns(i,'ip','route','show','default').stdout)
 capture=launch(0,['tcpdump','-Z','root','-U','-i','gh-a','-w',FOLDER+'/wire.pcap'])
 time.sleep(.2)
 env=dict(os.environ,SSL_CERT_FILE=FOLDER+'/cert.pem')
 outside=launch(1,[FOLDER+'/xray','run','-config',FOLDER+'/outside.json'],env)
 inside=launch(0,[FOLDER+'/xray','run','-config',FOLDER+'/iran.json'],env)
 time.sleep(.5)
 for i in (1,0):launch(i,['python3',FOLDER+'/gre_https_agent.py','serve',FOLDER+'/'+str(i)+'.json'])
 time.sleep(1)
 for i in (0,1):
  p=ns(i,'ping','-c','2','-W','3','-I',__IFACE__,'10.204.0.'+str(2-i));print(p.stdout)
 # Real TCP/UDP across GRE, not merely the independent TLS probe.
 for source,target in [(0,1),(1,0)]:
  echo=s.Popen(['nsenter','-t',pids[target],'-n','--','python3',FOLDER+'/gre_https_agent.py','echo',FOLDER+'/'+str(target)+'.json'],stdout=s.PIPE,text=True);workers.append(echo)
  port=echo.stdout.readline().strip();assert port.isdigit()
  ns(source,'python3',FOLDER+'/gre_https_agent.py','probe',FOLDER+'/'+str(source)+'.json',port,'GRE-HTTPS-SECRET-NONCE'.ljust(64,'x'))
  echo.terminate();echo.wait(timeout=3)
  counters=json.loads(ns(source,'ip','-s','-j','link','show','dev',__IFACE__).stdout)[0]
  assert counters['stats64']['rx']['bytes']>65536 and counters['stats64']['tx']['bytes']>65536
 # Test actual public entry forwarding through GRE to the outside backend.
 backend=r"""import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.204.0.2',22500));s.listen()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('10.204.0.2',22500))
def udp():
 while True:
  data,addr=u.recvfrom(65535);u.sendto(data,addr)
threading.Thread(target=udp,daemon=True).start()
while True:
 c,_=s.accept()
 def tcp(c):
  with c:
   while True:
    data=c.recv(65536)
    if not data:break
    c.sendall(data)
 threading.Thread(target=tcp,args=(c,),daemon=True).start()
"""
 launch(1,['python3','-c',backend])
 launch(0,['python3',FOLDER+'/gre_https_agent.py','relay',FOLDER+'/0.json'])
 time.sleep(.3)
 ns(0,'python3',FOLDER+'/https_probe.py','probe','22500','PUBLIC-ENTRY-THROUGH-GRE')
 # Keep the destination up; a dead HTTPS carrier must fail, not go direct.
 echo=s.Popen(['nsenter','-t',pids[1],'-n','--','python3',FOLDER+'/gre_https_agent.py','echo',FOLDER+'/1.json'],stdout=s.PIPE,text=True);workers.append(echo)
 port=echo.stdout.readline().strip();assert port.isdigit()
 inside.terminate();inside.wait(timeout=3)
 assert ns(0,'python3',FOLDER+'/gre_https_agent.py','probe',FOLDER+'/0.json',port,'NO-RAW-FALLBACK',check=False).returncode!=0
 assert ns(0,'python3',FOLDER+'/https_probe.py','probe','22500','NO-DIRECT-ENTRY',check=False).returncode!=0
 # Reconnect without rebuilding GRE. The next keepalive repairs the UDP path.
 inside=launch(0,[FOLDER+'/xray','run','-config',FOLDER+'/iran.json'],env)
 time.sleep(11)
 ns(0,'python3',FOLDER+'/https_probe.py','probe','22500','RECOVERED-AFTER-CARRIER-RESTART')
 capture.terminate();capture.wait(timeout=3)
 raw=pathlib.Path(FOLDER+'/wire.pcap').read_bytes()
 assert b'GRE-HTTPS-SECRET-NONCE' not in raw
 visible=run('tcpdump','-n','-r',FOLDER+'/wire.pcap','ip proto 47 or ip proto 50 or udp').stdout
 assert not visible.strip(),visible
 assert b'tunnel.test' in raw,'TLS SNI not present on underlay'
 for i in (0,1):assert ns(i,'ip','route','show','default').stdout==before[i]
 print('PASS: real GRE + TLS/XHTTP; bidirectional 65K TCP and UDP; public entry relay; no public GRE/ESP/UDP or plaintext nonce; carrier loss fails closed and reconnects; routes unchanged')
finally:
 for p in reversed(workers[2:]):
  if p.poll() is None:p.terminate()
 for p in workers[2:]:
  try:p.wait(timeout=3)
  except s.TimeoutExpired:p.kill();p.wait()
 for i in range(len(pids)):ns(i,'python3',FOLDER+'/gre_https_agent.py','down',FOLDER+'/'+str(i)+'.json',check=False)
 for p in workers[:2]:
  if p.poll() is None:p.terminate()
 for p in workers[:2]:p.wait(timeout=3)
'''.replace('__FOLDER__',repr(folder)).replace('__IFACE__',repr(configs[0]['interface']))
    def remote(command,timeout=30):
        _,out,err=client.exec_command(command,timeout=timeout)
        stdout=out.read().decode();stderr=err.read().decode();code=out.channel.recv_exit_status()
        if code:raise RuntimeError(stdout+stderr)
        return stdout
    try:
        remote('mkdir -m 700 '+folder)
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp)
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=tunnel.test','-addext','subjectAltName=DNS:tunnel.test','-keyout',str(tmp/'key.pem'),'-out',str(tmp/'cert.pem')],capture_output=True,check=True)
            with client.open_sftp() as ftp:
                for src,name,mode in [(binary,'xray',0o700),(tmp/'cert.pem','cert.pem',0o600),(tmp/'key.pem','key.pem',0o600),
                                      (Path(__file__).resolve().parents[1]/'core/gre_https_agent.py','gre_https_agent.py',0o600),
                                      (Path(__file__).resolve().parents[1]/'core/https_probe.py','https_probe.py',0o600),
                                      (Path(__file__).resolve().parents[1]/'core/gre_agent.py','gre_agent.py',0o600)]:
                    ftp.put(str(src),folder+'/'+name);ftp.chmod(folder+'/'+name,mode)
                for name,value in [('iran.json',iran),('outside.json',outside),('0.json',configs[0]),('1.json',configs[1])]:
                    with ftp.file(folder+'/'+name,'w') as f:f.write(json.dumps(value))
        print(remote('python3 -c '+shlex.quote(script),timeout=90))
    except Exception:
        print(remote('cat '+folder+'/process-*.log'))
        raise
    finally:remote('rm -rf '+folder)
