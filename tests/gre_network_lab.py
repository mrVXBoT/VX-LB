"""Real GRE + TCP/UDP test. Run: python3 tests/gre_network_lab.py.
The entry point creates isolated user/network namespaces before any mutation.

Creates two child network namespaces; never changes host routes/firewall.
"""
import json
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENT = str(ROOT / 'core/gre_agent.py')

def run(*args):
    try:return subprocess.check_output(list(args), text=True, stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError as error:raise RuntimeError(error.output) from error


def main():
    if not os.environ.get('LD_BP_LAB_HOST_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['LD_BP_LAB_HOST_NETNS'] or os.geteuid() != 0:
        raise RuntimeError('This lab must run in an isolated user/network namespace')
    children=[];workers=[]
    with tempfile.TemporaryDirectory(prefix='ldbp-gre-lab-') as folder:
        try:
            for _ in range(2): children.append(subprocess.Popen(['unshare','-n','sleep','120']))
            pids=[str(p.pid) for p in children]
            # Wait until each child actually owns a distinct network namespace.
            import time
            for pid in pids:
                for _ in range(100):
                    if os.readlink('/proc/'+pid+'/ns/net')!=os.readlink('/proc/self/ns/net'):break
                    time.sleep(.01)
                else:raise RuntimeError('Child namespace did not start')
            def ns(index,*args):return run('nsenter','-t',pids[index],'-n','--','env','LD_BP_VICI_SOCKET='+folder+'/run-'+str(index)+'/charon.vici',*args)
            run('ip','link','add','lab-a','type','veth','peer','name','lab-b')
            for index,link in enumerate(('lab-a','lab-b')):
                run('ip','link','set',link,'netns',pids[index])
                ns(index,'ip','link','set','lo','up');ns(index,'ip','link','set',link,'up')
                ns(index,'ip','addr','add','192.0.2.'+str(index+1)+'/30','dev',link)
                ns(index,'iptables','-A','INPUT','-i','lo','-j','ACCEPT')
                ns(index,'iptables','-A','INPUT','-m','conntrack','--ctstate','ESTABLISHED,RELATED','-j','ACCEPT')
                ns(index,'iptables','-A','INPUT','-p','tcp','--dport','29999','-m','comment','--comment','unrelated-test-rule','-j','ACCEPT')
                ns(index,'iptables','-P','INPUT','DROP')
            # One daemon per namespace; strongSwan 5.9 requires stock modular
            # /etc/strongswan.conf (a trimmed standalone file is rejected).
            # Use the default /run/charon.vici inside each namespace's own
            # namespace filesystem instead of trying to move the socket.
            bwrap=os.environ.get('LD_BP_LAB_BWRAP','bwrap')
            for index in range(2):
                run_dir = folder+'/run-'+str(index)
                pathlib.Path(run_dir).mkdir()
                log=open(folder+'/charon-'+str(index)+'.log','w+')
                process=subprocess.Popen(['nsenter','-t',pids[index],'-n','--',bwrap,'--die-with-parent','--bind','/','/','--bind',run_dir,'/run','/usr/lib/ipsec/charon','--debug-lib','1','--debug-cfg','1','--debug-ike','1'],stdout=log,stderr=log)
                workers.append(process)
                for _ in range(200):
                    if pathlib.Path(run_dir+'/charon.vici').exists(): break
                    if process.poll() is not None:
                        log.seek(0);raise RuntimeError(log.read())
                    time.sleep(.02)
                else:
                    log.seek(0);raise RuntimeError('Private charon socket did not start: '+log.read())
            configs=[];paths=[];before=[]
            for index in range(2):
                c=dict(owner='ldbp-gre-v1',interface='ldg0123456789',role='iran' if index==0 else 'kharej',
                       local='192.0.2.'+str(index+1),remote='192.0.2.'+str(2-index),
                       private='10.203.0.'+str(index+1),peer='10.203.0.'+str(2-index),key=123456,mtu=1400,ports=[22500],security={'mode':'ipsec','psk':'c'*64,'reqid':123456})
                configs.append(c);paths.append(folder+'/'+str(index)+'.json');pathlib.Path(paths[-1]).write_text(json.dumps(c))
                before.append((ns(index,'ip','route','show','default'),ns(index,'cat','/proc/sys/net/ipv4/ip_forward')))
                ns(index,'python3',AGENT,'preflight',paths[index]);ns(index,'python3',AGENT,'up',paths[index])
                ns(index,'python3',AGENT,'up',paths[index])  # idempotent owned link
            ns(0,'python3',AGENT,'secure-start',paths[0])
            for index in range(2):ns(index,'python3',AGENT,'secure-check',paths[index])
            # Capture only the encrypted underlay, not the decrypted GRE interface.
            capture=folder+'/underlay.pcap'
            cap=subprocess.Popen(['nsenter','-t',pids[0],'-n','--','tcpdump','-Z','root','-U','-i','lab-a','-w',capture,'ip proto 47 or ip proto 50'],stdout=open(folder+'/capture.log','w'),stderr=subprocess.STDOUT);workers.append(cap)
            time.sleep(.2)
            backend='''import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.203.0.2',22500));s.listen()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(('10.203.0.2',22500))
def udp():
 while True:
  data,addr=u.recvfrom(65535);u.sendto(data,addr)
threading.Thread(target=udp,daemon=True).start()
print('READY',flush=True)
while True:
 c,_=s.accept()
 def handle(c):
  with c:
   while True:
    data=c.recv(65536)
    if not data:break
    c.sendall(data)
 threading.Thread(target=handle,args=(c,),daemon=True).start()
'''
            process=subprocess.Popen(['nsenter','-t',pids[1],'-n','--','python3','-u','-c',backend],stdout=subprocess.PIPE,text=True);workers.append(process)
            assert process.stdout.readline().strip()=='READY'
            process=subprocess.Popen(['nsenter','-t',pids[0],'-n','--','python3',AGENT,'relay',paths[0]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);workers.append(process)
            for _ in range(100):
                if '22500' in ns(0,'ss','-ltn'):break
                time.sleep(.02)
            else:raise RuntimeError('Relay did not bind')
            ns(0,'python3',AGENT,'probe',paths[0],'22500','a'*48)
            client='''import socket
payload=b'GRE-RELAY-CHECK-'*8192
with socket.create_connection(('192.0.2.1',22500),timeout=4) as s:
 s.settimeout(4);s.sendall(payload);data=b''
 while len(data)<len(payload):
  chunk=s.recv(len(payload)-len(data))
  if not chunk:break
  data+=chunk
 assert data==payload
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
 s.settimeout(4);s.connect(('192.0.2.1',22500))
 for i in range(16):
  data=str(i).encode()+b'udp-probe'*100;s.send(data);assert s.recv(1200)==data
print('TCP+UDP forwarding passed')
'''
            print(ns(1,'python3','-c',client))
            for index,c in enumerate(configs):
                c['mtu']=1280;pathlib.Path(paths[index]).write_text(json.dumps(c));ns(index,'python3',AGENT,'mtu',paths[index])
            ns(0,'python3',AGENT,'probe',paths[0],'22500','b'*48)
            for index in range(2):
                stats=json.loads(ns(index,'ip','-s','-j','link','show','dev',configs[index]['interface']))[0]
                counters=stats.get('stats64',stats.get('stats',{}))
                assert counters['rx']['bytes']>65536 and counters['tx']['bytes']>65536
                assert before[index]==(ns(index,'ip','route','show','default'),ns(index,'cat','/proc/sys/net/ipv4/ip_forward'))
            ns(0,'python3',AGENT,'secure-rekey',paths[0])
            time.sleep(.3)
            ns(0,'python3',AGENT,'secure-check',paths[0])
            ns(0,'python3',AGENT,'probe',paths[0],'22500','c'*48)
            for index in range(2):ns(index,'python3',AGENT,'secure-stop',paths[index])
            bad=dict(configs[1],security={'mode':'ipsec','psk':'e'*64,'reqid':123456})
            pathlib.Path(paths[1]).write_text(json.dumps(bad))
            for index in range(2):ns(index,'python3',AGENT,'up',paths[index])
            try:ns(0,'python3',AGENT,'secure-start',paths[0])
            except RuntimeError:pass
            else:raise AssertionError('Wrong PSK authenticated successfully')
            for index in range(2):
                try:ns(index,'python3',AGENT,'secure-check',paths[index])
                except RuntimeError:pass
                else:raise AssertionError('Wrong PSK reported healthy')
                ns(index,'python3',AGENT,'secure-stop',paths[index])
            pathlib.Path(paths[1]).write_text(json.dumps(configs[1]))
            for index in range(2):ns(index,'python3',AGENT,'up',paths[index])
            ns(0,'python3',AGENT,'secure-start',paths[0])
            ns(0,'python3',AGENT,'probe',paths[0],'22500','f'*48)
            print('PASS: CHILD_SA rekey, wrong-PSK rejection and authenticated recovery')
            # Unload managed connections before policy loss so the daemon cannot
            # recover encryption during the deliberate outage test.
            for index in range(2):ns(index,'python3',AGENT,'secure-stop',paths[index])
            # Destroy all SAs and policies in the isolated endpoints, while
            # leaving the GRE devices up: firewall must prevent raw fallback.
            for index in range(2):
                ns(index,'ip','xfrm','state','flush');ns(index,'ip','xfrm','policy','flush')
            try:
                ns(0,'python3',AGENT,'probe',paths[0],'22500','d'*48)
            except RuntimeError:pass
            else:raise AssertionError('Plaintext fallback passed after SA/policy loss')
            cap.terminate();cap.wait(timeout=5)
            captured=pathlib.Path(capture).read_bytes()
            assert b'a'*48 not in captured and b'b'*48 not in captured
            raw=run('tcpdump','-Z','root','-n','-r',capture,'ip proto 47')
            esp=run('tcpdump','-Z','root','-n','-r',capture,'ip proto 50')
            # tcpdump status lines are on stderr; inspect actual packet lines.
            assert not any('GREv' in line or 'GRE,' in line for line in raw.splitlines()),raw
            assert 'ESP(' in esp,esp
            print('PASS: ESP capture; no plaintext GRE; SA/policy loss blocks TCP/UDP')
            for process in workers[2:]:
                if process.poll() is None:process.terminate();process.wait(timeout=5)
            for index in range(2):
                ns(index,'python3',AGENT,'down',paths[index]);ns(index,'python3',AGENT,'down',paths[index])
                firewall=ns(index,'iptables','-S','INPUT')
                assert 'unrelated-test-rule' in firewall and 'ldbp-gre-' not in firewall and 'ldbp-sec-' not in firewall
            print('PASS: actual keyed GRE, large TCP + multi-packet UDP, scoped DROP-policy firewall, MTU update, counters, unchanged default route/ip_forward and idempotent cleanup')
        except Exception:
            for file in pathlib.Path(folder).glob('charon-*.log'):
                print(file.name+': '+file.read_text()[-6000:])
            raise
        finally:
            for process in workers+children:
                if process.poll() is None:process.terminate()
            for process in workers+children:
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()

if __name__=='__main__':
    import sys
    if '--inside' in sys.argv:main()
    else:
        env=dict(os.environ,LD_BP_LAB_HOST_NETNS=os.readlink('/proc/self/ns/net'))
        sys.exit(subprocess.call(['unshare','-Urn',sys.executable,__file__,'--inside'],env=env))
