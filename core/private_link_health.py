"""Active private-link checks; never infer UDP application health from a listener."""
import ipaddress
import json
import re
import secrets
import shlex
import time
from core.storage import get_pools
from core.transport_change import connect
from core.kernel_relay_ports import node_credentials, relay_spec
from core.validation import validate_ports

ECHO = r'''
import socket,sys,select,time
host=sys.argv[1];af=socket.AF_INET6 if ':' in host else socket.AF_INET
server=socket.socket(af,socket.SOCK_STREAM);server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind((host,int(sys.argv[2]) if len(sys.argv)>2 else 0));server.listen(4)
port=server.getsockname()[1]
udp=socket.socket(af,socket.SOCK_DGRAM);udp.bind((host,port))
print(port,flush=True)
clients=[];deadline=time.monotonic()+120
try:
 while time.monotonic()<deadline:
  watch=[server,udp,*clients]
  if not sys.stdin.closed:watch.append(sys.stdin)
  ready,_,_=select.select(watch,[],[],0.2)
  for item in ready:
   if item is sys.stdin:
    if not sys.stdin.read(1):deadline=0;break
   elif item is server:
    client,_=server.accept();client.settimeout(2);clients.append(client)
   elif item is udp:
    data,addr=udp.recvfrom(1500);udp.sendto(data,addr)
   else:
    try:
     data=item.recv(65536)
    except socket.timeout:
     continue
    if data:item.sendall(data)
    else:clients.remove(item);item.close()
finally:
 for item in [server,udp,*clients]:item.close()
'''
PROBE = r'''
import socket,sys,json,time,secrets
host=sys.argv[1];port=int(sys.argv[2]);nonce=sys.argv[3].encode();iface=sys.argv[4]
af=socket.AF_INET6 if ':' in host else socket.AF_INET
start=time.monotonic()
deadline=time.monotonic()+30
for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
 while True:
  try:
   with socket.socket(af,kind) as sock:
    # A fresh kernel tunnel endpoint must first learn the peer MAC through
    # ARP/flooding across the tunnel; until resolution completes `connect`
    # can report EHOSTUNREACH/ENETUNREACH even when the tunnel is healthy.
    sock.settimeout(8)
    if iface:sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,iface.encode()+b'\0')
    sock.connect((host,port))
    for i in range(4):
     # UDP is not segmented. 64 bytes plus the nonce stays under a 576-byte tunnel MTU.
     size=65536 if kind==socket.SOCK_STREAM and i==0 else 64
     data=nonce+str(i).encode()+secrets.token_bytes(size)
     sock.sendall(data)
     result=b''
     while len(result)<len(data):
      part=sock.recv(65536)
      if not part:raise RuntimeError('Echo closed before completion')
      result+=part
      if kind==socket.SOCK_DGRAM:break
     if result!=data:raise RuntimeError('Echo challenge mismatch')
   break
  except OSError as error:
   # TimeoutError has no errno. A fresh tunnel can accept TCP and still drop
   # the first echo; retry until the deadline instead of aborting at 8s.
   if (isinstance(error, TimeoutError) or error.errno in (110,113,101,111)) and time.monotonic()<deadline:
    time.sleep(0.4)
    continue
   raise
print(json.dumps({'passed':True,'latency_ms':(time.monotonic()-start)*1000,'protocols':['tcp','udp']}))
'''


def probe_direction(source, target, target_ip, source_iface):
    target_ip=str(ipaddress.ip_address(target_ip.split('/')[0]))
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}',source_iface):
        raise ValueError('Invalid probe interface')
    channel=None
    try:
        stdin,stdout,stderr=target.client.exec_command('python3 -u -c '+shlex.quote(ECHO)+' '+shlex.quote(target_ip),timeout=10)
        channel=stdout.channel;channel.settimeout(10)
        port=stdout.readline().strip()
        if not port.isdigit() or not 1<=int(port)<=65535:
            raise RuntimeError('Private echo endpoint did not become ready')
        command='python3 -c '+shlex.quote(PROBE)+' '+shlex.quote(target_ip)+' '+port+' '+secrets.token_hex(24)+' '+shlex.quote(source_iface)
        code,out,error=source.execute(command,timeout=30)
        if code:
            raise RuntimeError('TCP/UDP challenge did not cross the private interface: '+(error.strip() or out.strip() or 'no probe result'))
        result=json.loads(out)
        if result.get('passed') is not True or result.get('protocols')!=['tcp','udp']:
            raise RuntimeError('Invalid probe result')
        return result
    finally:
        if channel:
            channel.close()


def probe_pair(iran, kharej, local_ip, remote_ip, iface):
    forward=probe_direction(iran,kharej,remote_ip,iface)
    reverse=probe_direction(kharej,iran,local_ip,iface)
    return {'passed':True,'protocols':['tcp','udp'],'directions':['iran_to_kharej','kharej_to_iran'],'latency_ms':max(forward['latency_ms'],reverse['latency_ms'])}


# A single read reports socket ownership and TCP reachability at the actual destination.
DESTINATION = r'''
import socket,subprocess,sys,json
host=sys.argv[1];service=sys.argv[2];ports=json.loads(sys.argv[3])
pid=subprocess.check_output(['systemctl','show','--property=MainPID','--value',service],text=True).strip()
rows=subprocess.check_output(['ss','-H','-lntup'],text=True).splitlines();result={}
def port_of(addr):
 text=str(addr).rsplit(':',1)[-1]
 return text if text.isdigit() else ''
for port in ports:
 owned=pid.isdecimal() and int(pid)>0 and all(any(len(parts)>=5 and parts[0]==proto and port_of(parts[4])==str(port) and ('pid='+pid+',') in r for r in rows for parts in [r.split()]) for proto in ('tcp','udp'))
 reachable=False
 try:
  with socket.create_connection((host,int(port)),timeout=2):reachable=True
 except OSError:pass
 udp='silent'
 family=socket.AF_INET6 if ':' in host else socket.AF_INET
 sock=socket.socket(family, socket.SOCK_DGRAM)
 sock.settimeout(1)
 try:
  sock.connect((host,int(port)));sock.send(b'vxlb')
  try:
   sock.recv(64);udp='reply'
  except socket.timeout:udp='silent'
 except ConnectionRefusedError:udp='closed'
 except OSError:udp='error'
 finally:sock.close()
 result[str(port)]={'relay_owned':owned,'destination_tcp':reachable,'destination_udp':udp}
print(json.dumps(result))
'''


def health(pool_name,node,ports):
    engine=node.get('engine') or node.get('transport')
    if node.get('provisioning'):
        return 'DOWN','راه‌اندازی لینک کامل نشده است',{}
    sessions=[]
    try:
        ports=validate_ports(ports)
        pool=get_pools()[pool_name];meta=node[engine]
        iface=meta.get('interface') or meta.get('iface')
        local=str(ipaddress.ip_address(meta['local_private'].split('/')[0]))
        remote=str(ipaddress.ip_address(meta['remote_private'].split('/')[0]))
        ir=connect(node_credentials(node));sessions.append(ir)
        kh=connect(pool['kharej_server']);sessions.append(kh)
        path_result=probe_pair(ir,kh,local,remote,iface)
        _,service,_=relay_spec(engine,node,ports)
        command='python3 -c '+shlex.quote(DESTINATION)+' '+shlex.quote(remote)+' '+shlex.quote(service)+' '+shlex.quote(json.dumps(ports))
        code,out,_=ir.execute(command,timeout=max(15,len(ports)*3))
        if code:raise RuntimeError('Cannot inspect relay and destination service')
        results=json.loads(out);details={}
        for port in ports:
            result=results.get(str(port),{})
            good=result.get('relay_owned') is True and result.get('destination_tcp') is True
            udp_application={'reply':'VERIFIED','closed':'CLOSED','silent':'SILENT','error':'ERROR'}.get(result.get('destination_udp'), 'UNVERIFIED')
            if not good:
                reason='مسیر خصوصی تأیید شد؛ رله یا سرویس TCP مقصد آماده نیست'
            elif udp_application=='VERIFIED':
                reason='مسیر خصوصی و پاسخ TCP و UDP مقصد تأیید شد'
            elif udp_application=='CLOSED':
                reason='مسیر خصوصی و TCP مقصد تأیید شد؛ پورت UDP مقصد بسته است'
            elif udp_application=='SILENT':
                reason='مسیر خصوصی و TCP مقصد تأیید شد؛ UDP مقصد پاسخی نداد'
            else:
                reason='مسیر خصوصی TCP/UDP و دسترسی TCP مقصد تأیید شدند؛ سلامت برنامهٔ UDP بررسی نشده'
            details[str(port)]={'status':'HEALTHY' if good else 'DOWN','reason':reason,'path_verified':True,'relay_verified':result.get('relay_owned',False),'destination_tcp':result.get('destination_tcp',False),'udp_application':udp_application,'latency_ms':path_result['latency_ms'],'last_success_epoch':time.time() if good else None}
        count=sum(v['status']=='HEALTHY' for v in details.values())
        return ('HEALTHY' if count==len(ports) else 'DEGRADED' if count else 'DOWN'),f'{count}/{len(ports)} TCP destinations ready; private TCP/UDP path verified',details
    except Exception:
        return 'DOWN','عبور دوطرفهٔ TCP/UDP یا دسترسی سرویس مقصد تأیید نشد',{}
    finally:
        for ssh in sessions:ssh.close()
