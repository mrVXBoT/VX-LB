"""A loopback-only TCP/UDP challenge forwarded through the real Paqet process."""
import json
import secrets
import shlex
import time
from core.validation import validate_ports,validate_port
from core.private_link_health import ECHO

# The shared 64KiB probe burst is fragile through a raw KCP tunnel (it can
# stall on segmentation/MTU and surface as a bare TimeoutError). Paqet uses a
# dedicated probe with bounded payloads, retries for tunnel/ARP/client-listener
# warm-up (including socket.timeout and an early EOF while the forward path is
# still settling), and explicit echo verification.
PAQET_PROBE = r'''
import socket,sys,json,time,secrets
host=sys.argv[1];port=int(sys.argv[2]);nonce=sys.argv[3].encode()
start=time.monotonic();deadline=time.monotonic()+60
class RetryWarmup(Exception): pass
def retriable(error):
    if isinstance(error,socket.timeout):
        return True
    return getattr(error,'errno',None) in (113,101,111,114)
def dial(kind):
    sock=socket.socket(socket.AF_INET,kind);sock.settimeout(15)
    while True:
        try:
            sock.connect((host,port))
            return sock
        except OSError as error:
            if retriable(error) and time.monotonic()<deadline:
                time.sleep(0.5);continue
            raise
def once():
    done=[]
    for kind,proto in ((socket.SOCK_STREAM,'tcp'),(socket.SOCK_DGRAM,'udp')):
        sock=dial(kind)
        try:
            data=nonce+b'/'+proto.encode()+secrets.token_bytes(256)
            sock.sendall(data)
            got=b''
            while len(got)<len(data):
                part=sock.recv(65536)
                if not part:
                    raise RetryWarmup()
                got+=part
                if kind==socket.SOCK_DGRAM:
                    break
            if got!=data:
                raise RuntimeError('Echo challenge mismatch')
            done.append(proto)
        finally:
            sock.close()
    return done
while True:
    try:
        protocols=once()
        break
    except RetryWarmup:
        if time.monotonic()>=deadline:
            raise RuntimeError('Echo closed before completion (tunnel/forward did not settle)')
        time.sleep(0.5)
    except OSError as error:
        if retriable(error) and time.monotonic()<deadline:
            time.sleep(0.5)
            continue
        raise
print(json.dumps({'passed':True,'latency_ms':round((time.monotonic()-start)*1000,1),'protocols':protocols}))
'''


def reserve_probe_port(ssh, exclude, preferred=None, bind_host="127.0.0.1"):
    program='''import socket,sys,json
exclude=set(map(int,json.loads(sys.argv[1])));preferred=int(sys.argv[2]);host=sys.argv[3]
for attempt in range(100):
 tcp=socket.socket();udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
 try:
  candidate=preferred if attempt==0 else 0
  if candidate and candidate in exclude:continue
  tcp.bind((host,candidate));port=tcp.getsockname()[1]
  if port in exclude:continue
  udp.bind((host,port));print(port);break
 except OSError:pass
 finally:tcp.close();udp.close()
else:raise RuntimeError('No probe port available')
'''
    code,out,_=ssh.execute('python3 -c '+shlex.quote(program)+' '+shlex.quote(json.dumps(list(exclude)))+' '+str(int(preferred or 0))+' '+shlex.quote(bind_host))
    if code:raise RuntimeError('Could not allocate probe port')
    return int(validate_port(out.strip()))


def forward_rules(node,server_ip,ports):
    rules=[]
    validated=validate_ports(ports)
    for port in validated:
        for protocol in ('tcp','udp'):
            rules.append({'listen':f'0.0.0.0:{port}','target':f'{server_ip}:{port}','protocol':protocol})
    meta=node.get('paqet',{})
    ingress=meta.get('probe_port');backend=meta.get('probe_backend_port')
    if str(meta.get('tunnel_port')) in validated:
        raise ValueError('Client port conflicts with the raw Paqet carrier port')
    if ingress and str(ingress) in validated:
        raise ValueError('Client port conflicts with reserved Paqet probe ingress')
    if ingress and backend:
        ingress=validate_port(ingress);backend=validate_port(backend)
        for protocol in ('tcp','udp'):
            rules.append({'listen':f'127.0.0.1:{ingress}','target':f'{server_ip}:{backend}','protocol':protocol})
    return rules


def verify_data(iran,kharej,node):
    meta=node.get('paqet',{})
    ingress=validate_port(meta.get('probe_port',''))
    backend=validate_port(meta.get('probe_backend_port',''))
    channel=None
    try:
        # Bind on all interfaces so the Paqet raw-packet server can deliver to
        # the real server IP. 0.0.0.0 covers both loopback and the public IP.
        bind_ip = "0.0.0.0"
        stdin,stdout,stderr=kharej.client.exec_command('python3 -u -c '+shlex.quote(ECHO)+' '+shlex.quote(bind_ip)+' '+backend,timeout=10)
        channel=stdout.channel;channel.settimeout(35)
        bound = None
        for _ in range(20):
            line = stdout.readline()
            if not line:
                time.sleep(0.3)
                continue
            bound = line.strip()
            break
        if bound != backend:
            raise RuntimeError('Paqet probe backend could not bind its reserved port')
        # Let the freshly started Paqet client register and raise its forward
        # listeners before the first probe attempt; the probe also retries.
        time.sleep(3)
        code,out,err=iran.execute('python3 -c '+shlex.quote(PAQET_PROBE)+' 127.0.0.1 '+ingress+' '+secrets.token_hex(24),timeout=60)
        if code:
            detail = (err.strip() or out.strip())
            msg = f'TCP/UDP data did not traverse Paqet: {detail}' if detail else 'TCP/UDP data did not traverse Paqet'
            raise RuntimeError(msg)
        result=json.loads(out)
        if result.get('passed') is not True or result.get('protocols')!=['tcp','udp']:
            raise RuntimeError('Invalid Paqet data challenge result')
        return result
    finally:
        if channel:channel.close()
