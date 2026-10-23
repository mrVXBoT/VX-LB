"""A loopback-only TCP/UDP challenge forwarded through the real Paqet process."""
import json
import secrets
import shlex
import time
from core.validation import validate_ports,validate_port
from core.private_link_health import ECHO,PROBE


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
    for port in validate_ports(ports):
        for protocol in ('tcp','udp'):
            rules.append({'listen':f'0.0.0.0:{port}','target':f'{server_ip}:{port}','protocol':protocol})
    meta=node.get('paqet',{})
    ingress=meta.get('probe_port');backend=meta.get('probe_backend_port')
    if not ingress or not backend:
        raise ValueError('Paqet probe mapping is missing; node requires provisioning with a probe route')
    ingress=validate_port(ingress);backend=validate_port(backend)
    if str(meta.get('tunnel_port')) in validate_ports(ports):
        raise ValueError('Client port conflicts with the raw Paqet carrier port')
    if ingress in validate_ports(ports):
        raise ValueError('Client port conflicts with reserved Paqet probe ingress')
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
        channel=stdout.channel;channel.settimeout(15)
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
        code,out,_=iran.execute('python3 -c '+shlex.quote(PROBE)+' 127.0.0.1 '+ingress+' '+secrets.token_hex(24)+" ''",timeout=30)
        if code:raise RuntimeError('TCP/UDP data did not traverse Paqet')
        result=json.loads(out)
        if result.get('passed') is not True or result.get('protocols')!=['tcp','udp']:
            raise RuntimeError('Invalid Paqet data challenge result')
        return result
    finally:
        if channel:channel.close()
