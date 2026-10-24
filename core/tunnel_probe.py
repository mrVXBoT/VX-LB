"""Loopback-only nonce probe through a temporary route in the real tunnel."""
import json
import re
import secrets
import shlex
import time
from core.validation import validate_ports, validate_port

ECHO_SERVER = '''import socket,time
s=socket.socket();s.bind(("127.0.0.1",0));s.listen(4);s.settimeout(1)
print(s.getsockname()[1],flush=True)
end=time.monotonic()+240
while time.monotonic()<end:
 try:
  c,_=s.accept();c.settimeout(10)
  with c:
   data=b""
   while not data.endswith(b"\\n") and len(data)<65537:
    chunk=c.recv(min(65536,65537-len(data)))
    if not chunk:break
    data+=chunk
   c.sendall(b"VX-LB-PROBE:"+data)
 except (OSError,TimeoutError):pass
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


def add_probe_route(config, listen_port, backend_port):
    # Do not change any existing mapping or transport option.
    pattern=r'(?ms)^(ports\s*=\s*\[)(.*?)(\])'
    matches=list(re.finditer(pattern,config))
    if len(matches)!=1:raise RuntimeError('فهرست پورت‌های فایل تونل قابل بررسی نیست')
    route=f'"127.0.0.1:{listen_port}=127.0.0.1:{backend_port}"'
    def insert(match):
        body=match.group(2).rstrip()
        return match.group(1)+body+(' ' if body.endswith(',') else ', ' if body.strip() else '')+route+match.group(3)
    return re.sub(pattern,insert,config,count=1)

class TunnelProbe:
    def __init__(self, iran, kharej):
        self.iran=iran;self.kharej=kharej;self.channel=None
    def __enter__(self):
        _,stdout,_=self.kharej.client.exec_command('python3 -u -c '+shlex.quote(ECHO_SERVER),timeout=10)
        self.channel=stdout.channel
        line=stdout.readline().strip()
        if not line.isdigit():self.close();raise RuntimeError('راه‌اندازی مقصد آزمون تونل ناموفق بود')
        self.backend_port=int(line)
        self.listen_port=self.iran.find_free_port()
        return self
    def close(self):
        if self.channel:self.channel.close();self.channel=None
    def __exit__(self,*args):self.close()
    def verify(self, timeout=45):
        nonce=secrets.token_hex(24)
        script='''import socket,sys
try:
 with socket.create_connection(("127.0.0.1",int(sys.argv[1])),timeout=3) as s:
  s.settimeout(10);seed=sys.argv[2].encode();payload=(seed*1366)[:65536]+b"\\n";s.sendall(payload);expected=b"VX-LB-PROBE:"+payload;data=b""
  while len(data)<len(expected):
   chunk=s.recv(len(expected)-len(data))
   if not chunk:break
   data+=chunk
  sys.exit(0 if data==expected else 2)
except OSError:sys.exit(3)
'''
        command='python3 -c '+shlex.quote(script)+' '+str(self.listen_port)+' '+shlex.quote(nonce)
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            code,_,_=self.iran.execute(command,timeout=15)
            if code==0:return True
            time.sleep(1)
        return False
