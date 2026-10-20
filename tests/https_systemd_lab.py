"""Opt-in remote service lab, using ONLY a temporary PrivateNetwork unit.

Call run(paramiko_client, verified_local_xray_path). No inventory or production
service is edited. The generated service stops automatically after 90 seconds.
"""
import json
import secrets
import shlex
import subprocess
import tempfile
from pathlib import Path
from core import https_tunnel as https

class Peer:
    def __init__(self,client):self.client=client
    def execute(self,command,timeout=30):
        _,out,error=self.client.exec_command(command,timeout=timeout)
        stdout=out.read().decode();stderr=error.read().decode()
        return out.channel.recv_exit_status(),stdout,stderr
    def write_file(self,path,content):
        code,_,_=self.execute('mkdir -p '+shlex.quote(str(Path(path).parent)))
        if code:return False
        with self.client.open_sftp() as sftp:
            with sftp.file(path,'w') as dest:dest.write(content)
            sftp.chmod(path,0o600)
        return True


def run(client,binary):
    peer=Peer(client);name='ldh'+secrets.token_hex(8)
    folder='/var/lib/ldbp-https-lab-'+secrets.token_hex(8)
    node={'node_name':name,'https':{'profile':https.profile('xhttp',{'server_name':'tunnel.test','binary':folder+'/xray',
          'certificate':folder+'/cert.pem','key':folder+'/key.pem'}),'uuid':secrets.token_hex(16),
          'path':'/'+secrets.token_hex(24),'outer_port':24443,'probe_local':22252,'probe_remote':22251}}
    import uuid
    node['https']['uuid']=str(uuid.uuid4())
    try:
        https.execute(peer,'mkdir -m 755 '+folder)
        with tempfile.TemporaryDirectory(prefix='ldbp-systemd-cert-') as temporary:
            temporary=Path(temporary)
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=tunnel.test',
                            '-addext','subjectAltName=DNS:tunnel.test','-keyout',str(temporary/'key.pem'),'-out',str(temporary/'cert.pem')],
                           check=True,capture_output=True)
            with client.open_sftp() as sftp:
                for local,remote,mode in [(binary,folder+'/xray',0o755),(str(temporary/'cert.pem'),folder+'/cert.pem',0o600),
                                          (str(temporary/'key.pem'),folder+'/key.pem',0o600),
                                          (str(Path(__file__).resolve().parents[1]/'core/https_probe.py'),folder+'/probe.py',0o600)]:
                    sftp.put(local,remote);sftp.chmod(remote,mode)
        iran,kharej=https.configs(node,'127.0.0.1',['22500'])
        for config in (iran,kharej):
            for inbound in config['inbounds']:inbound['listen']='127.0.0.1'
        https.test_config(peer,node,kharej)
        https.write(peer,folder+'/client.json',json.dumps(iran))
        service=https.service(node,iran=False).replace('[Install]','PrivateNetwork=yes\nRuntimeMaxSec=90\n[Install]')
        https.write(peer,'/etc/systemd/system/'+https.unit(node),service)
        https.execute(peer,'systemctl daemon-reload && systemctl start '+https.unit(node))
        pid=int(https.execute(peer,'systemctl show -p MainPID --value '+https.unit(node)))
        assert pid>1,'Sandbox service did not start'
        script='''import subprocess,os,time,pathlib
pid=PID
prefix=['nsenter','-t',str(pid),'-n','--']
uid=int(next(line for line in pathlib.Path('/proc/'+str(pid)+'/status').read_text().splitlines() if line.startswith('Uid:')).split()[1])
assert uid!=0,'Xray unexpectedly runs as root'
env=dict(os.environ,SSL_CERT_FILE=FOLDER+'/cert.pem')
workers=[]
try:
 log=open(FOLDER+'/client.log','w')
 workers.append(subprocess.Popen(prefix+[FOLDER+'/xray','run','-config',FOLDER+'/client.json'],stdout=log,stderr=log,env=env))
 echo=subprocess.Popen(prefix+['python3',FOLDER+'/probe.py','echo','22251'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);workers.append(echo)
 assert echo.stdout.readline().strip()=='READY'
 time.sleep(.4)
 result=subprocess.run(prefix+['python3',FOLDER+'/probe.py','probe','22252','SYSTEMD-PRIVATE-CREDENTIAL-CHECK'],capture_output=True,text=True,timeout=15)
 assert result.returncode==0,result.stdout+result.stderr
 print('PASS: real systemd DynamicUser UID '+str(uid)+', private TLS credentials, isolated network, actual TCP+UDP')
finally:
 for process in workers:
  if process.poll() is None:process.terminate()
 for process in workers:
  try:process.wait(timeout=3)
  except subprocess.TimeoutExpired:process.kill();process.wait()
'''.replace('FOLDER',repr(folder)).replace('pid=PID','pid='+str(pid))
        output=https.execute(peer,'python3 -c '+shlex.quote(script),timeout=30)
        print(output)
    except Exception:
        _,out,_=peer.execute('journalctl --no-pager -n 30 -u '+https.unit(node));print(out)
        raise
    finally:
        # All paths have generated identities; never stop an existing service.
        peer.execute('systemctl stop '+https.unit(node))
        peer.execute('rm -f /etc/systemd/system/'+https.unit(node)+' '+https.path(node)+' '+https.path(node)+'.validate.json')
        peer.execute('systemctl daemon-reload')
        peer.execute('rm -rf '+shlex.quote(folder))
