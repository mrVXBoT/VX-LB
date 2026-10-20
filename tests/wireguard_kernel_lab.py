"""Real Linux WireGuard test. Requires root in a disposable VM.

Uses adapter-generated wg-quick configurations, real kernel interfaces, TCP/UDP
challenges, wrong-PSK rejection and recovery. Not the historical crypto mock lab.
"""
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.wireguard_adapter import WireGuardAdapter
from core.wireguard_tools import generate_preshared_key
from core.private_link_health import probe_pair


def run(*args):
    return subprocess.check_output(list(map(str,args)),stderr=subprocess.STDOUT,text=True).strip()


class ProcessChannel:
    def __init__(self,process):self.process=process
    def settimeout(self,seconds):pass
    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait()


class NamespaceSSH:
    def __init__(self,namespace):self.namespace=namespace;self.ip=namespace;self.client=self
    def execute(self,command,timeout=30):
        result=subprocess.run(['ip','netns','exec',self.namespace,'sh','-c',command],capture_output=True,text=True,timeout=timeout)
        if result.returncode:print('Namespace command failed:',result.stderr[-500:])
        return result.returncode,result.stdout,result.stderr
    def exec_command(self,command,timeout=10):
        process=subprocess.Popen(['ip','netns','exec',self.namespace,'sh','-c','exec '+command],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        process.stdout.channel=ProcessChannel(process)
        return process.stdin,process.stdout,process.stderr


def main():
    if os.geteuid()!=0:raise RuntimeError('Run only as root inside a disposable VM')
    if not os.environ.get('LD_BP_WG_LAB_INSIDE'):
        env=dict(os.environ,LD_BP_WG_LAB_INSIDE='1')
        return subprocess.call(['unshare','-n',sys.executable,__file__],env=env)
    suffix=secrets.token_hex(3);names=['wgir-'+suffix,'wgkh-'+suffix]
    adapter=WireGuardAdapter();config=adapter.configure({'ip':'192.0.2.1','node_name':'labtest'},{'ip':'192.0.2.2'},{'enable_psk':True,'tunnel_port':51820})
    iface=config['interface'];created=[]
    with tempfile.TemporaryDirectory(prefix='ldbp-wg-kernel-') as folder:
        try:
            for name in names:run('ip','netns','add',name);created.append(name)
            run('ip','link','add','wg-lab-a','type','veth','peer','name','wg-lab-b')
            configs=[]
            for index,name in enumerate(names):
                link=['wg-lab-a','wg-lab-b'][index]
                run('ip','link','set',link,'netns',name)
                for command in (['ip','link','set','lo','up'],['ip','link','set',link,'up'],['ip','addr','add',f'192.0.2.{index+1}/30','dev',link]):run('ip','netns','exec',name,*command)
                directory=Path(folder)/str(index);directory.mkdir();path=directory/(iface+'.conf');path.write_text(config['iran_config' if index==0 else 'kharej_config']);path.chmod(0o600);configs.append(path)
                run('ip','netns','exec',name,'wg-quick','up',path)
            ir,kh=map(NamespaceSSH,names)
            local=config['iran_private_ip'].split('/')[0];remote=config['kharej_private_ip'].split('/')[0]
            result=probe_pair(ir,kh,local,remote,iface)
            print('PASS: real WireGuard TCP/UDP in both directions',result)
            counters=run('ip','netns','exec',names[0],'wg','show',iface,'transfer')
            assert any(int(v)>0 for v in counters.split()[1:])
            print('PASS: kernel WireGuard transfer counters increased')
            other=adapter.configure({'ip':'192.0.2.1','node_name':'labsecond'},{'ip':'192.0.2.2'},{'enable_psk':True,'ipv4_subnet':'10.100.3.0/30','tunnel_port':51821})
            for index,name in enumerate(names):
                path=Path(folder)/str(index)/(other['interface']+'.conf');path.write_text(other['iran_config' if index==0 else 'kharej_config']);path.chmod(0o600)
                run('ip','netns','exec',name,'wg-quick','up',path)
            try:
                probe_pair(ir,kh,other['iran_private_ip'].split('/')[0],other['kharej_private_ip'].split('/')[0],other['interface'])
            except Exception:
                for name in names:
                    print(name,run('ip','netns','exec',name,'ip','-4','route','show'))
                    for field in ('latest-handshakes','listen-port','endpoints','allowed-ips','transfer'):
                        print(field,run('ip','netns','exec',name,'wg','show',other['interface'],field))
                raise
            probe_pair(ir,kh,local,remote,iface)
            assert '10.100.0.0/16' not in run('ip','netns','exec',names[0],'ip','-4','route','show')
            print('PASS: two adapter-generated WireGuard links coexist without a shared /16 route')

            # Rebuild Iran endpoint with a wrong PSK; no old session may survive.
            original=configs[0].read_text();wrong=generate_preshared_key()
            import re
            bad=re.sub(r'(?m)^PresharedKey\s*=.*$', 'PresharedKey = '+wrong, original)
            assert bad!=original
            run('ip','netns','exec',names[0],'wg-quick','down',configs[0]);configs[0].write_text(bad)
            run('ip','netns','exec',names[0],'wg-quick','up',configs[0])
            try:probe_pair(ir,kh,local,remote,iface)
            except RuntimeError:print('PASS: wrong PSK rejected real TCP/UDP probe')
            else:raise RuntimeError('Wrong WireGuard PSK was accepted')
            run('ip','netns','exec',names[0],'wg-quick','down',configs[0]);configs[0].write_text(original)
            run('ip','netns','exec',names[0],'wg-quick','up',configs[0])
            probe_pair(ir,kh,local,remote,iface);print('PASS: correct PSK restored the data path')
            run('ip','netns','exec',names[0],'wg-quick','down',configs[0])
            try:probe_pair(ir,kh,local,remote,iface)
            except RuntimeError:print('PASS: removing the actual interface stops data transfer')
            else:raise RuntimeError('Data crossed after interface deletion')
        finally:
            for name in reversed(created):subprocess.run(['ip','netns','delete',name],capture_output=True)
    print('PASS: isolated WireGuard namespaces cleaned up')
    return 0

if __name__=='__main__':sys.exit(main())
