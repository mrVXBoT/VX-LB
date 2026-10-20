"""Real official Paqet binary across two Linux namespaces in a disposable VM.

Exercises adapter-generated configs and the reserved loopback TCP/UDP mapping.
No raw socket or firewall operation occurs outside the isolated namespaces.
"""
import copy
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.paqet_adapter import PaqetAdapter,generate_paqet_secret
from core.paqet_probe import forward_rules,verify_data,reserve_probe_port
from core.private_link_health import ECHO,PROBE
import shlex
from wireguard_kernel_lab import NamespaceSSH,run


def main():
    if os.geteuid()!=0:raise RuntimeError('Run as root only inside a disposable VM')
    if not os.environ.get('LD_BP_PAQET_LAB_INSIDE'):
        return subprocess.call(['unshare','-n',sys.executable,__file__],env=dict(os.environ,LD_BP_PAQET_LAB_INSIDE='1'))
    binary=os.environ.get('LD_BP_PAQET_BINARY','/opt/ldbp-lab/bin/paqet')
    print('Official Paqet binary:',run(binary,'version'))
    names=['pqir-'+secrets.token_hex(3),'pqkh-'+secrets.token_hex(3)];created=[];processes=[];logs=[];echo_channel=None
    adapter=PaqetAdapter();node={'node_name':'lab','paqet':{'probe_port':43000,'probe_backend_port':44000}}
    with tempfile.TemporaryDirectory(prefix='ldbp-paqet-kernel-') as folder:
        folder=Path(folder)
        try:
            for name in names:run('ip','netns','add',name);created.append(name)
            run('ip','link','add','pq-a','type','veth','peer','name','pq-b')
            macs=[]
            for index,name in enumerate(names):
                link=['pq-a','pq-b'][index];run('ip','link','set',link,'netns',name)
                run('ip','-n',name,'link','set','lo','up');run('ip','-n',name,'link','set',link,'up')
                run('ip','-n',name,'addr','add',f'192.0.2.{index+1}/30','dev',link)
                macs.append(json.loads(run('ip','-n',name,'-j','link','show','dev',link))[0]['address'])
            ir,kh=map(NamespaceSSH,names)
            tunnel_port=reserve_probe_port(kh,[45001,43000,44000],preferred=29999,bind_host='0.0.0.0')
            other_port=reserve_probe_port(kh,[tunnel_port,45001],preferred=tunnel_port,bind_host='0.0.0.0')
            assert other_port!=tunnel_port
            node['paqet']['tunnel_port']=tunnel_port
            print('PASS: raw carrier allocation avoids reserved ports for another node')
            for command in adapter.build_iptables_setup_commands(tunnel_port):
                run('ip','netns','exec',names[1],'sh','-c',command)
            secret=generate_paqet_secret()
            _,server_yaml=adapter.build_server_config(listen_port=tunnel_port,interface='pq-b',server_ip='192.0.2.2',router_mac=macs[0],secret_key=secret)
            client_config,client_yaml=adapter.build_client_config(server_ip='192.0.2.2',server_port=tunnel_port,interface='pq-a',client_ip='192.0.2.1',router_mac=macs[1],secret_key=secret,forward_rules=forward_rules(node,'192.0.2.2',['45001']))
            for name,content in [('server',server_yaml),('client',client_yaml)]:
                path=folder/(name+'.yaml');path.write_text(content);path.chmod(0o600)
            def launch(index,role):
                log=(folder/(role+'-'+str(len(processes))+'.log')).open('w+')
                logs.append(log)
                process=subprocess.Popen(['ip','netns','exec',names[index],binary,'run','-c',str(folder/(role+'.yaml'))],stdout=log,stderr=log)
                processes.append(process)
                return process
            server=launch(1,'server');client=launch(0,'client')
            ir,kh=map(NamespaceSSH,names)
            def wait_client(process):
                for _ in range(100):
                    if process.poll() is not None:raise RuntimeError('Paqet process exited before forward became ready')
                    code,_,_=ir.execute("ss -H -lnt 'sport = :43000' | grep -q 43000")
                    if code==0:return
                    time.sleep(0.05)
                raise RuntimeError('Paqet forward did not become ready')
            wait_client(client)
            result=verify_data(ir,kh,node)
            print('PASS: official Paqet forwarded TCP/UDP challenge and returned data',result)
            echo_stdin,echo_stdout,echo_stderr=kh.exec_command('python3 -u -c '+shlex.quote(ECHO)+' 0.0.0.0 45001')
            echo_channel=echo_stdout.channel
            assert echo_stdout.readline().strip()=='45001'
            code,output,error=ir.execute('python3 -c '+shlex.quote(PROBE)+" 127.0.0.1 45001 user-port-test ''")
            assert code==0 and json.loads(output)['protocols']==['tcp','udp'],error
            print('PASS: user-facing TCP and UDP port mappings carried real data to the destination service')

            client.terminate();client.wait(timeout=5)
            wrong=copy.deepcopy(client_config);wrong['transport']['kcp']['key']=generate_paqet_secret()
            import yaml
            (folder/'client.yaml').write_text(yaml.safe_dump(wrong,sort_keys=False))
            client=launch(0,'client');wait_client(client)
            try:verify_data(ir,kh,node)
            except RuntimeError:print('PASS: wrong KCP encryption key rejected the challenge')
            else:raise RuntimeError('Wrong Paqet key accepted data')
            client.terminate();client.wait(timeout=5);(folder/'client.yaml').write_text(client_yaml)
            client=launch(0,'client');wait_client(client)
            verify_data(ir,kh,node);print('PASS: restoring the correct key recovered the real data path')
            client.terminate();client.wait(timeout=5)
            assert server.poll() is None
            try:verify_data(ir,kh,node)
            except RuntimeError:print('PASS: stopping the Paqet client stopped data; server and responder remained available')
            else:raise RuntimeError('Data bypassed the stopped Paqet client')
        except Exception:
            for log in logs:
                log.flush();log.seek(0);print('Paqet diagnostic:',log.read()[-3000:])
            raise
        finally:
            if echo_channel:echo_channel.close()
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait()
            for log in logs:log.close()
            for name in reversed(created):subprocess.run(['ip','netns','delete',name],capture_output=True)
    print('PASS: Paqet processes and isolated namespaces cleaned up')
    return 0

if __name__=='__main__':sys.exit(main())
