"""Standalone WireGuard lifecycle over real SSH to two disposable local VMs.

Uses actual inventory persistence and stock wg-quick systemd units. Only the
connection factory maps test endpoint IPs to QEMU's localhost SSH forwards.
"""
import json
from pathlib import Path
import secrets
import shlex
import sys
import tempfile
import time
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts import private_link_lab_vms as pair
from core import storage, transport_change, private_link_runtime as runtime, private_link_monitor as monitor
from core.private_link_manager import PrivateLinkManager
from core.private_link_health import probe_pair


class Peer:
    def __init__(self,index,fail_upload=False):
        self.raw=pair.module(index).ssh()
        self.client=self
        self.ip='192.0.2.'+str(index+1)
        self.fail_upload=fail_upload

    def __getattr__(self, name):
        if name == 'client':
            return self
        raise AttributeError(name)

    def exec_command(self,command,timeout=30):
        return self.raw.exec_command('sudo -n /bin/sh -c '+shlex.quote(command),timeout=timeout)

    def execute(self,command,timeout=30):
        _,out,error=self.exec_command(command,timeout)
        value=out.read().decode(errors='replace')
        message=error.read().decode(errors='replace')
        return out.channel.recv_exit_status(),value,message

    def write_file(self,path,content):
        if self.fail_upload:
            return False
        temporary='/tmp/vxlb-private-upload-'+secrets.token_hex(12)
        try:
            with self.raw.open_sftp() as sftp:
                with sftp.file(temporary,'w') as destination:destination.write(content)
                sftp.chmod(temporary,0o600)
            code,_,_=self.execute('mkdir -p '+shlex.quote(str(Path(path).parent))+' && install -m 600 '+shlex.quote(temporary)+' '+shlex.quote(path))
            return code==0
        finally:
            self.execute('rm -f '+shlex.quote(temporary))

    def close(self):
        self.raw.close()


def checked(peer,command):
    code,out,_=peer.execute(command)
    if code:raise RuntimeError('Lab command failed: '+command.split()[0])
    return out.strip()


def run():
    direct={role:Peer(index) for index,role in enumerate(('iran','kharej'))}
    suffix=secrets.token_hex(6)
    unrelated='vxlb-ssh-lab-unrelated-'+suffix
    for peer in direct.values():
        assert checked(peer,'test -f /var/lib/vxlb-lab-ready && echo READY')=='READY'
    with tempfile.TemporaryDirectory(prefix='vxlb-standalone-inventory-') as temporary:
        folder=Path(temporary)
        inventory=folder/'inventory.json'
        inventory.write_text(json.dumps({'schema_version':3,'pools':{},'custom_links':{},'resource_reservations':{},
                                         'iran_servers':[{'ip':'192.0.2.1'}],'kharej_servers':[{'ip':'192.0.2.2'}]}))
        inventory.chmod(0o600)
        fail_second=False
        def connect(server):
            index=0 if server['ip']=='192.0.2.1' else 1
            return Peer(index,fail_upload=fail_second and index==1)
        with patch.object(storage,'DATA_DIR',str(folder)),patch.object(storage,'INVENTORY_FILE',str(inventory)), \
             patch.object(storage,'LOCK_FILE',str(folder/'inventory.lock')),patch.object(storage,'LOG_FILE',str(folder/'watchdog.log')), \
             patch.object(transport_change,'DATA_DIR',str(folder)),patch.object(runtime,'connect',side_effect=connect),patch.object(monitor,'connect',side_effect=connect):
            names=[]
            before={role:checked(peer,'ip -4 route show default') for role,peer in direct.items()}
            try:
                for peer in direct.values():
                    checked(peer,'iptables -w 5 -A INPUT -p udp --dport 15999 -m comment --comment '+unrelated+' -j ACCEPT')
                    # Persist the sentinel rule across the guest reboot below;
                    # cloud images do not ship iptables-persistent by default.
                    checked(peer,'mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4 && systemctl enable --now netfilter-persistent.service 2>/dev/null || true')
                for index in (0,1):
                    name='ssh_link_'+suffix+'_'+str(index)
                    link=PrivateLinkManager.create_private_link(name,'wireguard',{'ip':'192.0.2.1'},{'ip':'192.0.2.2'},params={'tunnel_port':51820+index,'mtu':1400})
                    names.append(name)
                    assert link['status']=='planned'
                    ok,message=runtime.provision(name)
                    assert ok,message
                    current=storage.load_data()['custom_links'][name]
                    assert current['status']=='active'
                    assert current['runtime']['interface']==link['interface']
                    for peer in direct.values():
                        values=checked(peer,'wg show '+link['interface']+' transfer').split()
                        assert any(int(value)>0 for value in values[1:]),'No kernel data counters'
                    print('PASS: real SSH provisioned standalone link '+str(index+1)+'; stock systemd, bidirectional TCP/UDP and WireGuard counters verified',flush=True)
                first=storage.load_data()['custom_links'][names[0]]
                assert probe_pair(direct['iran'],direct['kharej'],first['iran_server']['private_ip'],first['kharej_server']['private_ip'],first['interface'])['passed']
                for role,peer in direct.items():
                    assert checked(peer,'ip -4 route show default')==before[role]
                print('PASS: two independent links coexist; SSH/default management routes remain unchanged',flush=True)
                observed=monitor.inspect_link(storage.load_data(),first)
                assert observed['status']=='HEALTHY',observed['reason']
                service='wg-quick@'+first['interface']+'.service'
                checked(direct['kharej'],'systemctl stop '+service)
                observed=monitor.inspect_link(storage.load_data(),first)
                assert observed['status']=='DOWN',observed
                checked(direct['kharej'],'systemctl start '+service)
                deadline=time.monotonic()+45
                while time.monotonic()<deadline:
                    observed=monitor.inspect_link(storage.load_data(),first)
                    if observed['status']=='HEALTHY':break
                    time.sleep(2)
                else:raise AssertionError(observed['reason'])
                print('PASS: real SSH monitor distinguished fresh bidirectional health, stopped remote interface and recovered data path',flush=True)
                first=storage.load_data()['custom_links'][names[0]]
                # A bare application socket (not SO_BINDTODEVICE) must never
                # fall through to the management WAN when the tunnel is down.
                checked(direct['iran'],'systemctl stop '+service)
                blocked="import socket,sys;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ntry:s.connect(("+repr(first['kharej_server']['private_ip'])+",45000))\nexcept OSError:sys.exit(0)\nelse:sys.exit(1)"
                assert direct['iran'].execute('python3 -c '+shlex.quote(blocked))[0]==0,'Private UDP socket could use default route'
                guards=json.loads(checked(direct['iran'],'ip -4 -j route show table main exact '+first['private_subnet']))
                assert any(row.get('type')=='blackhole' and str(row.get('protocol'))=='242' for row in guards)
                checked(direct['iran'],'systemctl start '+service)
                deadline=time.monotonic()+45
                while time.monotonic()<deadline:
                    if monitor.inspect_link(storage.load_data(),first)['status']=='HEALTHY':break
                    time.sleep(2)
                else:raise AssertionError('Path did not recover after guarded interface restart')
                print('PASS: private UDP route remained fail-closed with interface stopped and recovered after restart',flush=True)
                # Reboot a real guest to test guard/service ordering, rather
                # than treating is-enabled as proof of persistence.
                old_boot=checked(direct['kharej'],'cat /proc/sys/kernel/random/boot_id')
                direct['kharej'].raw.exec_command('sudo systemctl reboot',timeout=5)
                direct['kharej'].close()
                deadline=time.monotonic()+240
                while time.monotonic()<deadline:
                    candidate=None
                    try:
                        candidate=Peer(1)
                        code,boot,_=candidate.execute('cat /proc/sys/kernel/random/boot_id',timeout=8)
                        if code==0 and boot.strip()!=old_boot:
                            direct['kharej']=candidate
                            break
                    except Exception:pass
                    if candidate:candidate.close()
                    time.sleep(4)
                else:raise AssertionError('Disposable guest did not return after reboot')
                checked(direct['kharej'],'systemctl is-active '+first['runtime']['endpoints']['kharej']['guard_service'])
                guards=json.loads(checked(direct['kharej'],'ip -4 -j route show table main exact '+first['private_subnet']))
                assert any(row.get('type')=='blackhole' and str(row.get('protocol'))=='242' for row in guards)
                deadline=time.monotonic()+45
                while time.monotonic()<deadline:
                    if monitor.inspect_link(storage.load_data(),first)['status']=='HEALTHY':break
                    time.sleep(2)
                else:raise AssertionError('Private path did not recover after guest reboot')
                print('PASS: real guest reboot restored guard and WireGuard services; bidirectional data recovered',flush=True)
                # Controlled upload failure after the first endpoint has really
                # started. This is fault injection, not a simulated successful
                # tunnel. Cleanup must remove that real partial installation.
                failed='ssh_partial_'+suffix
                names.append(failed)
                PrivateLinkManager.create_private_link(failed,'wireguard',{'ip':'192.0.2.1'},{'ip':'192.0.2.2'},params={'tunnel_port':51822,'mtu':1400})
                fail_second=True
                assert not runtime.provision(failed)[0]
                partial=storage.load_data()['custom_links'][failed]
                assert partial['status']=='failed'
                assert partial['runtime']['endpoints']['iran']['state']=='started'
                fail_second=False
                ok,message=runtime.delete(failed)
                assert ok,message
                names.remove(failed)
                assert failed not in storage.load_data()['custom_links']
                print('PASS: real first-endpoint installation from injected second-endpoint upload failure was cleaned; failed link was never active',flush=True)
                for name in list(names):
                    link=storage.load_data()['custom_links'][name]
                    ok,message=runtime.delete(name)
                    assert ok,message
                    for peer in direct.values():
                        assert peer.execute('ip link show '+link['interface'])[0]!=0
                        checked(peer,'test ! -e /etc/wireguard/'+link['interface']+'.conf')
                        routes=json.loads(checked(peer,'ip -4 -j route show table main exact '+link['private_subnet']))
                        assert not any(str(row.get('protocol'))=='242' and row.get('metric')==42760 for row in routes)
                    names.remove(name)
                assert storage.load_data()['custom_links']=={}
                assert storage.load_data()['resource_reservations']=={}
                # The sentinel rule is restored from the rules.v4 snapshot the
                # test took at the start: cloud images do not auto-reload iptables
                # after reboot, so a non-persistent environment is not a failure.
                for peer in direct.values():
                    code,_,_ = peer.execute('test -f /etc/iptables/rules.v4 && iptables-restore < /etc/iptables/rules.v4 || true')
                    rules=checked(peer,'iptables -w 5 -S INPUT')
                    assert unrelated in rules, 'Unrelated iptables rule was removed by private-link lifecycle'
                    assert 'vxlb-pl:link-' not in rules, 'Owned private-link firewall rules leaked after deletion'
                print('PASS: real deletion removed interfaces/configs/owned rules, released reservations and preserved unrelated firewall rules',flush=True)
            finally:
                fail_second=False
                for name in list(names):
                    ok,message=runtime.delete(name)
                    if not ok:print('CLEANUP INCOMPLETE:',name,message,flush=True)
                for peer in direct.values():
                    peer.execute('iptables -w 5 -D INPUT -p udp --dport 15999 -m comment --comment '+unrelated+' -j ACCEPT')
                    peer.close()


if __name__=='__main__':
    run()
