#!/usr/bin/env python3
"""Two disposable SSH endpoints backed by the stopped managed lab disk.

No disk copy, production credentials, host routes or host firewall changes.
The backing VM MUST stay stopped until overlays are deleted. QEMU's own block
locks also prevent opening that backing disk for writes while guests run.
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path.home()/'.cache/ldbp-kernel-lab'
PAIR = CACHE/'private-link-pair'


def module(index=None):
    spec = importlib.util.spec_from_file_location('ldbp_vm_'+str(index), ROOT/'scripts/kernel_lab_vm.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    if index is not None:
        value.CACHE = PAIR/str(index)
        value.PORT = 18766+index
    return value


def command(*arguments):
    return subprocess.run(list(map(str, arguments)),check=True,capture_output=True,text=True).stdout.strip()


def prepare():
    original = module()
    if original.pid():
        raise RuntimeError('Power off the managed backing VM before preparing endpoint overlays')
    if shutil.disk_usage(CACHE).free < 180*1024*1024:
        raise RuntimeError('At least 180 MiB free required for disposable overlays')
    PAIR.mkdir(mode=0o700,exist_ok=True)
    stat = (CACHE/'disk.qcow2').stat()
    identity = dict(size=stat.st_size, mtime_ns=stat.st_mtime_ns)
    if (PAIR/'base.json').exists() and json.loads((PAIR/'base.json').read_text()) != identity:
        raise RuntimeError('Backing disk changed; remove stopped pair overlays before preparing again')
    (PAIR/'base.json').write_text(json.dumps(identity))
    sys.path.insert(0,str(CACHE/'python'))
    import pycdlib
    public = (CACHE/'id_ed25519.pub').read_text().strip()
    for index in (0,1):
        folder = PAIR/str(index)
        folder.mkdir(mode=0o700,exist_ok=True)
        shutil.copyfile(CACHE/'id_ed25519',folder/'id_ed25519')
        (folder/'id_ed25519').chmod(0o600)
        cloud = f'''#cloud-config
hostname: ldbp-private-link-{index}
manage_etc_hosts: true
ssh_deletekeys: true
ssh_genkeytypes: [ed25519]
users:
  - name: ldbp
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - {public}
ssh_pwauth: false
package_update: false
package_upgrade: false
'''
        iso = pycdlib.PyCdlib()
        iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='cidata')
        for name, filename, value in [('USER_DATA.;1','user-data',cloud), ('META_DATA.;1','meta-data',f'instance-id: ldbp-private-link-{index}\nlocal-hostname: ldbp-private-link-{index}\n')]:
            data = value.encode()
            iso.add_fp(io.BytesIO(data),len(data),iso_path='/'+name,rr_name=filename,joliet_path='/'+filename)
        iso.write(str(folder/'seed.iso'))
        iso.close()
        if not (folder/'disk.qcow2').exists():
            command('qemu-img','create','-f','qcow2','-F','qcow2','-b',CACHE/'disk.qcow2',folder/'disk.qcow2')
    print('Prepared two thin, disposable endpoint overlays')


def start():
    if module().pid():
        raise RuntimeError('Backing VM must stay stopped while endpoint overlays exist')
    stat=(CACHE/'disk.qcow2').stat()
    if json.loads((PAIR/'base.json').read_text()) != dict(size=stat.st_size,mtime_ns=stat.st_mtime_ns):
        raise RuntimeError('Backing disk changed; endpoint overlays cannot safely run')
    for index in (0,1):
        vm=module(index)
        if vm.pid():
            continue
        link='listen=127.0.0.1:18768' if index==0 else 'connect=127.0.0.1:18768'
        command('qemu-system-x86_64','-name',f'ldbp-private-link-{index}', '-enable-kvm','-cpu','host','-m','1024','-smp','2',
            '-drive',f'file={vm.CACHE}/disk.qcow2,if=virtio,format=qcow2',
            '-drive',f'file={vm.CACHE}/seed.iso,media=cdrom,readonly=on',
            '-netdev',f'user,id=management,hostfwd=tcp:127.0.0.1:{vm.PORT}-:22',
            '-device',f'virtio-net-pci,netdev=management,mac=52:54:00:80:01:0{index+1}',
            '-netdev',f'socket,id=private,{link}',
            '-device',f'virtio-net-pci,netdev=private,mac=52:54:00:80:02:0{index+1}',
            '-display','none','-serial',f'file:{vm.CACHE}/serial.log','-pidfile',vm.CACHE/'vm.pid','-daemonize')
        print('Started disposable endpoint',index,'PID',vm.pid(),'SSH port',vm.PORT)


def configure():
    for index in (0,1):
        vm=module(index)
        client=vm.ssh()
        try:
            # Persist only the guest's isolated backplane interface. Management
            # DHCP/default route is not modified.
            config = f'''network:
  version: 2
  ethernets:
    lab-backplane:
      match:
        macaddress: '52:54:00:80:02:0{index+1}'
      dhcp4: false
      addresses: [192.0.2.{index+1}/30]
'''
            with client.open_sftp() as sftp:
                with sftp.file('/tmp/ldbp-backplane.yaml','w') as target:target.write(config)
                sftp.chmod('/tmp/ldbp-backplane.yaml',0o600)
            _,out,err=client.exec_command('sudo install -m 600 /tmp/ldbp-backplane.yaml /etc/netplan/90-ldbp-backplane.yaml && sudo netplan apply',timeout=30)
            error=err.read().decode()
            if out.channel.recv_exit_status():raise RuntimeError(error)
            print('Configured isolated guest backplane',index)
        finally:client.close()


def stop(remove=False):
    for index in (1,0):
        vm=module(index)
        value=vm.pid()
        if value:
            os.kill(value,signal.SIGTERM)
            for _ in range(100):
                if not vm.pid():break
                time.sleep(.1)
            else:raise RuntimeError('Disposable VM has not stopped')
    if remove:
        shutil.rmtree(PAIR)
    print('Stopped endpoint pair'+(' and removed disposable overlays' if remove else ''))


if __name__=='__main__':
    action=sys.argv[1]
    if action=='prepare':prepare()
    elif action=='start':start()
    elif action=='configure':configure()
    elif action=='status':
        for index in (0,1):print('Endpoint',index,'PID',module(index).pid())
    elif action=='stop':stop('--remove' in sys.argv)
