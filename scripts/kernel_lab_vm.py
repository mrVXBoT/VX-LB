#!/usr/bin/env python3
"""Local KVM lab. No production inventory or host routes/firewall are used.

Download the official Ubuntu Minimal 24.04 image and SHA256SUMS into CACHE,
then run `prepare`, `start`, `status`, `sync`, `exec COMMAND`, or `stop`.
pycdlib 1.14.0 is only needed by prepare (isolated in CACHE/python).
"""
import argparse
import datetime
import hashlib
import io
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tarfile

CACHE=Path.home()/'.cache/vxlb-kernel-lab'
ROOT=Path(__file__).resolve().parents[1]
PORT=18766


def run(*args):
    return subprocess.run(list(map(str,args)),check=True,capture_output=True,text=True).stdout.strip()


def prepare():
    CACHE.mkdir(parents=True,exist_ok=True);CACHE.chmod(0o700)
    filename='ubuntu-24.04-minimal-cloudimg-amd64.img'
    expected=next(line.split()[0] for line in (CACHE/'SHA256SUMS').read_text().splitlines() if line.split()[-1].lstrip('*')==filename)
    image=CACHE/'ubuntu-minimal.img'
    source=image if image.exists() else CACHE/'ubuntu-minimal.img.part'
    actual=hashlib.file_digest(source.open('rb'),'sha256').hexdigest()
    if actual!=expected:raise RuntimeError('Ubuntu image checksum mismatch (or incomplete download)')
    if source!=image:source.rename(image)
    if not (CACHE/'id_ed25519').exists():
        run('ssh-keygen','-q','-t','ed25519','-N','','-C','vxlb-isolated-kernel-lab','-f',CACHE/'id_ed25519')
    (CACHE/'id_ed25519').chmod(0o600)
    public=(CACHE/'id_ed25519.pub').read_text().strip()
    cloud=f'''#cloud-config
hostname: vxlb-kernel-lab
manage_etc_hosts: true
users:
  - name: vxlb
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - {public}
ssh_pwauth: false
package_update: true
packages:
  - python3
  - python3-pip
  - python3-venv
  - python3-yaml
  - python3-paramiko
  - python3-cryptography
  - python3-pytest
  - wireguard-tools
  - strongswan-charon
  - libcharon-extra-plugins
  - libstrongswan-extra-plugins
  - strongswan-swanctl
  - iptables
  - tcpdump
  - bubblewrap
  - iproute2
  - iputils-ping
runcmd:
  - [bash, -c, 'set -e; if ! modprobe geneve; then apt-get install -y linux-modules-extra-$(uname -r); fi; for m in geneve vxlan bridge wireguard ip6_gre ip6_tunnel; do modprobe "$m"; done; touch /var/lib/vxlb-lab-ready']
'''
    sys.path.insert(0,str(CACHE/'python'))
    import pycdlib
    iso=pycdlib.PyCdlib();iso.new(interchange_level=3,joliet=3,rock_ridge='1.09',vol_ident='cidata')
    for iso_name,rr_name,content in [('USER_DATA.;1','user-data',cloud),('META_DATA.;1','meta-data','instance-id: vxlb-kernel-lab-1\nlocal-hostname: vxlb-kernel-lab\n')]:
        payload=content.encode();iso.add_fp(io.BytesIO(payload),len(payload),iso_path='/'+iso_name,rr_name=rr_name,joliet_path='/'+rr_name)
    iso.write(str(CACHE/'seed.iso'));iso.close()
    if not (CACHE/'disk.qcow2').exists():
        run('qemu-img','create','-f','qcow2','-F','qcow2','-b',image,CACHE/'disk.qcow2')
        run('qemu-img','resize',CACHE/'disk.qcow2','12G')
    print('Verified Ubuntu image SHA256:',actual)
    print('Prepared isolated lab in',CACHE)


def pid():
    try:
        value=int((CACHE/'vm.pid').read_text());os.kill(value,0)
        cmd=Path('/proc',str(value),'cmdline').read_bytes()
        return value if str(CACHE/'disk.qcow2').encode() in cmd else None
    except (OSError,ValueError):return None


def start():
    if pid():print('Already running PID',pid());return
    run('qemu-system-x86_64','-name','vxlb-isolated-kernel-lab','-enable-kvm','-cpu','host','-m','1536','-smp','2','-drive',f'file={CACHE}/disk.qcow2,if=virtio,format=qcow2','-drive',f'file={CACHE}/seed.iso,media=cdrom,readonly=on','-netdev',f'user,id=labnet,hostfwd=tcp:127.0.0.1:{PORT}-:22','-device','virtio-net-pci,netdev=labnet','-display','none','-serial',f'file:{CACHE}/serial.log','-monitor',f'unix:{CACHE}/monitor.sock,server,nowait','-pidfile',CACHE/'vm.pid','-daemonize')
    print('Started isolated VM PID',pid(),'SSH 127.0.0.1:'+str(PORT))


def ssh():
    if not pid():raise RuntimeError('Managed VM is not running')
    import paramiko
    client=paramiko.SSHClient()
    known=CACHE/'ssh_known_hosts'
    if known.exists():client.load_host_keys(str(known))
    class LabFirstUse(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self,client,hostname,key):
            client.get_host_keys().add(hostname,key.get_name(),key);client.save_host_keys(str(known));known.chmod(0o600)
    client.set_missing_host_key_policy(LabFirstUse())
    client.connect('127.0.0.1',port=PORT,username='vxlb',key_filename=str(CACHE/'id_ed25519'),allow_agent=False,look_for_keys=False,timeout=5,banner_timeout=5,auth_timeout=5)
    return client


def execute(command):
    client=ssh()
    try:
        stdin,stdout,stderr=client.exec_command(command,timeout=120)
        output=stdout.read().decode(errors='replace');error=stderr.read().decode(errors='replace')
        code=stdout.channel.recv_exit_status()
        print(output,end='');print(error,end='',file=sys.stderr)
        name=os.environ.get('VX_LB_LAB_CAPTURE')
        if name:
            if Path(name).name!=name:raise ValueError('Capture must be a filename')
            folder=CACHE/'logs';folder.mkdir(mode=0o700,exist_ok=True)
            path=folder/name
            path.write_text('Command: '+command+'\nUTC: '+datetime.datetime.now(datetime.timezone.utc).isoformat()+'\nExit: '+str(code)+'\n'+output+'\nSTDERR:\n'+error)
            path.chmod(0o600)
        return code
    finally:client.close()


def sync():
    client=ssh()
    try:
        payload=io.BytesIO()
        with tarfile.open(fileobj=payload,mode='w:gz') as tar:
            for directory in ('core','tests'):
                for path in (ROOT/directory).rglob('*'):
                    if path.is_file() and '__pycache__' not in path.parts and path.suffix not in ('.pyc','.log'):
                        tar.add(path,arcname=str(path.relative_to(ROOT)))
        payload.seek(0)
        with client.open_sftp() as sftp:
            sftp.putfo(payload,'/tmp/vxlb-lab-source.tar.gz')
        stdin,stdout,stderr=client.exec_command('sudo mkdir -p /opt/vxlb-lab && sudo tar -xzf /tmp/vxlb-lab-source.tar.gz -C /opt/vxlb-lab',timeout=30)
        error=stderr.read().decode();code=stdout.channel.recv_exit_status()
        if code:raise RuntimeError(error)
        print('Synced core/ and tests/ only; no inventory, credentials or production data')
    finally:client.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['prepare','start','status','sync','exec','stop']);parser.add_argument('command',nargs='*');args=parser.parse_args()
    if args.action=='prepare':prepare()
    elif args.action=='start':start()
    elif args.action=='status':
        print('Managed VM PID:',pid())
        if pid():return execute('test -f /var/lib/vxlb-lab-ready && echo LAB_READY; cloud-init status; uname -r')
    elif args.action=='exec':return execute(' '.join(args.command))
    elif args.action=='sync':sync()
    elif args.action=='stop':
        value=pid()
        if value:os.kill(value,signal.SIGTERM);print('Stopped managed lab VM PID',value)
    return 0

if __name__=='__main__':sys.exit(main())
