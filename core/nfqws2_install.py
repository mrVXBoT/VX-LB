"""Verified immutable packet-engine package installation, separate from tunnels."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import tarfile
import tempfile
import time
import urllib.request
from core.nfqws2_profiles import VERSION,ARCHIVE_URL,ARCHIVE_SHA256,COMPONENT_SHA256,LIBRARY_DIRECTORY
from core.storage import DATA_DIR

MAX_ARCHIVE = 16*1024*1024


def archive_bundle(path):
    path=Path(path)
    if path.stat().st_size>MAX_ARCHIVE or hashlib.sha256(path.read_bytes()).hexdigest()!=ARCHIVE_SHA256:
        raise ValueError('NFQWS2 archive SHA256 mismatch')
    prefix='zapret2-'+VERSION+'/'
    members={'nfqws2':'binaries/linux-x86_64/nfqws2','zapret-lib.lua':'lua/zapret-lib.lua',
             'zapret-antidpi.lua':'lua/zapret-antidpi.lua','LICENSE.txt':'docs/LICENSE.txt'}
    result={}
    with tarfile.open(path) as archive:
        for name,relative in members.items():
            member=archive.getmember(prefix+relative)
            if not member.isfile() or member.size>4*1024*1024:
                raise ValueError('NFQWS2 package component is not a bounded regular file')
            content=archive.extractfile(member).read()
            if name in COMPONENT_SHA256 and hashlib.sha256(content).hexdigest()!=COMPONENT_SHA256[name]:
                raise ValueError('NFQWS2 component SHA256 mismatch')
            result[name]=content
    return result


def cached_archive(allow_download=False):
    directory=Path(DATA_DIR)/'cache';directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    target=directory/('zapret2-'+VERSION+'.tar.gz')
    if target.exists():
        archive_bundle(target);return target
    # Bundled offline copy: prefer the depot over any network when internet is
    # down. In strict-offline deployments we never reach for ARCHIVE_URL.
    bundled = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / 'bin' / 'x86_64' / ('zapret2-'+VERSION+'.tar.gz')
    if bundled.is_file():
        archive_bundle(bundled)
        shutil.copy(bundled, target)
        return target
    if not allow_download:
        raise FileNotFoundError(
            f"NFQWS2 archive missing from local depot; run VX-LB depot preflight "
            f"or pass allow_download=True explicitly. Expected: {bundled}"
        )
    temporary=directory/('.nfqws2-'+secrets.token_hex(8)+'.download')
    try:
        digest=hashlib.sha256();size=0;deadline=time.monotonic()+600
        with urllib.request.urlopen(ARCHIVE_URL,timeout=15) as response,temporary.open('xb') as output:
            temporary.chmod(0o600)
            while True:
                if time.monotonic()>deadline:raise TimeoutError('NFQWS2 download deadline exceeded')
                chunk=response.read(131072)
                if not chunk:break
                size+=len(chunk)
                if size>MAX_ARCHIVE:raise ValueError('NFQWS2 download exceeds package limit')
                digest.update(chunk);output.write(chunk)
        if digest.hexdigest()!=ARCHIVE_SHA256:raise ValueError('NFQWS2 download SHA256 mismatch')
        archive_bundle(temporary)
        temporary.replace(target)
        return target
    finally:temporary.unlink(missing_ok=True)


CHECK=r'''import hashlib,json,stat,sys
from pathlib import Path
base=Path(sys.argv[1]);expected=json.loads(sys.argv[2]);archive=sys.argv[3]
try:
 if not base.is_dir():raise FileNotFoundError
 if not base.stat().st_mode&1:raise RuntimeError('Packet library directory not traversable')
 for name,digest in expected.items():
  p=base/name
  if not p.is_file() or p.is_symlink():raise RuntimeError('Packet component must be a regular file')
  if hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise RuntimeError('Installed packet component SHA256 mismatch')
  if not p.stat().st_mode&4:raise RuntimeError('Packet library must be readable after privilege drop')
  if name=='nfqws2' and not p.stat().st_mode&1:raise RuntimeError('Packet engine is not executable')
 if (base/'ARCHIVE.SHA256').read_text().strip()!=archive:raise RuntimeError('Packet package marker mismatch')
 if not (base/'LICENSE.txt').is_file():raise RuntimeError('Packet package license missing')
except FileNotFoundError:sys.exit(3)
'''


def execute(ssh,command,timeout=30):
    code,out,error=ssh.execute(command,timeout=timeout)
    if code:raise RuntimeError(error.strip() or out.strip() or 'Packet package command failed')
    return out.strip()


def check(ssh,directory=None):
    args=['python3','-c',CHECK,directory or LIBRARY_DIRECTORY,json.dumps(COMPONENT_SHA256),ARCHIVE_SHA256]
    code,out,error=ssh.execute(' '.join(map(shlex.quote,args)),timeout=20)
    if code not in (0,3):raise RuntimeError(error.strip() or 'Installed packet package is invalid')
    return code==0


def install(ssh,archive_path=None,allow_download=False):
    execute(ssh,'test "$(id -u)" = 0 && command -v python3 systemctl iptables modprobe ss')
    if execute(ssh,'uname -s')!='Linux' or execute(ssh,'uname -m')!='x86_64':
        raise ValueError('Pinned packet engine currently requires Linux x86_64')
    if int(execute(ssh,'uname -r').split('.')[0])<4:
        raise ValueError('Packet engine requires a modern per-queue Linux kernel')
    execute(ssh,'modprobe nfnetlink_queue')
    if not check(ssh):
        bundle=archive_bundle(archive_path or cached_archive(allow_download=allow_download))
        parent=str(Path(LIBRARY_DIRECTORY).parent);stage=parent+'/.stage-'+secrets.token_hex(16)
        try:
            execute(ssh,'install -d -m 755 '+shlex.quote(parent)+' && install -d -m 700 '+shlex.quote(stage))
            with tempfile.NamedTemporaryFile() as binary:
                binary.write(bundle['nfqws2']);binary.flush()
                if not ssh.upload_binary(binary.name,stage+'/nfqws2'):raise RuntimeError('Packet binary upload failed')
            for name in ['zapret-lib.lua','zapret-antidpi.lua','LICENSE.txt']:
                if not ssh.write_file(stage+'/'+name,bundle[name].decode('utf-8')):
                    raise RuntimeError('Packet library upload failed')
            if not ssh.write_file(stage+'/ARCHIVE.SHA256',ARCHIVE_SHA256+'\n'):
                raise RuntimeError('Packet package marker write failed')
            names=' '.join(shlex.quote(stage+'/'+name) for name in ['zapret-lib.lua','zapret-antidpi.lua','LICENSE.txt','ARCHIVE.SHA256'])
            execute(ssh,'chmod 644 '+names+' && chmod 755 '+shlex.quote(stage))
            if not check(ssh,stage):raise RuntimeError('Staged packet package could not be verified')
            publish='''import errno,os,sys
from pathlib import Path
stage,target=map(Path,sys.argv[1:])
if stage.is_dir():
 try:os.rename(stage,target)
 except OSError as error:
  if error.errno not in (errno.EEXIST,errno.ENOTEMPTY):raise
'''
            execute(ssh,'python3 -c '+shlex.quote(publish)+' '+shlex.quote(stage)+' '+shlex.quote(LIBRARY_DIRECTORY))
            if not check(ssh):raise RuntimeError('Published packet package could not be verified')
        finally:
            cleanup='import shutil,sys;shutil.rmtree(sys.argv[1],ignore_errors=False) if __import__("os").path.exists(sys.argv[1]) else None'
            execute(ssh,'python3 -c '+shlex.quote(cleanup)+' '+shlex.quote(stage))
    args=[LIBRARY_DIRECTORY+'/nfqws2','--intercept=0','--lua-init=@'+LIBRARY_DIRECTORY+'/zapret-lib.lua',
          '--lua-init=@'+LIBRARY_DIRECTORY+'/zapret-antidpi.lua',
          "--lua-init=assert(type(fake)=='function' and type(multidisorder)=='function' and type(oob)=='function' and type(rst)=='function' and type(http_hostcase)=='function')"]
    execute(ssh,' '.join(map(shlex.quote,args)),timeout=20)
    return dict(version=VERSION,directory=LIBRARY_DIRECTORY,archive_sha256=ARCHIVE_SHA256)
