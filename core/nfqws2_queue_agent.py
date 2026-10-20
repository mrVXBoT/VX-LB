"""Owned, peer/port-scoped NFQUEUE rules for the managed packet engine.

Standalone stdlib agent. No global policies, forwarding sysctls, table flushes
or fail-open queue bypass. Queue ownership is proved from systemd PID, command
line and the actual netlink socket held by that process before rules are added.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

GENERATOR_MARK = '0x40000000/0x40000000'


def run(arguments, allowed=(0,)):
    result=subprocess.run(arguments,capture_output=True,text=True,timeout=15)
    if result.returncode not in allowed:
        raise RuntimeError(result.stderr.strip() or 'Packet-engine control command failed')
    return result


def iptables(*arguments,allowed=(0,)):
    return run(['iptables','-w','5','-t','mangle',*arguments],allowed)


def identity(config):
    value=config.get('id','')
    if not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{32}',value):
        raise ValueError('Invalid packet-engine ownership identity')
    return value


def number(value,name):
    if isinstance(value,bool) or not str(value).isdigit() or not 1<=int(value)<=65535:
        raise ValueError('Invalid '+name)
    return int(value)


def rules(config):
    tag='vxlb-nfq:'+identity(config)
    peer=str(ipaddress.IPv4Address(config['peer']))
    port=str(number(config['carrier_port'],'carrier port'))
    queue=str(number(config['queue'],'queue'))
    incoming=config.get('incoming',False)
    if not isinstance(incoming,bool):raise ValueError('Explicit incoming-queue flag required')
    common=['-m','mark','!','--mark',GENERATOR_MARK,'-m','comment','--comment',tag,'-j','NFQUEUE','--queue-num',queue]
    yield 'OUTPUT',['-d',peer,'-p','tcp','--dport',port,*common]
    if incoming:yield 'INPUT',['-s',peer,'-p','tcp','--sport',port,*common]


def queue_entry(queue,procroot='/proc'):
    path=Path(procroot)/'net/netfilter/nfnetlink_queue'
    try:rows=path.read_text().splitlines()
    except FileNotFoundError:return None
    for row in rows:
        fields=row.split()
        if len(fields)>=8 and int(fields[0])==queue:
            return dict(queue=queue,portid=int(fields[1]),pending=int(fields[2]),
                        kernel_dropped=int(fields[5]),user_dropped=int(fields[6]),seen=int(fields[7]))
    return None


def owns_netlink_socket(pid,portid,procroot='/proc'):
    root=Path(procroot);inodes=set()
    try:
        for entry in (root/str(pid)/'fd').iterdir():
            try:target=os.readlink(entry)
            except FileNotFoundError:continue
            match=re.fullmatch(r'socket:\[(\d+)\]',target)
            if match:inodes.add(int(match[1]))
        rows=(root/'net/netlink').read_text().splitlines()[1:]
    except FileNotFoundError:return False
    for row in rows:
        fields=row.split()
        if len(fields)>=10 and int(fields[1])==12 and int(fields[2])==portid and int(fields[9]) in inodes:
            return True
    return False


def inspect(config,procroot='/proc'):
    unit='vxlb-spoof-'+identity(config)+'-nfq.service'
    queue=number(config['queue'],'queue')
    binary=config.get('binary','')
    if not isinstance(binary,str) or not binary.startswith('/') or Path(binary).name!='nfqws2':
        raise ValueError('Invalid packet-engine executable')
    run(['systemctl','is-active','--quiet',unit])
    pid_text=run(['systemctl','show','--property=MainPID','--value',unit]).stdout.strip()
    if not pid_text.isdigit() or int(pid_text)<1:raise RuntimeError('Packet-engine PID is not ready')
    pid=int(pid_text)
    try:command=(Path(procroot)/str(pid)/'cmdline').read_bytes().split(b'\0')
    except FileNotFoundError:raise RuntimeError('Packet-engine process disappeared')
    if not command or os.path.realpath(os.fsdecode(command[0]))!=os.path.realpath(binary) or ('--qnum='+str(queue)).encode() not in command:
        raise RuntimeError('Packet-engine process does not own this configuration')
    entry=queue_entry(queue,procroot)
    if entry is None:raise RuntimeError('Packet-engine queue is not ready')
    if not owns_netlink_socket(pid,entry['portid'],procroot):
        raise RuntimeError('NFQUEUE socket is not owned by the managed process')
    return dict(entry,owner_pid=pid,verified=True)


def wait_ready(config):
    deadline=time.monotonic()+5
    while True:
        try:return inspect(config)
        except (OSError,RuntimeError):
            if time.monotonic()>=deadline:raise
            time.sleep(.1)


def apply(config):
    plans=list(rules(config))  # Validate all inputs before any mutation.
    status=wait_ready(config)
    created=[]
    try:
        for chain,rule in plans:
            if iptables('-C',chain,*rule,allowed=(0,1)).returncode:
                iptables('-I',chain,'1',*rule)
                created.append((chain,rule))
    except Exception as error:
        failures=[]
        for chain,rule in reversed(created):
            try:iptables('-D',chain,*rule)
            except Exception as failure:failures.append(str(failure))
        if failures:raise RuntimeError('Queue rule rollback unverified: '+'; '.join(failures)) from error
        raise
    return status


def remove(config):
    tag='vxlb-nfq:'+identity(config)
    for chain in ['OUTPUT','INPUT']:
        for row in iptables('-S',chain).stdout.splitlines():
            parts=shlex.split(row)
            if parts[:2]!=['-A',chain] or '--comment' not in parts:continue
            index=parts.index('--comment')
            if index+1<len(parts) and parts[index+1]==tag:
                iptables('-D',*parts[1:])
    # Prove absence even if the engine died; never require an active queue for cleanup.
    for chain in ['OUTPUT','INPUT']:
        for row in iptables('-S',chain).stdout.splitlines():
            parts=shlex.split(row)
            if '--comment' in parts:
                index=parts.index('--comment')
                if index+1<len(parts) and parts[index+1]==tag:
                    raise RuntimeError('Owned queue rule remains after removal')
    return {'removed':True}


if __name__=='__main__':
    action,path=sys.argv[1:]
    with open(path) as source:config=json.load(source)
    result={'apply':apply,'remove':remove,'status':inspect}[action](config)
    print(json.dumps(result),flush=True)
