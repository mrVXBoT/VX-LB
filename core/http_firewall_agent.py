"""Owned IPv4 ingress rules for HTTP CONNECT/mTLS services and loopback probes."""
import ipaddress
import json
import re
import shlex
import subprocess
import sys


def command(*args, allowed=(0,)):
    result=subprocess.run(['iptables','-w','5',*args],capture_output=True,text=True,timeout=15)
    if result.returncode not in allowed:raise RuntimeError(result.stderr.strip() or 'HTTP firewall command failed')
    return result


def tag(config):
    if not re.fullmatch(r'[0-9a-f]{32}',config['id']):raise ValueError('Invalid HTTP firewall identity')
    return 'ldbp-http:'+config['id']


def port(value):
    if not str(value).isdigit() or not 1<=int(value)<=65535:raise ValueError('Invalid HTTP firewall port')
    return str(value)


def rules(config):
    comment=['-m','comment','--comment',tag(config)]
    if config['role']=='server':
        peer=str(ipaddress.IPv4Address(config['peer']))
        yield ['-s',peer,'-p','tcp','--dport',port(config['public_port']),*comment,'-j','ACCEPT']
        loopback=[(config['relay_backend_port'],['tcp']), (config['probe_port'],['tcp','udp'])]
        loopback += [(value,['tcp','udp']) for value in config['ports']]
    elif config['role']=='client':
        for value in config['ports']:
            for proto in ['tcp','udp']:
                yield ['-p',proto,'--dport',port(value),*comment,'-j','ACCEPT']
        loopback=[(config['carrier_local_port'],['tcp']), (config['probe_port'],['tcp','udp'])]
        loopback += [(value,['tcp']) for value in config.get('extra_loopback_ports',[])]
    else:raise ValueError('Invalid HTTP firewall role')
    for value, protocols in loopback:
        for proto in protocols:
            yield ['-i','lo','-d','127.0.0.1','-p',proto,'--dport',port(value),*comment,'-j','ACCEPT']


def remove(config):
    identity=tag(config)
    for row in command('-S','INPUT').stdout.splitlines():
        parts=shlex.split(row)
        if parts[:2]!=['-A','INPUT'] or '--comment' not in parts:continue
        index=parts.index('--comment')
        if index+1<len(parts) and parts[index+1]==identity:command('-D',*parts[1:])


def apply(config):
    for rule in rules(config):
        result=command('-C','INPUT',*rule,allowed=(0,1))
        if result.returncode:command('-I','INPUT','1',*rule)


if __name__=='__main__':
    action,path=sys.argv[1:]
    with open(path) as source:config=json.load(source)
    {'apply':apply,'remove':remove}[action](config)
