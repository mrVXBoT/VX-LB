"""Pinned packet-engine inputs for the unfinished managed Spoof runtime.

These definitions do not enable deployment or prove evasion. Each profile
requires its declared carrier, scoped queue rules, real data verification and
wire evidence before it can be exposed as working in the frontend.
"""
from dataclasses import dataclass
from pathlib import PurePosixPath
import re

VERSION = 'v1.0.5.2'
LIBRARY_DIRECTORY = '/usr/local/lib/vxlb-nfqws2/'+VERSION
ARCHIVE_URL = 'https://github.com/bol-van/zapret2/releases/download/v1.0.5.2/zapret2-v1.0.5.2.tar.gz'
ARCHIVE_SHA256 = 'fb3bcf69e7d86b9fa2d60bd53c956ac06d9dcc3adf9392afd84865f1d94b1158'
COMPONENT_SHA256 = {
    'nfqws2': 'de1414b1e0f9a5659d438cddcb0c7e9099b4533bf5c8a3cf841c7bc7e5aa1473',
    'zapret-lib.lua': 'b67a470f23b00a8d6e732c4e5135a39b224511e0b71809d5f4616adf62674980',
    'zapret-antidpi.lua': '31c9dd75b0bd55e98e5306293f2be81e9d2ecadcbbf9157394ff37dcff7dc85a',
}
MODES = frozenset(['fake-sni','split-tls','hop-ttl-injection','tcp-state-desync','l7-header-mutation'])


@dataclass(frozen=True)
class PacketProfile:
    mode: str
    carrier: str
    incoming_queue: bool
    arguments: tuple


def number(value, minimum, maximum, name):
    if isinstance(value,bool) or not str(value).isdigit() or not minimum<=int(value)<=maximum:
        raise ValueError('Invalid '+name)
    return int(value)


def hostname(value):
    if not isinstance(value,str) or len(value)>253:
        raise ValueError('Invalid fake SNI')
    labels=value.split('.')
    if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in labels):
        raise ValueError('Invalid fake SNI')
    return value.lower()


def build(mode, queue, carrier_port, directory, fake_sni='www.shaparak.ir', ttl_delta=3):
    if mode not in MODES:raise ValueError('Packet profile runtime is not defined')
    queue=number(queue,1,65535,'queue');port=number(carrier_port,1,65535,'carrier port')
    delta=number(ttl_delta,1,15,'TTL delta');domain=hostname(fake_sni)
    if not isinstance(directory,str) or not directory.startswith('/') or any(c in directory for c in '\x00\r\n') or '..' in PurePosixPath(directory).parts:
        raise ValueError('Invalid packet-engine directory')
    base=directory.rstrip('/')
    args=['--qnum='+str(queue),'--debug=0','--fwmark=0x40000000','--lua-init=@'+base+'/zapret-lib.lua',
          '--lua-init=@'+base+'/zapret-antidpi.lua','--filter-l3=ipv4','--filter-tcp='+str(port)]
    incoming=mode in ['hop-ttl-injection','tcp-state-desync']
    carrier='http_connect' if mode=='l7-header-mutation' else 'tls_records' if mode=='split-tls' else 'tls'
    if mode=='tcp-state-desync':
        # OOB must cover the handshake and cannot be restricted to a detected
        # payload. The library cuts this lasting instance off after insertion.
        args+=['--in-range=-s1','--out-range=a','--payload=all','--lua-desync=oob:urp=2']
    else:
        args+=['--filter-l7=http' if carrier=='http_connect' else '--filter-l7=tls']
    args+=['--in-range=x','--out-range=-n6','--payload=http_req' if carrier=='http_connect' else '--payload=tls_client_hello']
    if mode=='fake-sni':
        args+=['--lua-desync=fake:blob=fake_default_tls:tls_mod=sni='+domain+':badsum:tcp_md5:repeats=2']
    elif mode=='split-tls':
        # Use the fake-disorder primitive so the packet engine emits an
        # observable out-of-order segment while the authenticated TLS stream
        # remains intact after the receiver reassembles it.
        args+=['--lua-desync=fakeddisorder:pos=midsld:pattern=fake_default_tls:badsum']
    elif mode=='hop-ttl-injection':
        args+=['--lua-desync=fake:blob=fake_default_tls:tls_mod=sni='+domain+':ip_ttl=6:ip_autottl='+str(delta)+',1-14:repeats=2']
    elif mode=='tcp-state-desync':
        args+=['--lua-desync=rst:badsum:tcp_seq=-10000:repeats=2']
    else:
        args+=['--lua-desync=http_hostcase:spell=hOsT']
    return PacketProfile(mode,carrier,incoming,tuple(args))
