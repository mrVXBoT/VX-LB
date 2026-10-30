"""Bounded outbound packet evidence for five managed packet profiles.

Standalone stdlib agent. Captures only the configured local/peer carrier flow,
keeps bounded handshake prefixes in memory and returns sanitized observations.
No packet payload, authorization header or private material is logged/saved.
"""
import ipaddress
import json
import re
import select
import socket
import struct
import sys
import time

MODES={'fake-sni','split-tls','hop-ttl-injection','tcp-state-desync','l7-header-mutation'}
PREFIX=8192


def decode(frame):
    if len(frame)<54:return None
    offset=14;kind=int.from_bytes(frame[12:14],'big')
    for _ in range(2):
        if kind not in (0x8100,0x88a8):break
        if len(frame)<offset+4:return None
        kind=int.from_bytes(frame[offset+2:offset+4],'big');offset+=4
    if kind!=0x0800:return None
    ip=frame[offset:]
    if len(ip)<40 or ip[0]>>4!=4 or ip[9]!=6:return None
    hlen=(ip[0]&15)*4;total=int.from_bytes(ip[2:4],'big')
    if hlen<20 or total<hlen+20 or total>len(ip) or int.from_bytes(ip[6:8],'big')&0x3fff:return None
    tcp=ip[hlen:total];thlen=(tcp[12]>>4)*4
    if thlen<20 or thlen>len(tcp):return None
    md5=False;index=20
    while index<thlen:
        kind=tcp[index]
        if kind==0:break
        if kind==1:index+=1;continue
        if index+1>=thlen or tcp[index+1]<2 or index+tcp[index+1]>thlen:break
        if kind==19 and tcp[index+1]==18:md5=True
        index+=tcp[index+1]
    sport,dport,seq,ack=struct.unpack('!HHII',tcp[:12])
    return dict(source=socket.inet_ntoa(ip[12:16]),destination=socket.inet_ntoa(ip[16:20]),
                sport=sport,dport=dport,seq=seq,flags=tcp[13],urgent=int.from_bytes(tcp[18:20],'big'),
                ttl=ip[8],md5=md5,payload=tcp[thlen:])


def hello_names(payload):
    """Read the actual SNI extension, never a coincidental payload substring."""
    try:
        if len(payload)<9 or payload[0]!=22 or payload[1]!=3:return set()
        size=int.from_bytes(payload[3:5],'big')
        if size>18432 or len(payload)<5+size:return set()
        body=payload[5:5+size]
        if body[0]!=1 or int.from_bytes(body[1:4],'big')+4>len(body):return set()
        cursor=38
        cursor+=1+body[cursor]
        cursor+=2+int.from_bytes(body[cursor:cursor+2],'big')
        cursor+=1+body[cursor]
        extension_size=int.from_bytes(body[cursor:cursor+2],'big');cursor+=2
        end=cursor+extension_size
        if end>len(body):return set()
        names=set()
        while cursor+4<=end:
            kind=int.from_bytes(body[cursor:cursor+2],'big');length=int.from_bytes(body[cursor+2:cursor+4],'big');cursor+=4
            if cursor+length>end:return set()
            if kind==0:
                data=body[cursor:cursor+length]
                if len(data)<2 or int.from_bytes(data[:2],'big')!=len(data)-2:return set()
                index=2
                while index+3<=len(data):
                    name_kind=data[index];name_size=int.from_bytes(data[index+1:index+3],'big');index+=3
                    if index+name_size>len(data):return set()
                    if name_kind==0:names.add(data[index:index+name_size].lower())
                    index+=name_size
            cursor+=length
        return names
    except (IndexError,ValueError):return set()


def relative(seq,base):return (seq-base+(1<<31))%(1<<32)-(1<<31)


class Observer:
    def __init__(self,config):
        self.mode=config['profile']
        if self.mode not in MODES:raise ValueError('Unsupported wire profile')
        self.local=str(ipaddress.IPv4Address(config['local']))
        self.peer=str(ipaddress.IPv4Address(config['peer']))
        value=config['carrier_port']
        if isinstance(value,bool) or not str(value).isdigit() or not 1<=int(value)<=65535:raise ValueError('Invalid wire carrier port')
        self.port=int(value);identity=config['id']
        if not re.fullmatch(r'[0-9a-f]{32}',identity):raise ValueError('Invalid wire identity')
        domain=config.get('fake_sni','www.shaparak.ir')
        if not isinstance(domain,str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',domain):raise ValueError('Invalid fake SNI')
        self.domain=domain.lower().encode()
        if self.mode=='hop-ttl-injection' and self.domain==b'vxlb-http':raise ValueError('Fake SNI must differ from the authenticated carrier identity')
        self.authority=('CONNECT link-'+identity+':443 HTTP/1.1\r\n').encode()
        self.flows={};self.packets=0;self.limited=False
        self.fake_md5=False;self.fake_ttl=set();self.urg=False;self.fake_rst=False;self.hostcase=False
        self.record_lengths=[];self.disordered=False

    def feed(self,frame):
        packet=decode(frame)
        if packet is None or packet['source']!=self.local or packet['destination']!=self.peer or packet['dport']!=self.port:return
        self.packets+=1
        if self.packets>5000:self.limited=True;return
        port=packet['sport'];flags=packet['flags']
        if flags&2 and not flags&16:
            if port not in self.flows:
                if len(self.flows)>=16:self.limited=True;return
                self.flows[port]=dict(base=(packet['seq']+1)%(1<<32),data=bytearray(PREFIX),mask=bytearray(PREFIX),offsets=set(),last=None,small=False,reordered=False)
        flow=self.flows.get(port)
        if flow is None:return  # Existing connections cannot supply fresh handshake proof.
        payload=packet['payload'];position=relative(packet['seq'],flow['base'])
        if self.domain in hello_names(payload):
            if packet['md5']:self.fake_md5=True
            if 3<=packet['ttl']<=14:self.fake_ttl.add(packet['ttl'])
        if flags&32 and packet['urgent']>0 and payload:self.urg=True
        if flags&4 and -11000<=position<=-9000:self.fake_rst=True
        if self.mode not in ['split-tls','l7-header-mutation'] or not payload:return
        if 0<=position<PREFIX:
            if position==0 and len(payload)==2 and payload==b'\x16\x03':flow['small']=True
            if position not in flow['offsets']:
                if flow['last'] is not None and position<flow['last']:flow['reordered']=True
                flow['offsets'].add(position);flow['last']=position
            for index,value in enumerate(payload[:PREFIX-position]):
                where=position+index
                if not flow['mask'][where]:flow['data'][where]=value;flow['mask'][where]=1
            try:complete=flow['mask'].index(0)
            except ValueError:complete=PREFIX
            prefix=bytes(flow['data'][:complete])
            if self.mode=='l7-header-mutation':
                if prefix.startswith(self.authority) and b'\r\nhOsT:' in prefix:self.hostcase=True
            else:
                lengths=[];bodies=b'';cursor=0
                while cursor+5<=len(prefix) and prefix[cursor]==22 and prefix[cursor+1]==3:
                    size=int.from_bytes(prefix[cursor+3:cursor+5],'big')
                    if size>18432 or cursor+5+size>len(prefix):break
                    lengths.append(size);bodies+=prefix[cursor+5:cursor+5+size];cursor+=5+size
                if len(lengths)>=2 and len(bodies)>=4 and bodies[0]==1 and len(bodies)>=4+int.from_bytes(bodies[1:4],'big'):
                    self.record_lengths=lengths[:4]
                    if flow['small'] and flow['reordered']:self.disordered=True

    def result(self):
        passed={'fake-sni':self.fake_md5,'hop-ttl-injection':bool(self.fake_ttl),
                'tcp-state-desync':self.urg and self.fake_rst,'l7-header-mutation':self.hostcase,
                'split-tls':bool(self.record_lengths) and self.record_lengths[0]==2,}[self.mode]
        return dict(profile=self.mode,passed=bool(passed and not self.limited),observations=dict(
            packets=self.packets,fake_sni_md5=self.fake_md5,fake_sni_ttl=sorted(self.fake_ttl),
            urgent_data=self.urg,out_of_window_rst=self.fake_rst,host_header_mutated=self.hostcase,
            client_hello_records=self.record_lengths,tcp_reordered=self.disordered,capture_limit=self.limited))


def capture(config):
    observer=Observer(config);duration=config.get('duration',20)
    if isinstance(duration,bool) or not str(duration).isdigit() or not 1<=int(duration)<=20:raise ValueError('Invalid capture duration')
    deadline=time.monotonic()+int(duration)
    with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0003)) as listener:
        print('READY',flush=True)
        while time.monotonic()<deadline:
            ready,_,_=select.select([listener,sys.stdin],[],[],.2)
            if sys.stdin in ready:
                sys.stdin.buffer.read(1);break
            if listener in ready:
                frame,address=listener.recvfrom(65535)
                if address[2]==socket.PACKET_OUTGOING:observer.feed(frame)
    return observer.result()


if __name__=='__main__':
    with open(sys.argv[1]) as source:configuration=json.load(source)
    print(json.dumps(capture(configuration)),flush=True)
