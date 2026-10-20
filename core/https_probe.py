"""Standalone loopback-only nonce echo/probe for managed HTTPS forwarding."""
import asyncio
import socket
import sys

class Echo(asyncio.DatagramProtocol):
    def connection_made(self,transport):self.transport=transport
    def __init__(self,done):self.done=done;self.seen=set()
    def datagram_received(self,data,address):
        self.transport.sendto(data,address);self.seen.add(data)
        if len(self.seen)>=8:self.done.set()

async def echo(port):
    async def handle(reader,writer):
        try:
            while data:=await reader.read(65536):writer.write(data);await writer.drain()
        finally:writer.close()
    done=asyncio.Event()
    asyncio.get_running_loop().add_reader(sys.stdin.fileno(),done.set)
    server=await asyncio.start_server(handle,'127.0.0.1',port)
    transport,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Echo(done),local_addr=('127.0.0.1',port))
    print('READY',flush=True)
    try:await asyncio.wait_for(done.wait(),45)
    finally:server.close();await server.wait_closed();transport.close()

def probe(port,nonce):
    payload=(nonce.encode()*1024)[:65536]
    with socket.create_connection(('127.0.0.1',port),timeout=4) as s:
        s.settimeout(4);s.sendall(payload);s.shutdown(socket.SHUT_WR);data=b''
        while len(data)<len(payload):
            chunk=s.recv(len(payload)-len(data))
            if not chunk:break
            data+=chunk
        if data!=payload:raise RuntimeError('TCP nonce mismatch')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(4);s.connect(('127.0.0.1',port))
        for i in range(8):
            packet=str(i).encode()+payload[:1000];s.send(packet)
            if s.recv(2048)!=packet:raise RuntimeError('UDP nonce mismatch')
    print('TCP+UDP nonce verified')

if __name__=='__main__':
    if sys.argv[1]=='echo':asyncio.run(echo(int(sys.argv[2])))
    elif sys.argv[1]=='probe':probe(int(sys.argv[2]),sys.argv[3])
    else:raise ValueError('Unknown action')
