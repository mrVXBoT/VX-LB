"""Loopback-only TLS byte proxy that splits the initial ClientHello record.

TLS authentication and encryption remain at the original peers. This proxy
changes only plaintext handshake record boundaries, preserving handshake
bytes and leaving encrypted records untouched. Standalone stdlib agent.
"""
import argparse
import asyncio
import ipaddress
import json
import socket

MAX_RECORD = 18432


def split_hello(header, body, offset=2):
    if len(header)!=5 or int.from_bytes(header[3:5],'big')!=len(body):
        raise ValueError('Invalid TLS record length')
    if len(body)>MAX_RECORD:
        raise ValueError('TLS record exceeds limit')
    if header[0]!=22 or len(body)<4 or body[0]!=1:
        return header+body
    if not 1<=offset<len(body):
        raise ValueError('Invalid ClientHello split offset')
    prefix=header[:3]
    return prefix+offset.to_bytes(2,'big')+body[:offset]+prefix+(len(body)-offset).to_bytes(2,'big')+body[offset:]


def tcp_socket():
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if hasattr(socket,'TCP_MAXSEG'):
        sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_MAXSEG,1360)
    sock.setblocking(False)
    return sock


async def finish(writer):
    if writer.can_write_eof():
        writer.write_eof()
        await writer.drain()


async def forward_records(reader,writer):
    first=True
    while True:
        try:
            header=await asyncio.wait_for(reader.readexactly(5),10) if first else await reader.readexactly(5)
        except asyncio.IncompleteReadError as error:
            if error.partial:raise ValueError('Truncated TLS record header') from error
            await finish(writer);return
        size=int.from_bytes(header[3:5],'big')
        if size>MAX_RECORD or header[0] not in range(20,25) or header[1]!=3:
            raise ValueError('Invalid TLS record')
        body=await asyncio.wait_for(reader.readexactly(size),10) if first else await reader.readexactly(size)
        writer.write(split_hello(header,body) if first else header+body)
        first=False
        await writer.drain()


async def forward_bytes(reader,writer):
    while True:
        data=await reader.read(65536)
        if not data:
            await finish(writer);return
        writer.write(data)
        await writer.drain()


async def close(writer):
    if writer is None:return
    writer.close()
    try:await asyncio.wait_for(writer.wait_closed(),2)
    except (OSError,TimeoutError):pass


async def run(config):
    if config.get('listen_host','127.0.0.1')!='127.0.0.1':
        raise ValueError('TLS record helper must bind loopback')
    remote=str(ipaddress.IPv4Address(config['remote_host']))
    for field in ['listen_port','remote_port']:
        if not str(config[field]).isdigit() or not 1<=int(config[field])<=65535:
            raise ValueError('Invalid TLS helper port')
    limit=int(config.get('max_connections',128))
    if not 1<=limit<=512:raise ValueError('Invalid connection limit')
    active=0
    async def connection(reader,writer):
        nonlocal active
        target=None;tasks=[]
        if active>=limit:
            await close(writer);return
        active+=1
        sock=None
        try:
            sock=tcp_socket()
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock,(remote,int(config['remote_port']))),10)
            target_reader,target=await asyncio.open_connection(sock=sock)
            sock=None  # Stream writer now owns the socket.
            tasks=[asyncio.create_task(forward_records(reader,target)),asyncio.create_task(forward_bytes(target_reader,writer))]
            await asyncio.gather(*tasks)
        except (OSError,ValueError,TimeoutError,asyncio.IncompleteReadError):
            pass
        finally:
            for task in tasks:
                if not task.done():task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
            if sock is not None:sock.close()
            await close(target);await close(writer)
            active-=1
    listener=tcp_socket()
    try:
        listener.bind(('127.0.0.1',int(config['listen_port'])));listener.listen(128)
        server=await asyncio.start_server(connection,sock=listener)
        print('READY',flush=True)
        async with server:await server.serve_forever()
    finally:listener.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('config');args=parser.parse_args()
    with open(args.config) as source:settings=json.load(source)
    asyncio.run(run(settings))
