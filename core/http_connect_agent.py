"""Bounded authenticated HTTP/1.1 CONNECT carrier for the managed mTLS relay.

The CONNECT authority is a fixed per-link identity; it never selects a remote
host. HTTPS additionally verifies dedicated client/server certificates. This
agent carries bytes and cannot choose application destinations.
"""
import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import ssl
import struct
import time

HEADER_LIMIT = 8192


def validate(config):
    if config['role'] not in ['client', 'server']:
        raise ValueError('Invalid HTTP carrier role')
    if not re.fullmatch(r'[0-9a-f]{32}', config['id']) or not re.fullmatch(r'[0-9a-f]{64}', config['token']):
        raise ValueError('Invalid HTTP carrier identity')
    ipaddress.IPv4Address(config['listen_host'])
    for field in (['listen_port', 'backend_port'] if config['role']=='server' else ['listen_port', 'remote_port']):
        if not str(config[field]).isdigit() or not 1 <= int(config[field]) <= 65535:
            raise ValueError('Invalid HTTP carrier port')
    if config['role']=='client':
        ipaddress.IPv4Address(config['remote_host'])
    if not 1 <= int(config.get('max_connections',128)) <= 512:
        raise ValueError('Invalid HTTP carrier concurrency limit')
    if not isinstance(config.get('tls'), bool):
        raise ValueError('Explicit HTTP/HTTPS transport is required')
    return config


def authority(config):
    return 'link-'+config['id']+':443'


def signature(config, stamp, nonce):
    message=f'CONNECT|{config["id"]}|{stamp}|{nonce}'.encode('ascii')
    return hmac.new(bytes.fromhex(config['token']), message, hashlib.sha256).hexdigest()


def request(config):
    stamp=str(int(time.time()));nonce=secrets.token_hex(16)
    auth=f'LDBP {stamp}:{nonce}:{signature(config,stamp,nonce)}'
    target=authority(config)
    return f'CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {auth}\r\n\r\n'.encode('ascii')


def parse_headers(data):
    if len(data)>HEADER_LIMIT or not data.endswith(b'\r\n\r\n'):
        raise ValueError('HTTP header limit exceeded')
    lines=data[:-4].decode('ascii').split('\r\n')
    if len(lines)>64:
        raise ValueError('Too many HTTP fields')
    fields={}
    for line in lines[1:]:
        key,separator,value=line.partition(':')
        if not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",key):
            raise ValueError('Invalid HTTP field')
        key=key.lower()
        if key in fields or '\r' in value or '\n' in value:
            raise ValueError('Ambiguous HTTP fields')
        fields[key]=value.strip()
    if 'content-length' in fields or 'transfer-encoding' in fields:
        raise ValueError('CONNECT cannot carry an HTTP message body')
    return lines[0],fields


def authorized(config, data, seen):
    try:
        line,fields=parse_headers(data)
        if line!=f'CONNECT {authority(config)} HTTP/1.1' or fields.get('host')!=authority(config):
            return False
        match=re.fullmatch(r'LDBP ([0-9]{1,12}):([0-9a-f]{32}):([0-9a-f]{64})',fields.get('proxy-authorization',''))
        if not match:
            return False
        stamp,nonce,digest=match.groups();now=time.time()
        if abs(now-int(stamp))>60 or not hmac.compare_digest(signature(config,stamp,nonce),digest):
            return False
        for key,expires in list(seen.items()):
            if expires<now:
                seen.pop(key,None)
        if nonce in seen or len(seen)>=4096:
            return False
        seen[nonce]=now+120
        return True
    except (ValueError,UnicodeError):
        return False


def tls_context(config, server):
    if not config['tls']:
        return None
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.verify_mode=ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=config['peer_cert'])
    context.load_cert_chain(config['cert'],config['key'])
    context.set_alpn_protocols(['http/1.1'])
    return context


def tcp_socket():
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if hasattr(socket,'TCP_MAXSEG'):
        sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_MAXSEG,1360)
    sock.setblocking(False)
    return sock


async def close(writer):
    if writer is not None:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(),2)
        except (OSError,TimeoutError,ssl.SSLError):
            pass


async def encode_stream(reader, writer):
    # Private post-CONNECT framing carries FIN even over TLS, whose asyncio
    # writer cannot half-close. Zero length ends only this logical direction.
    while True:
        data=await reader.read(65536)
        writer.write(struct.pack('!I',len(data))+data)
        await writer.drain()
        if not data:
            return


async def decode_stream(reader, writer):
    while True:
        size=struct.unpack('!I',await reader.readexactly(4))[0]
        if size>65536:
            raise ValueError('Carrier frame limit exceeded')
        if size==0:
            if writer.can_write_eof():
                writer.write_eof()
                await writer.drain()
            return
        writer.write(await reader.readexactly(size))
        await writer.drain()


async def bridge(left_reader,left_writer,right_reader,right_writer,server=False):
    if server:
        operations=[decode_stream(left_reader,right_writer),encode_stream(right_reader,left_writer)]
    else:
        operations=[encode_stream(left_reader,right_writer),decode_stream(right_reader,left_writer)]
    tasks=[asyncio.create_task(operation) for operation in operations]
    try:
        # Normal directional EOF must not impose a response deadline. Actual
        # errors cancel the remaining direction and close the connection.
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done():task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)


async def open_remote(config, context):
    sock=tcp_socket()
    try:
        await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock,(config['remote_host'],int(config['remote_port']))),10)
        options=dict(ssl=context,server_hostname=config.get('server_name','ldbp-http'),ssl_handshake_timeout=8) if context else {}
        result=await asyncio.wait_for(asyncio.open_connection(sock=sock,limit=HEADER_LIMIT,**options),10)
        if context and result[1].get_extra_info('ssl_object').selected_alpn_protocol()!='http/1.1':
            await close(result[1]);raise RuntimeError('HTTPS carrier ALPN mismatch')
        return result
    except BaseException:
        sock.close();raise


async def run(config):
    validate(config)
    is_server=config['role']=='server'
    context=tls_context(config,is_server)
    seen={};active=0

    async def connection(reader,writer):
        nonlocal active
        remote_writer=None
        if active>=int(config.get('max_connections',128)):
            await close(writer);return
        active+=1
        try:
            if is_server:
                data=await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'),5)
                if not authorized(config,data,seen):
                    writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: LDBP realm="ldbp"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                    await writer.drain();return
                remote_reader,remote_writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',int(config['backend_port'])),5)
                writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                await writer.drain()
            else:
                remote_reader,remote_writer=await open_remote(config,context)
                remote_writer.write(request(config));await remote_writer.drain()
                data=await asyncio.wait_for(remote_reader.readuntil(b'\r\n\r\n'),8)
                line,_=parse_headers(data)
                if line!='HTTP/1.1 200 Connection Established':
                    raise RuntimeError('HTTP carrier authorization failed')
            await bridge(reader,writer,remote_reader,remote_writer,server=is_server)
        except (OSError,ValueError,RuntimeError,TimeoutError,ssl.SSLError,asyncio.IncompleteReadError,asyncio.LimitOverrunError):
            pass
        finally:
            active-=1
            await close(remote_writer);await close(writer)

    listener=tcp_socket()
    try:
        listener.bind((config['listen_host'],int(config['listen_port'])))
        listener.listen(128)
        options=dict(ssl=context,ssl_handshake_timeout=8) if is_server and context else {}
        server=await asyncio.start_server(connection,sock=listener,limit=HEADER_LIMIT,**options)
        print('READY',flush=True)
        async with server:
            await server.serve_forever()
    finally:
        listener.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('config');args=parser.parse_args()
    with open(args.config) as source:settings=json.load(source)
    asyncio.run(run(settings))
