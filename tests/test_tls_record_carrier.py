"""Actual mTLS handshake across record splitting; local foundation, no VPS claim."""
import asyncio
import json
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import pytest
from core import tls_record_carrier as carrier
from core.slipstream_deploy import identity_material


def record(body,kind=22):return bytes([kind,3,1])+len(body).to_bytes(2,'big')+body


def test_client_hello_handshake_bytes_are_preserved_across_two_records():
    body=b'\x01\x00\x00\x08'+b'12345678';source=record(body)
    result=carrier.split_hello(source[:5],body)
    assert result[:5]==record(body[:2])[:5]
    assert result[5:7]==body[:2]
    assert result[7:12]==record(body[2:])[:5]
    assert result[12:]==body[2:]
    assert len(result)==len(source)+5


def test_encrypted_records_remain_byte_identical():
    body=b'encrypted TLS application data';source=record(body,23)
    assert carrier.split_hello(source[:5],body)==source


@pytest.mark.parametrize('data',[b'\x16\x03\x03\xff\xff',b'\x16\x03'])
def test_bad_or_truncated_header_fails_before_body_forwarding(data):
    async def check():
        reader=asyncio.StreamReader();reader.feed_data(data);reader.feed_eof()
        class Writer:
            def write(self,data):raise AssertionError('Invalid record was forwarded')
        with pytest.raises(ValueError):await carrier.forward_records(reader,Writer())
    asyncio.run(check())


def test_real_mtls_peer_receives_two_hello_records_and_exact_64kib(tmp_path):
    material=identity_material('vxlb-split')
    paths={}
    for name,value in material.items():
        path=tmp_path/name;path.write_text(value);path.chmod(0o600);paths[name]=str(path)
    server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version=ssl.TLSVersion.TLSv1_3
    server_context.verify_mode=ssl.CERT_REQUIRED
    server_context.load_verify_locations(cafile=paths['client_cert'])
    server_context.load_cert_chain(paths['server_cert'],paths['server_key'])
    observations=[];failures=[]
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.settimeout(5)
                deadline=time.monotonic()+5
                while True:
                    first=self.request.recv(12,socket.MSG_PEEK)
                    if len(first)>=12:break
                    if not first or time.monotonic()>deadline:raise RuntimeError('Incomplete hello capture')
                    time.sleep(.01)
                observations.append((first[:3],int.from_bytes(first[3:5],'big'),first[7:10],int.from_bytes(first[10:12],'big')))
                with server_context.wrap_socket(self.request,server_side=True) as secured:
                    while True:
                        data=secured.recv(65536)
                        if not data:return
                        secured.sendall(data)
            except BaseException as error:failures.append(error)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True;daemon_threads=True
    backend=Server(('127.0.0.1',0),Echo)
    thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
    with socket.socket() as allocation:
        allocation.bind(('127.0.0.1',0));port=allocation.getsockname()[1]
    path=tmp_path/'config.json';path.write_text(json.dumps(dict(listen_port=port,remote_host='127.0.0.1',remote_port=backend.server_address[1])))
    child=subprocess.Popen([sys.executable,'-u',carrier.__file__,str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        ready,_,_=select.select([child.stdout],[],[],8)
        assert ready and child.stdout.readline().strip()=='READY'
        context=ssl.create_default_context(cafile=paths['server_cert'])
        context.minimum_version=ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(paths['client_cert'],paths['client_key'])
        with socket.create_connection(('127.0.0.1',port),timeout=5) as raw:
            with context.wrap_socket(raw,server_hostname='vxlb-split') as secured:
                data=bytes(range(256))*256;secured.sendall(data);received=b''
                while len(received)<len(data):
                    chunk=secured.recv(65536)
                    if not chunk:break
                    received+=chunk
                assert received==data
        assert not failures
        assert len(observations)==1
        first,first_len,second,second_len=observations[0]
        assert first[0]==22 and first==second and first_len==2 and second_len>2
    finally:
        child.terminate()
        try:child.communicate(timeout=3)
        except subprocess.TimeoutExpired:child.kill();child.communicate(timeout=3)
        backend.shutdown();backend.server_close();thread.join(timeout=2)
