"""Real local HTTP/HTTPS carriers and hostile CONNECT inputs, without claiming VPS acceptance."""
from contextlib import contextmanager
import json
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import sys
import threading
import time
import pytest
from core import http_connect_agent as agent
from core.slipstream_deploy import identity_material


def settings(role='server', **updates):
    value=dict(role=role,id='1'*32,token='2'*64,listen_host='127.0.0.1',listen_port=24001,
                backend_port=24002,remote_host='127.0.0.1',remote_port=24003,tls=False)
    value.update(updates);return value


def test_connect_authorization_is_bound_to_link_and_replay_protected():
    config=settings();seen={};data=agent.request(config)
    assert agent.authorized(config,data,seen)
    assert not agent.authorized(config,data,seen)
    assert not agent.authorized(settings(id='3'*32),data,{})


@pytest.mark.parametrize('change', [lambda raw:raw.replace(b'CONNECT link-',b'GET link-'),
                                    lambda raw:raw.replace(b'Host:',b'Content-Length: 1\r\nHost:'),
                                    lambda raw:raw.replace(b'Host:',b'Transfer-Encoding: chunked\r\nHost:'),
                                    lambda raw:raw.replace(b'Host:',b'Host: evil.example\r\nHost:'),
                                    lambda raw:raw[:-4]+b'\r\n folded: value\r\n\r\n'])
def test_ambiguous_or_wrong_connect_requests_fail_closed(change):
    config=settings()
    assert not agent.authorized(config,change(agent.request(config)),{})


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


@contextmanager
def process(tmp_path, name, config):
    path=tmp_path/(name+'.json');path.write_text(json.dumps(config))
    agent_path=Path(agent.__file__)
    child=subprocess.Popen([sys.executable,'-u',str(agent_path),str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        ready,_,_=select.select([child.stdout],[],[],8)
        assert ready and child.stdout.readline().strip()=='READY', 'Carrier process did not start'
        yield child
    finally:
        child.terminate()
        try:child.wait(timeout=3)
        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)


@pytest.fixture
def echo():
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            while True:
                chunk=self.request.recv(65536)
                if not chunk:return
                self.request.sendall(chunk)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True;daemon_threads=True
    server=Server(('127.0.0.1',0),Echo)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield server.server_address[1]
    finally:server.shutdown();server.server_close();thread.join(timeout=2)


def certificates(tmp_path):
    material=identity_material('vxlb-http')
    result={}
    for name,text in material.items():
        path=tmp_path/name;path.write_text(text);result[name]=str(path)
    return result


@pytest.mark.parametrize('tls', [False,True])
def test_real_64kib_bytes_cross_carrier_and_tls_is_verified(tmp_path,echo,tls):
    public,local=free_port(),free_port()
    material=certificates(tmp_path)
    server=settings(listen_port=public,backend_port=echo,tls=tls,cert=material['server_cert'],key=material['server_key'],peer_cert=material['client_cert'])
    client=settings('client',listen_port=local,remote_port=public,tls=tls,server_name='vxlb-http',cert=material['client_cert'],key=material['client_key'],peer_cert=material['server_cert'])
    with process(tmp_path,'server',server),process(tmp_path,'client',client):
        payload=bytes(range(256))*256
        with socket.create_connection(('127.0.0.1',local),timeout=5) as connection:
            connection.sendall(payload);received=b''
            while len(received)<len(payload):
                chunk=connection.recv(65536)
                if not chunk:break
                received+=chunk
            assert received==payload
    if tls:
        context=agent.tls_context(client,False)
        import ssl
        assert context.verify_mode==ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert context.minimum_version==ssl.TLSVersion.TLSv1_3


def test_unauthorized_request_never_chooses_an_arbitrary_backend(tmp_path,echo):
    public=free_port();server=settings(listen_port=public,backend_port=echo)
    with process(tmp_path,'server',server):
        for data in [agent.request(settings(token='3'*64)),agent.request(server).replace(agent.authority(server).encode(),b'example.com:443')]:
            with socket.create_connection(('127.0.0.1',public),timeout=5) as connection:
                connection.sendall(data)
                assert connection.recv(4096).startswith(b'HTTP/1.1 407 ')


@pytest.mark.parametrize('failure',['hostname','trust'])
def test_https_never_falls_back_when_peer_identity_is_wrong(tmp_path,echo,failure):
    public,local=free_port(),free_port()
    material=certificates(tmp_path)
    server=settings(listen_port=public,backend_port=echo,tls=True,cert=material['server_cert'],key=material['server_key'],peer_cert=material['client_cert'])
    client=settings('client',listen_port=local,remote_port=public,tls=True,server_name='vxlb-http',cert=material['client_cert'],key=material['client_key'],peer_cert=material['server_cert'])
    if failure=='hostname':
        client['server_name']='untrusted-name'
    else:
        wrong=tmp_path/'other-server.pem';wrong.write_text(identity_material('vxlb-http')['server_cert']);client['peer_cert']=str(wrong)
    with process(tmp_path,'server',server),process(tmp_path,'client',client):
        with socket.create_connection(('127.0.0.1',local),timeout=5) as connection:
            connection.sendall(b'must-not-cross')
            try:result=connection.recv(100)
            except (ConnectionResetError,BrokenPipeError):result=b''
            assert result==b''


@pytest.mark.parametrize('tls',[False,True])
def test_half_close_preserves_delayed_backend_response(tmp_path,tls):
    class Delayed(socketserver.BaseRequestHandler):
        def handle(self):
            payload=b''
            while True:
                chunk=self.request.recv(65536)
                if not chunk:break
                payload+=chunk
            time.sleep(2.5)
            self.request.sendall(b'reply:'+payload)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address=True;daemon_threads=True
    backend=Server(('127.0.0.1',0),Delayed)
    thread=threading.Thread(target=backend.serve_forever,daemon=True);thread.start()
    public,local=free_port(),free_port();material=certificates(tmp_path)
    server=settings(listen_port=public,backend_port=backend.server_address[1],tls=tls,cert=material['server_cert'],key=material['server_key'],peer_cert=material['client_cert'])
    client=settings('client',listen_port=local,remote_port=public,tls=tls,server_name='vxlb-http',cert=material['client_cert'],key=material['client_key'],peer_cert=material['server_cert'])
    try:
        with process(tmp_path,'server',server),process(tmp_path,'client',client):
            with socket.create_connection(('127.0.0.1',local),timeout=7) as connection:
                connection.sendall(b'finished');connection.shutdown(socket.SHUT_WR)
                response=b''
                while True:
                    chunk=connection.recv(100)
                    if not chunk:break
                    response+=chunk
                assert response==b'reply:finished'
    finally:
        backend.shutdown();backend.server_close();thread.join(timeout=2)
