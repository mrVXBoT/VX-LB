"""Real local CONNECT + mTLS + TCP/UDP chain; no firewall or systemd is modified."""
from contextlib import ExitStack,contextmanager
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import threading
import time
import pytest
from core import http_transport as http
from core.private_link_health import PROBE
from core.slipstream_deploy import identity_material


def free_ports(count):
    ports=set()
    while len(ports)<count:
        with socket.socket() as tcp,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            tcp.bind(('127.0.0.1',0));port=tcp.getsockname()[1]
            if port in ports:continue
            try:udp.bind(('127.0.0.1',port))
            except OSError:continue
            ports.add(port)
    return list(ports)


@contextmanager
def echo(port, delayed=False):
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            collected=b''
            while True:
                data=self.request.recv(65536)
                if not data:
                    if delayed:
                        time.sleep(2.5)
                        self.request.sendall(b'reply:'+collected)
                    return
                if delayed:collected+=data
                else:self.request.sendall(data)
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            self.server.seen_peers.add(self.client_address)
            data=self.request[0]
            if data.startswith(b'duplex:'):
                self.request[1].sendto(b'first:'+data,self.client_address)
                self.request[1].sendto(b'second:'+data,self.client_address)
            else:self.request[1].sendto(data,self.client_address)
    servers=[];threads=[]
    for base,handler in [(socketserver.ThreadingTCPServer,TCP),(socketserver.ThreadingUDPServer,UDP)]:
        class Server(base):allow_reuse_address=True;daemon_threads=True
        server=Server(('127.0.0.1',port),handler);server.seen_peers=set();servers.append(server)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread)
    try:yield servers[1]
    finally:
        for server in servers:server.shutdown();server.server_close()
        for thread in threads:thread.join(timeout=2)


@contextmanager
def process(script,config,host,port):
    child=subprocess.Popen([sys.executable,'-u',str(script),str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        for _ in range(100):
            if child.poll() is not None:raise AssertionError(child.stderr.read())
            try:
                with socket.create_connection((host,port),timeout=0.1):break
            except OSError:time.sleep(0.05)
        else:raise AssertionError('Managed relay did not open its owned listener')
        yield
    except BaseException as error:
        child.terminate()
        try:
            _,diagnostic=child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill();_,diagnostic=child.communicate(timeout=3)
        if diagnostic:error.add_note(diagnostic)
        raise
    finally:
        child.terminate()
        try:child.wait(timeout=3)
        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)


def configuration(tmp_path,mode):
    app,public,backend,carrier,probe=free_ports(5)
    node=dict(ip='127.0.0.2',node_name='http-'+('1'*32),transport=mode,engine=mode,
              http_connect=dict(id='1'*32,token='2'*64,public_port=public,relay_backend_port=backend,
                                carrier_local_port=carrier,probe_port=probe,security=identity_material('vxlb-http')))
    pool=dict(client_ports=[str(app)],kharej_server={'ip':'127.0.0.1'})
    config=http.plan(node,pool);base=config['base']
    for files in [config['server_files'],config['client_files']]:
        for path,text in files.items():
            if path.startswith('/etc/systemd/system/'):continue
            local=tmp_path/Path(path).name
            if path.endswith('.json'):text=text.replace(base,str(tmp_path))
            local.write_text(text);local.chmod(0o600)
    return app,public,backend,carrier,probe


@pytest.mark.parametrize('mode',['http','https'])
def test_complete_http_mtls_chain_carries_large_tcp_and_udp(tmp_path,mode):
    app,public,backend,carrier,probe=configuration(tmp_path,mode)
    path=tmp_path/'client.json';client=json.loads(path.read_text())
    # Both roles run on one host here: distinct loopback IPs avoid port overlap.
    client.update(listen_host='127.0.0.2',loopback_ports=[]);path.write_text(json.dumps(client))
    with ExitStack() as stack:
        for port in [app,probe]:stack.enter_context(echo(port))
        for script,config,host,port in [('relay.py','server.json','127.0.0.1',backend),
                                      ('carrier.py','server-carrier.json','127.0.0.1',public),
                                      ('carrier.py','client-carrier.json','127.0.0.1',carrier),
                                      ('relay.py','client.json','127.0.0.2',app)]:
            stack.enter_context(process(tmp_path/script,tmp_path/config,host,port))
        for port in [app,probe]:
            result=subprocess.run([sys.executable,'-c',PROBE,'127.0.0.2',str(port),'local-http-nonce',''],capture_output=True,text=True,timeout=25)
            assert result.returncode==0,result.stderr
            assert json.loads(result.stdout)['protocols']==['tcp','udp']


def test_probe_listener_is_loopback_only_and_separate_from_app_listeners(tmp_path):
    app,public,backend,carrier,probe=configuration(tmp_path,'http')
    path=tmp_path/'client.json';client=json.loads(path.read_text());client['listen_host']='127.0.0.2';path.write_text(json.dumps(client))
    with process(tmp_path/'relay.py',path,'127.0.0.2',app):
        with socket.create_connection(('127.0.0.1',probe),timeout=1):pass
        with pytest.raises(OSError):socket.create_connection(('127.0.0.2',probe),timeout=0.2)


@pytest.mark.parametrize('mode',['http','https'])
def test_udp_session_keeps_backend_source_and_forwards_multiple_replies(tmp_path,mode):
    app,public,backend,carrier,probe=configuration(tmp_path,mode)
    path=tmp_path/'client.json';client=json.loads(path.read_text());client.update(listen_host='127.0.0.2',loopback_ports=[]);path.write_text(json.dumps(client))
    with ExitStack() as stack:
        target=stack.enter_context(echo(app))
        for script,config,host,port in [('relay.py','server.json','127.0.0.1',backend),
                                      ('carrier.py','server-carrier.json','127.0.0.1',public),
                                      ('carrier.py','client-carrier.json','127.0.0.1',carrier),
                                      ('relay.py','client.json','127.0.0.2',app)]:
            stack.enter_context(process(tmp_path/script,tmp_path/config,host,port))
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as source:
            source.settimeout(2);source.connect(('127.0.0.2',app))
            for index in range(4):
                data=b'duplex:'+str(index).encode();source.send(data)
                assert source.recv(100)==b'first:'+data
                assert source.recv(100)==b'second:'+data
            assert len(target.seen_peers)==1
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as other:
                other.settimeout(2);other.connect(('127.0.0.2',app))
                other.send(b'duplex:other')
                assert other.recv(100)==b'first:duplex:other'
                assert other.recv(100)==b'second:duplex:other'
                source.send(b'duplex:original')
                assert source.recv(100)==b'first:duplex:original'
                assert source.recv(100)==b'second:duplex:original'
            assert len(target.seen_peers)==2


@pytest.mark.parametrize('mode',['http','https'])
def test_application_half_close_gets_delayed_response_through_complete_chain(tmp_path,mode):
    app,public,backend,carrier,probe=configuration(tmp_path,mode)
    path=tmp_path/'client.json';client=json.loads(path.read_text());client.update(listen_host='127.0.0.2',loopback_ports=[]);path.write_text(json.dumps(client))
    with ExitStack() as stack:
        stack.enter_context(echo(app,delayed=True))
        for script,config,host,port in [('relay.py','server.json','127.0.0.1',backend),
                                      ('carrier.py','server-carrier.json','127.0.0.1',public),
                                      ('carrier.py','client-carrier.json','127.0.0.1',carrier),
                                      ('relay.py','client.json','127.0.0.2',app)]:
            stack.enter_context(process(tmp_path/script,tmp_path/config,host,port))
        with socket.create_connection(('127.0.0.2',app),timeout=7) as source:
            source.sendall(b'finished');source.shutdown(socket.SHUT_WR)
            received=b''
            while True:
                chunk=source.recv(65536)
                if not chunk:break
                received+=chunk
            assert received==b'reply:finished'
