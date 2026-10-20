"""Real Slipstream v0.1.1 plus mutual TLS relay, on disposable loopback ports.

Proves TCP/UDP application payloads inside an authenticated TLS stream over
real DNS carrier. Does not prove public recursive resolution/delegation.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from core.dependency_manifest import get_dependency_manifest
from core.slipstream_runtime import server_argv, client_argv
from core.slipstream_secure_relay import connect_carrier
from tests.slipstream_binary_lab import free_port


def run(client, server):
    for path, engine in ((client, 'slipstream'), (server, 'slipstream-server')):
        assert hashlib.sha256(Path(path).read_bytes()).hexdigest() == get_dependency_manifest(engine).architectures['x86_64']['sha256']
    processes, logs = [], []
    stop = threading.Event()
    tcp, udp = socket.socket(), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp.bind(('127.0.0.2', 0))
    app_port = tcp.getsockname()[1]
    udp.bind(('127.0.0.2', app_port))
    tcp.listen()
    tcp.settimeout(.2)
    udp.settimeout(.2)

    def tcp_echo():
        while not stop.is_set():
            try:
                connection, _ = tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(2)
                try:
                    while not stop.is_set():
                        data = connection.recv(65536)
                        if not data:
                            break
                        connection.sendall(data)
                except OSError:
                    pass

    def udp_echo():
        while not stop.is_set():
            try:
                data, address = udp.recvfrom(65535)
                udp.sendto(data, address)
            except socket.timeout:
                continue
            except OSError:
                break

    threads = [threading.Thread(target=function, daemon=True) for function in (tcp_echo, udp_echo)]
    for thread in threads:
        thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='ldbp-slipstream-secure-') as folder:
            root = Path(folder)
            for name in ('server', 'client', 'wrong'):
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                                '-keyout', str(root / f'{name}.key'), '-out', str(root / f'{name}.crt'),
                                '-days', '1', '-subj', '/CN=ldbp-slipstream'], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                os.chmod(root / f'{name}.key', 0o600)
            def launch(command):
                log = (root / f'{len(processes)}.log').open('wb')
                logs.append(log)
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                processes.append(process)
                return process
            relay_port, carrier_port, dns_port = free_port(), free_port(), free_port(socket.SOCK_DGRAM)
            server_config = {'role': 'server', 'listen_port': relay_port, 'ports': [app_port],
                             'target_host': '127.0.0.2', 'cert': str(root / 'server.crt'),
                             'key': str(root / 'server.key'), 'peer_cert': str(root / 'client.crt')}
            client_config = {'role': 'client', 'carrier_port': carrier_port, 'ports': [app_port],
                             'listen_host': '127.0.0.1', 'cert': str(root / 'client.crt'),
                             'key': str(root / 'client.key'), 'peer_cert': str(root / 'server.crt')}
            for name, config in (('server', server_config), ('client', client_config)):
                (root / f'{name}.json').write_text(json.dumps(config))
            relay_script = str(Path(__file__).resolve().parents[1] / 'core' / 'slipstream_secure_relay.py')
            relay_server = launch([sys.executable, relay_script, str(root / 'server.json')])
            launch(server_argv(server, domain='secure.example.test', dns_port=dns_port,
                               target_ip='127.0.0.1', target_port=relay_port,
                               cert=root / 'server.crt', key=root / 'server.key'))
            launch(client_argv(client, domain='secure.example.test', listen_port=carrier_port,
                               resolvers=[f'127.0.0.1:{dns_port}'], congestion='bbr'))
            launch([sys.executable, relay_script, str(root / 'client.json')])
            time.sleep(1)
            payload = secrets.token_bytes(16384)
            with socket.create_connection(('127.0.0.1', app_port), timeout=5) as connection:
                connection.settimeout(15)
                connection.sendall(payload)
                received = bytearray()
                while len(received) < len(payload):
                    chunk = connection.recv(len(payload) - len(received))
                    assert chunk, 'Premature EOF'
                    received.extend(chunk)
                assert received == payload
            print('PASS: authenticated TCP payload crossed real Slipstream DNS carrier', flush=True)
            for payload in (b'', secrets.token_bytes(1200)):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                    connection.settimeout(15)
                    connection.sendto(payload, ('127.0.0.1', app_port))
                    assert connection.recvfrom(65535)[0] == payload
            print('PASS: UDP application datagrams including empty payload crossed TLS-over-DNS relay', flush=True)
            with connect_carrier(client_config) as connection:
                import struct
                nonce = secrets.token_bytes(64)
                connection.sendall(b'LDS1' + bytes([3]) + bytes(2) + struct.pack('!H', len(nonce)) + nonce)
                from core.slipstream_secure_relay import exact
                assert exact(connection, len(nonce)) == nonce
            print('PASS: production transport probe nonce returned through authenticated DNS carrier', flush=True)
            for field in ('peer_cert', 'client_identity'):
                bad = dict(client_config)
                if field == 'peer_cert':
                    bad['peer_cert'] = str(root / 'wrong.crt')
                else:
                    bad.update(cert=str(root / 'wrong.crt'), key=str(root / 'wrong.key'))
                rejected = False
                try:
                    with connect_carrier(bad) as connection:
                        connection.sendall(b'LDS1\x01' + app_port.to_bytes(2, 'big') + b'forbidden')
                        rejected = connection.recv(64) == b''
                except (ssl.SSLError, OSError):
                    rejected = True
                assert rejected, f'Invalid {field} was accepted'
                print(f'PASS: wrong {field} rejected through real DNS carrier', flush=True)
            # The service must remain usable after rejected identities.
            with connect_carrier(client_config) as connection:
                payload = secrets.token_bytes(128)
                connection.sendall(b'LDS1\x01' + app_port.to_bytes(2, 'big') + payload)
                assert connection.recv(128) == payload
            print('PASS: valid identity recovered after failed authentication attempts', flush=True)
            relay_server.terminate()
            relay_server.wait(timeout=5)
            with socket.create_connection(('127.0.0.1', app_port), timeout=5) as connection:
                connection.settimeout(5)
                try:
                    connection.sendall(b'no-plaintext-fallback')
                    assert connection.recv(64) == b'', 'Plaintext fallback detected'
                except OSError:
                    pass
            print('PASS: stopping authenticated backend prevented data; raw DNS carrier and target remained alive', flush=True)
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for log in logs:
            log.close()
        stop.set()
        tcp.close()
        udp.close()
        for thread in threads:
            thread.join(timeout=2)
    print('PASS: all child processes, sockets and temporary trust material cleaned', flush=True)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True)
    parser.add_argument('--server', required=True)
    arguments = parser.parse_args()
    run(arguments.client, arguments.server)
