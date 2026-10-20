"""Real upstream TCP/DNS transport test on loopback, not a DNS delegation test.

Requires explicit official binary paths. Generates disposable server keys.
Also records whether upstream accepts an unrelated self-signed certificate;
that observation must not be described as authenticated server identity.
"""
import argparse
import hashlib
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time

from core.dependency_manifest import get_dependency_manifest
from core.slipstream_runtime import client_argv, server_argv


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def run(client, server):
    for binary, manifest_name in ((client, 'slipstream'), (server, 'slipstream-server')):
        actual = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
        expected = get_dependency_manifest(manifest_name).architectures['x86_64']['sha256']
        if actual != expected:
            raise RuntimeError(f'Unverified binary: {binary}')
        print(f'Binary SHA-256 verified: {manifest_name} {actual}', flush=True)
    processes = []
    stop = threading.Event()
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    listener.settimeout(.2)
    backend = listener.getsockname()[1]

    def echo():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(1)
                try:
                    while not stop.is_set():
                        data = connection.recv(65536)
                        if not data:
                            break
                        connection.sendall(data)
                except (OSError, socket.timeout):
                    pass

    thread = threading.Thread(target=echo, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='vxlb-slipstream-lab-') as folder:
            root = Path(folder)
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(key), '-out', str(cert), '-days', '1',
                            '-subj', '/CN=unrelated-self-signed.invalid'], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.chmod(key, 0o600)
            dns_port, ingress = free_port(socket.SOCK_DGRAM), free_port()
            commands = [server_argv(server, domain='lab.example.test', dns_port=dns_port,
                                    target_ip='127.0.0.1', target_port=backend, cert=cert, key=key),
                        client_argv(client, domain='lab.example.test', listen_port=ingress,
                                    resolvers=[f'127.0.0.1:{dns_port}'], congestion='bbr')]
            handles = []
            try:
                for index, command in enumerate(commands):
                    handle = (root / f'{index}.log').open('wb')
                    handles.append(handle)
                    processes.append(subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT))
                    time.sleep(.3)
                payload = secrets.token_bytes(32768)
                deadline = time.monotonic() + 30
                failure = None
                while time.monotonic() < deadline:
                    try:
                        with socket.create_connection(('127.0.0.1', ingress), timeout=2) as connection:
                            connection.settimeout(5)
                            connection.sendall(payload)
                            received = bytearray()
                            while len(received) < len(payload):
                                chunk = connection.recv(len(payload) - len(received))
                                if not chunk:
                                    raise RuntimeError('Premature EOF')
                                received.extend(chunk)
                            assert received == payload, 'Data mismatch'
                        break
                    except (OSError, RuntimeError) as error:
                        failure = error
                        if any(process.poll() is not None for process in processes):
                            raise RuntimeError('Slipstream process exited') from error
                        time.sleep(.2)
                else:
                    raise RuntimeError(f'TCP challenge did not traverse Slipstream: {failure}')
                print('PASS: 32768 random bytes echoed through real client/server DNS carrier', flush=True)
                print('SECURITY LIMITATION: unrelated self-signed server certificate was accepted; server identity NOT authenticated', flush=True)
                processes[0].terminate()
                processes[0].wait(timeout=5)
                try:
                    with socket.create_connection(('127.0.0.1', ingress), timeout=2) as connection:
                        connection.settimeout(3)
                        connection.sendall(secrets.token_bytes(64))
                        if connection.recv(64):
                            raise RuntimeError('Data returned with server stopped')
                except OSError:
                    pass
                print('PASS: stopping real DNS server prevented fresh data while backend remained alive', flush=True)
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                for handle in handles:
                    handle.close()
                for path in sorted(root.glob('*.log')):
                    text = path.read_text(errors='replace')
                    print(f'{path.name}: {text[-1200:]}', flush=True)
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=2)
    print('PASS: child processes, backend and temporary certificate files cleaned', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--client', required=True)
    parser.add_argument('--server', required=True)
    args = parser.parse_args()
    run(args.client, args.server)
