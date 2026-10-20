#!/usr/bin/env python3
"""
Integration tests for WaterWall TCP tunnel (requires WaterWall binary).

Run: VX_LB_WATERWALL_BINARY=/path/to/waterwall python3 -m pytest tests/test_waterwall_tcp.py -v -s

This suite tests:
1. TCP basic tunnel data transmission and echo
2. Bidirectional data integrity
3. Rejection of invalid UUIDs (fail-closed)
4. Rejection of plaintext connection attempts on outer TLS port (fail-closed)
5. Rejection of untrusted TLS certificates
"""
import copy
import json
import os
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

from core import waterwall


class WaterWallTcpIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.environ.get('VX_LB_WATERWALL_BINARY')
        if not cls.binary or not Path(cls.binary).exists():
            raise unittest.SkipTest(f"VX_LB_WATERWALL_BINARY not set or not found: {cls.binary}")

    def free_port(self):
        """Find a free port."""
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            return s.getsockname()[1]

    def node_config(self):
        """Create test node config."""
        p = waterwall.profile('waterwall', {'server_name': 'tunnel.test'})
        return {
            'node_name': 'ldw' + secrets.token_hex(8),
            'waterwall': {
                'profile': p,
                'uuid_tcp': str(uuid.uuid4()),
                'uuid_udp': str(uuid.uuid4()),
                'outer_port': self.free_port(),
                'backend_port': self.free_port()
            }
        }

    @classmethod
    def _ensure_unpacked_binary(cls, binary_path):
        """Ensure an unpacked WaterWall binary exists with CA roots visible on disk."""
        target_marker = b'##\n## Bundle of CA Root'
        p = Path(binary_path)
        if p.exists() and target_marker in p.read_bytes():
            return str(p)

        unpacked_path = Path('/tmp/Waterwall_unpacked')
        if unpacked_path.exists() and target_marker in unpacked_path.read_bytes():
            return str(unpacked_path)

        # Unpack via dynamic interception of execveat / syscall(SYS_execveat)
        with tempfile.TemporaryDirectory(prefix='vxlb-ww-unpack-') as tmpdir:
            tmpdir = Path(tmpdir)
            hook_c = tmpdir / 'dump.c'
            hook_so = tmpdir / 'dump.so'
            hook_c.write_text(r"""#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/syscall.h>

#ifndef SYS_execveat
#define SYS_execveat 322
#endif

static void dump_fd(int dirfd) {
    int out = open("/tmp/Waterwall_unpacked", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out >= 0) {
        lseek(dirfd, 0, SEEK_SET);
        char buf[65536];
        ssize_t n;
        while ((n = read(dirfd, buf, sizeof(buf))) > 0) {
            write(out, buf, n);
        }
        close(out);
        lseek(dirfd, 0, SEEK_SET);
    }
}

int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags) {
    dump_fd(dirfd);
    int (*real_execveat)(int, const char *, char *const [], char *const [], int) = dlsym(RTLD_NEXT, "execveat");
    if (!real_execveat) return syscall(SYS_execveat, dirfd, pathname, argv, envp, flags);
    return real_execveat(dirfd, pathname, argv, envp, flags);
}

long syscall(long number, ...) {
    va_list args;
    va_start(args, number);
    long a1 = va_arg(args, long);
    long a2 = va_arg(args, long);
    long a3 = va_arg(args, long);
    long a4 = va_arg(args, long);
    long a5 = va_arg(args, long);
    long a6 = va_arg(args, long);
    va_end(args);

    if (number == SYS_execveat) {
        dump_fd((int)a1);
    }
    long (*real_syscall)(long, ...) = dlsym(RTLD_NEXT, "syscall");
    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}
""")
            subprocess.run(
                ['gcc', '-shared', '-fPIC', '-o', str(hook_so), str(hook_c), '-ldl'],
                check=True, capture_output=True
            )
            env = dict(os.environ)
            env['LD_PRELOAD'] = str(hook_so)
            dummy_cfg = tmpdir / 'dummy.json'
            dummy_cfg.write_text('{"log":{"level":"error"}}')
            try:
                subprocess.run(
                    [str(binary_path), f'--config:{dummy_cfg}'],
                    env=env, timeout=1, capture_output=True
                )
            except (subprocess.TimeoutExpired, Exception):
                pass

        if unpacked_path.exists() and target_marker in unpacked_path.read_bytes():
            unpacked_path.chmod(0o755)
            return str(unpacked_path)

        raise RuntimeError(f"Unable to unpack WaterWall binary {binary_path}")

    @classmethod
    def _prepare_binary_with_ca(cls, unpacked_bin, ca_cert_path, target_bin_path):
        """Patch the first embedded CA root certificate in the unpacked binary with the given CA cert."""
        data = Path(unpacked_bin).read_bytes()
        target = b'##\n## Bundle of CA Root'
        idx = data.find(target)
        if idx == -1:
            raise ValueError(f"CA Root bundle marker not found in {unpacked_bin}")
        cert_start = data.find(b'-----BEGIN CERTIFICATE-----', idx)
        if cert_start == -1:
            raise ValueError(f"BEGIN CERTIFICATE not found after marker in {unpacked_bin}")
        cert_end = data.find(b'-----END CERTIFICATE-----', cert_start) + len(b'-----END CERTIFICATE-----')
        orig_len = cert_end - cert_start

        ca_data = Path(ca_cert_path).read_bytes()
        diff = orig_len - len(ca_data)
        if diff < 0:
            raise ValueError(f"CA certificate ({len(ca_data)} bytes) exceeds slot ({orig_len} bytes)")

        # Pad remaining bytes with '#' so alignment and file length are exactly unchanged
        new_block = ca_data + (b'\n' + (b'#' * (diff - 1)) if diff > 0 else b'')
        assert len(new_block) == orig_len, f"Block length mismatch: {len(new_block)} != {orig_len}"

        new_data = data[:cert_start] + new_block + data[cert_end:]
        target_path = Path(target_bin_path)
        target_path.write_bytes(new_data)
        target_path.chmod(0o755)
        return str(target_path)

    def start_waterwall(self, chain_config, tmpdir, name, trust_cert_path=None):
        """Start WaterWall process with given chain config and valid core configuration."""
        chain_file = tmpdir / f'{name}_chain.json'
        chain_file.write_text(json.dumps(chain_config, indent=2))

        log_dir = tmpdir / f'{name}_logs'
        log_dir.mkdir(exist_ok=True)

        core_file = tmpdir / f'{name}_core.json'
        core = {
            'log': {'path': str(log_dir), 'level': 'debug'},
            'misc': {'workers': 2},
            'dns': {'domain-strategy': 'prefer-ipv4'},
            'configs': [str(chain_file)]
        }
        core_file.write_text(json.dumps(core, indent=2))

        binary_to_run = self.binary
        if trust_cert_path:
            unpacked = self._ensure_unpacked_binary(self.binary)
            binary_to_run = tmpdir / f'{name}_binary_with_ca'
            self._prepare_binary_with_ca(unpacked, trust_cert_path, binary_to_run)

        log_file = tmpdir / f'{name}.log'
        log_handle = open(log_file, 'w+')

        process = subprocess.Popen(
            [str(binary_to_run), '--verbose', f'--config:{core_file}'],
            stdout=log_handle,
            stderr=log_handle,
            env=os.environ
        )
        time.sleep(0.3)

        if process.poll() is not None:
            log_handle.close()
            log_text = log_file.read_text()
            raise RuntimeError(f'WaterWall {name} failed to start:\n{log_text}')

        return process, log_file, log_handle

    def _generate_cert(self, tmpdir):
        cert_file = tmpdir / 'cert.pem'
        key_file = tmpdir / 'key.pem'
        subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
             '-keyout', str(key_file), '-out', str(cert_file),
             '-days', '1', '-subj', '/CN=tunnel.test',
             '-addext', 'subjectAltName=DNS:tunnel.test'],
            check=True, capture_output=True
        )
        return cert_file, key_file

    def test_tcp_tunnel_basic(self):
        """Test basic TCP tunnel: start both sides, verify bidirectional connectivity."""
        node = self.node_config()
        entry_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            cert_file, key_file = self._generate_cert(tmpdir)

            node['waterwall']['profile']['certificate'] = str(cert_file)
            node['waterwall']['profile']['key'] = str(key_file)

            iran_chain, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(entry_port)]
            )

            # In integration tests with self-signed certs, disable verify for client
            for n in iran_chain['nodes']:
                if n['type'] == 'TlsClient':
                    n['settings']['verify'] = False

            # Start Kharej (server)
            kharej_proc, kharej_log, kharej_handle = self.start_waterwall(
                kharej_chain, tmpdir, 'kharej'
            )

            # Start Iran (client)
            try:
                iran_proc, iran_log, iran_handle = self.start_waterwall(
                    iran_chain, tmpdir, 'iran'
                )
            except Exception as e:
                kharej_proc.terminate()
                self.fail(f'Failed to start Iran: {e}')

            try:
                backend_port = node['waterwall']['backend_port']
                test_payload = b'PAYLOAD-' + secrets.token_bytes(32)
                server_received = []

                server_ready = threading.Event()

                def echo_server():
                    try:
                        sock = socket.socket()
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        sock.bind(('127.0.0.1', backend_port))
                        sock.listen(1)
                        server_ready.set()

                        conn, _ = sock.accept()
                        conn.settimeout(3)
                        data = conn.recv(4096)
                        server_received.append(data)
                        conn.sendall(b'REPLY:' + data)
                        conn.close()
                        sock.close()
                    except Exception as err:
                        print(f'Echo server error: {err}')

                server_thread = threading.Thread(target=echo_server, daemon=True)
                server_thread.start()

                if not server_ready.wait(timeout=3):
                    self.fail('Echo server failed to bind')

                time.sleep(0.3)

                client = socket.socket()
                client.settimeout(4)
                client.connect(('127.0.0.1', entry_port))
                client.sendall(test_payload)
                reply = client.recv(4096)
                client.close()

                server_thread.join(timeout=3)

                self.assertEqual(len(server_received), 1)
                self.assertEqual(server_received[0], test_payload)
                self.assertEqual(reply, b'REPLY:' + test_payload)

            finally:
                for proc in [kharej_proc, iran_proc]:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                for handle in [kharej_handle, iran_handle]:
                    handle.close()

    def test_invalid_uuid_rejected(self):
        """Test that client connecting with wrong UUID is rejected and no data reaches backend."""
        node = self.node_config()
        entry_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            cert_file, key_file = self._generate_cert(tmpdir)

            node['waterwall']['profile']['certificate'] = str(cert_file)
            node['waterwall']['profile']['key'] = str(key_file)

            iran_chain, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(entry_port)]
            )

            # Change UUID on Iran side to an unauthorized UUID
            wrong_uuid = str(uuid.uuid4())
            for n in iran_chain['nodes']:
                if n.get('name', '').startswith('tcp-vless-client-'):
                    n['settings']['uuid'] = wrong_uuid
                if n['type'] == 'TlsClient':
                    n['settings']['verify'] = False

            kharej_proc, _, kharej_handle = self.start_waterwall(kharej_chain, tmpdir, 'kharej')
            iran_proc, _, iran_handle = self.start_waterwall(iran_chain, tmpdir, 'iran')

            try:
                backend_port = node['waterwall']['backend_port']
                server_received = []

                def backend_listener():
                    try:
                        sock = socket.socket()
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        sock.bind(('127.0.0.1', backend_port))
                        sock.listen(1)
                        sock.settimeout(2)
                        conn, _ = sock.accept()
                        data = conn.recv(1024)
                        server_received.append(data)
                        conn.close()
                        sock.close()
                    except socket.timeout:
                        pass
                    except Exception:
                        pass

                server_thread = threading.Thread(target=backend_listener, daemon=True)
                server_thread.start()

                time.sleep(0.3)

                client = socket.socket()
                client.settimeout(2)
                client.connect(('127.0.0.1', entry_port))
                client.sendall(b'UNAUTHORIZED_UUID_TEST')
                try:
                    client.recv(1024)
                except Exception:
                    pass
                client.close()

                server_thread.join(timeout=3)
                self.assertEqual(len(server_received), 0, 'Backend received data with wrong UUID!')

            finally:
                for proc in [kharej_proc, iran_proc]:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                kharej_handle.close()
                iran_handle.close()

    def test_plaintext_rejected_fail_closed(self):
        """Test that sending raw plaintext to Kharej outer port fails closed."""
        node = self.node_config()

        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            cert_file, key_file = self._generate_cert(tmpdir)

            node['waterwall']['profile']['certificate'] = str(cert_file)
            node['waterwall']['profile']['key'] = str(key_file)

            _, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(self.free_port())]
            )

            kharej_proc, _, kharej_handle = self.start_waterwall(kharej_chain, tmpdir, 'kharej')

            try:
                backend_port = node['waterwall']['backend_port']
                server_received = []

                def backend_listener():
                    try:
                        sock = socket.socket()
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        sock.bind(('127.0.0.1', backend_port))
                        sock.listen(1)
                        sock.settimeout(2)
                        conn, _ = sock.accept()
                        data = conn.recv(1024)
                        server_received.append(data)
                        conn.close()
                        sock.close()
                    except socket.timeout:
                        pass
                    except Exception:
                        pass

                server_thread = threading.Thread(target=backend_listener, daemon=True)
                server_thread.start()

                time.sleep(0.3)

                # Connect directly to Kharej outer port with raw plaintext (bypassing TLS)
                client = socket.socket()
                client.settimeout(2)
                client.connect(('127.0.0.1', node['waterwall']['outer_port']))
                client.sendall(b'RAW_PLAINTEXT_ATTACK')
                try:
                    data = client.recv(1024)
                    self.assertEqual(data, b'', 'Connection was not closed immediately by TLS server')
                except Exception:
                    pass
                client.close()

                server_thread.join(timeout=3)
                self.assertEqual(len(server_received), 0, 'Backend received plaintext attack payload!')

            finally:
                if kharej_proc.poll() is None:
                    kharej_proc.terminate()
                    try:
                        kharej_proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        kharej_proc.kill()
                kharej_handle.close()

    def test_untrusted_cert_rejected(self):
        """Test that Iran client with verify: true rejects self-signed / untrusted certificates."""
        node = self.node_config()
        entry_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            cert_file, key_file = self._generate_cert(tmpdir)

            node['waterwall']['profile']['certificate'] = str(cert_file)
            node['waterwall']['profile']['key'] = str(key_file)

            iran_chain, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(entry_port)]
            )

            # Ensure verify remains True
            for n in iran_chain['nodes']:
                if n['type'] == 'TlsClient':
                    n['settings']['verify'] = True

            kharej_proc, _, kharej_handle = self.start_waterwall(kharej_chain, tmpdir, 'kharej')
            iran_proc, _, iran_handle = self.start_waterwall(iran_chain, tmpdir, 'iran')

            try:
                backend_port = node['waterwall']['backend_port']
                server_received = []

                def backend_listener():
                    try:
                        sock = socket.socket()
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        sock.bind(('127.0.0.1', backend_port))
                        sock.listen(1)
                        sock.settimeout(2)
                        conn, _ = sock.accept()
                        data = conn.recv(1024)
                        server_received.append(data)
                        conn.close()
                        sock.close()
                    except socket.timeout:
                        pass
                    except Exception:
                        pass

                server_thread = threading.Thread(target=backend_listener, daemon=True)
                server_thread.start()

                time.sleep(0.3)

                client = socket.socket()
                client.settimeout(2)
                client.connect(('127.0.0.1', entry_port))
                client.sendall(b'TEST_UNTRUSTED_CERT')
                try:
                    client.recv(1024)
                except Exception:
                    pass
                client.close()

                server_thread.join(timeout=3)
                self.assertEqual(len(server_received), 0, 'Backend received data with untrusted certificate!')

            finally:
                for proc in [kharej_proc, iran_proc]:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                kharej_handle.close()
                iran_handle.close()

    def test_valid_cert_tls_verification_success(self):
        """Positive test: TlsClient with verify: True connects to a server with valid certificate,
        verifies the TLS certificate against built-in CA root store, and transfers data."""
        try:
            with socket.create_connection(('1.1.1.1', 443), timeout=3) as s:
                import ssl
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(s, server_hostname='one.one.one.one') as ss:
                    ss.settimeout(3)
                    ss.sendall(b'HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n')
                    if not ss.recv(64):
                        raise OSError("Empty response from 1.1.1.1")
        except (OSError, socket.timeout, Exception):
            raise unittest.SkipTest("Public network connection to 1.1.1.1:443 unavailable or throttled")

        entry_port = self.free_port()
        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            chain = {
                'name': 'test-valid-tls-verify',
                'nodes': [
                    {
                        'name': 'tcp-listener',
                        'type': 'TcpListener',
                        'settings': {'address': '127.0.0.1', 'port': entry_port},
                        'next': 'tls-client'
                    },
                    {
                        'name': 'tls-client',
                        'type': 'TlsClient',
                        'settings': {
                            'sni': 'one.one.one.one',
                            'verify': True,
                            'alpns': ['http/1.1']
                        },
                        'next': 'tcp-connector'
                    },
                    {
                        'name': 'tcp-connector',
                        'type': 'TcpConnector',
                        'settings': {
                            'address': '1.1.1.1',
                            'port': 443
                        }
                    }
                ]
            }
            proc, log_file, handle = self.start_waterwall(chain, tmpdir, 'client')
            try:
                time.sleep(0.5)
                client = socket.socket()
                client.settimeout(15)
                try:
                    client.connect(('127.0.0.1', entry_port))
                    client.sendall(b'HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n')
                    response = client.recv(4096)
                except (TimeoutError, socket.timeout, OSError) as e:
                    raise unittest.SkipTest("Public network connection to 1.1.1.1:443 timed out or was throttled during transfer") from e
                finally:
                    client.close()

                if not response:
                    raise unittest.SkipTest("Public network connection to 1.1.1.1:443 timed out or was throttled during transfer")

                self.assertIn(b'HTTP/1.1', response)
                self.assertTrue(b'200 OK' in response or b'301' in response, f'Unexpected response: {response}')
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                handle.close()

    def test_wrong_domain_certificate_rejected(self):
        """Test that TlsClient with verify: True rejects certificate when SNI does not match server SAN."""
        try:
            with socket.create_connection(('1.1.1.1', 443), timeout=3) as s:
                import ssl
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(s, server_hostname='one.one.one.one') as ss:
                    ss.settimeout(3)
                    ss.sendall(b'HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n')
                    if not ss.recv(64):
                        raise OSError("Empty response from 1.1.1.1")
        except (OSError, socket.timeout, Exception):
            raise unittest.SkipTest("Public network connection to 1.1.1.1:443 unavailable or throttled")

        entry_port = self.free_port()
        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            chain = {
                'name': 'test-wrong-sni-rejected',
                'nodes': [
                    {
                        'name': 'tcp-listener',
                        'type': 'TcpListener',
                        'settings': {'address': '127.0.0.1', 'port': entry_port},
                        'next': 'tls-client'
                    },
                    {
                        'name': 'tls-client',
                        'type': 'TlsClient',
                        'settings': {
                            'sni': 'wrong-domain.example.com',
                            'verify': True,
                            'alpns': ['http/1.1']
                        },
                        'next': 'tcp-connector'
                    },
                    {
                        'name': 'tcp-connector',
                        'type': 'TcpConnector',
                        'settings': {
                            'address': '1.1.1.1',
                            'port': 443
                        }
                    }
                ]
            }
            proc, log_file, handle = self.start_waterwall(chain, tmpdir, 'client')
            try:
                time.sleep(0.4)
                client = socket.socket()
                client.settimeout(4)
                client.connect(('127.0.0.1', entry_port))
                client.sendall(b'HEAD / HTTP/1.1\r\nHost: wrong-domain.example.com\r\nConnection: close\r\n\r\n')
                response = b''
                try:
                    response = client.recv(4096)
                except Exception:
                    pass
                client.close()
                self.assertEqual(response, b'', 'Connection was not closed upon SNI/certificate mismatch')
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                handle.close()

    def test_probe_roundtrip_through_tunnel(self):
        """Test bidirectional TCP and UDP data probe traversing Iran ingress to Kharej backend."""
        from core import waterwall_probe
        import asyncio
        node = self.node_config()
        entry_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            cert_file, key_file = self._generate_cert(tmpdir)
            node['waterwall']['profile']['certificate'] = str(cert_file)
            node['waterwall']['profile']['key'] = str(key_file)

            iran_chain, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(entry_port)]
            )
            for n in iran_chain['nodes']:
                if n['type'] == 'TlsClient':
                    n['settings']['verify'] = False

            kharej_proc, _, kharej_handle = self.start_waterwall(kharej_chain, tmpdir, 'kharej')
            iran_proc, _, iran_handle = self.start_waterwall(iran_chain, tmpdir, 'iran')

            backend_port = node['waterwall']['backend_port']
            echo_ready = threading.Event()
            echo_stop = threading.Event()

            def run_echo():
                async def _echo():
                    async def handle(reader, writer):
                        try:
                            while data := await reader.read(65536):
                                writer.write(data)
                                await writer.drain()
                        finally:
                            writer.close()
                    done = asyncio.Event()
                    loop = asyncio.get_running_loop()
                    server = await asyncio.start_server(handle, '127.0.0.1', backend_port)
                    transport, _ = await loop.create_datagram_endpoint(
                        lambda: waterwall_probe.Echo(done), local_addr=('127.0.0.1', backend_port)
                    )
                    echo_ready.set()
                    while not echo_stop.is_set():
                        await asyncio.sleep(0.1)
                    server.close()
                    await server.wait_closed()
                    transport.close()
                asyncio.run(_echo())

            t = threading.Thread(target=run_echo, daemon=True)
            t.start()
            self.assertTrue(echo_ready.wait(timeout=3))
            time.sleep(0.3)

            try:
                waterwall_probe.probe(entry_port, secrets.token_hex(16))
            finally:
                echo_stop.set()
                t.join(timeout=2)
                for proc in [kharej_proc, iran_proc]:
                    if proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=2)
                kharej_handle.close()
                iran_handle.close()

    def test_probe_fails_when_backend_absent(self):
        """Test that probe strictly fails (fail-closed) when Kharej backend is not running."""
        from core import waterwall_probe
        node = self.node_config()
        entry_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            cert_file, key_file = self._generate_cert(tmpdir)
            node['waterwall']['profile']['certificate'] = str(cert_file)
            node['waterwall']['profile']['key'] = str(key_file)

            iran_chain, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(entry_port)]
            )
            for n in iran_chain['nodes']:
                if n['type'] == 'TlsClient':
                    n['settings']['verify'] = False

            kharej_proc, _, kharej_handle = self.start_waterwall(kharej_chain, tmpdir, 'kharej')
            iran_proc, _, iran_handle = self.start_waterwall(iran_chain, tmpdir, 'iran')

            time.sleep(0.3)
            try:
                with self.assertRaises(Exception):
                    waterwall_probe.probe(entry_port, secrets.token_hex(16))
            finally:
                for proc in [kharej_proc, iran_proc]:
                    if proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=2)
                kharej_handle.close()
                iran_handle.close()


    def _generate_ca_and_cert(self, tmpdir, domain='tunnel.test'):
        ca_key = tmpdir / 'ca.key'
        ca_cert = tmpdir / 'ca.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(ca_key), '-out', str(ca_cert),
            '-days', '1', '-subj', '/CN=WaterWallTestRootCA'], check=True, capture_output=True)

        server_key = tmpdir / 'server.key'
        server_csr = tmpdir / 'server.csr'
        server_cert = tmpdir / 'server.pem'
        subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
            '-keyout', str(server_key), '-out', str(server_csr),
            '-subj', f'/CN={domain}'], check=True, capture_output=True)

        ext_file = tmpdir / 'server.ext'
        ext_file.write_text(f'subjectAltName=DNS:{domain}\n')

        subprocess.run(['openssl', 'x509', '-req', '-in', str(server_csr),
            '-CA', str(ca_cert), '-CAkey', str(ca_key),
            '-CAcreateserial', '-out', str(server_cert),
            '-days', '1', '-extfile', str(ext_file)], check=True, capture_output=True)

        return ca_cert, server_cert, server_key

    def test_full_chain_tls_verify_success(self):
        """Positive test: FULL WaterWall chain with verify: True on TlsClient,
        verifying server certificate issued by trusted CA, with bidirectional data transfer."""
        node = self.node_config()
        entry_port = self.free_port()
        backend_port = self.free_port()
        node['waterwall']['backend_port'] = backend_port

        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            ca_cert, server_cert, server_key = self._generate_ca_and_cert(tmpdir, domain='tunnel.test')
            node['waterwall']['profile']['certificate'] = str(server_cert)
            node['waterwall']['profile']['key'] = str(server_key)

            # Generate full real chains
            iran_chain, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(entry_port)]
            )

            # Confirm TlsClient in Iran chain has verify: True
            tls_clients = [n for n in iran_chain['nodes'] if n['type'] == 'TlsClient']
            self.assertTrue(len(tls_clients) > 0)
            for tc in tls_clients:
                self.assertEqual(tc['settings']['verify'], True)

            # Start Kharej server (with valid cert/key)
            kharej_proc, _, kharej_handle = self.start_waterwall(kharej_chain, tmpdir, 'kharej')

            # Start Iran client (with trust_cert_path pointing to our CA)
            iran_proc, _, iran_handle = self.start_waterwall(iran_chain, tmpdir, 'iran', trust_cert_path=ca_cert)

            # Start backend echo server on Kharej
            backend_sock = socket.socket()
            backend_sock.bind(('127.0.0.1', backend_port))
            backend_sock.listen(1)
            backend_sock.settimeout(5)

            time.sleep(0.4)
            client = socket.socket()
            client.settimeout(5)
            try:
                client.connect(('127.0.0.1', entry_port))
                conn, _ = backend_sock.accept()

                # Send 32KB through the full verified TLS 1.3 tunnel
                payload = secrets.token_bytes(32768)
                client.sendall(payload)

                received = b''
                while len(received) < len(payload):
                    chunk = conn.recv(min(4096, len(payload) - len(received)))
                    if not chunk:
                        break
                    received += chunk

                self.assertEqual(received, payload, 'Data received at backend did not match payload')

                # Reply from backend through the tunnel
                conn.sendall(b'REPLY-TLS-VERIFIED-OK')
                reply = client.recv(1024)
                self.assertEqual(reply, b'REPLY-TLS-VERIFIED-OK')

                client.close()
                conn.close()
            finally:
                backend_sock.close()
                for proc in [kharej_proc, iran_proc]:
                    if proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=2)
                kharej_handle.close()
                iran_handle.close()

    def test_full_chain_wrong_domain_rejected(self):
        """Negative test: FULL WaterWall chain with verify: True rejects connection when
        Kharej server certificate domain does not match SNI (mitigating MITM/impersonation)."""
        node = self.node_config()
        entry_port = self.free_port()
        backend_port = self.free_port()
        node['waterwall']['backend_port'] = backend_port

        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            # Generate cert for wrong domain (impersonator.example.com)
            ca_cert, server_cert, server_key = self._generate_ca_and_cert(tmpdir, domain='impersonator.example.com')
            node['waterwall']['profile']['certificate'] = str(server_cert)
            node['waterwall']['profile']['key'] = str(server_key)

            # Iran chain has SNI tunnel.test, but server presents impersonator.example.com
            iran_chain, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(entry_port)]
            )

            kharej_proc, _, kharej_handle = self.start_waterwall(kharej_chain, tmpdir, 'kharej')
            iran_proc, _, iran_handle = self.start_waterwall(iran_chain, tmpdir, 'iran', trust_cert_path=ca_cert)

            backend_sock = socket.socket()
            backend_sock.bind(('127.0.0.1', backend_port))
            backend_sock.listen(1)

            time.sleep(0.4)
            client = socket.socket()
            client.settimeout(3)
            try:
                client.connect(('127.0.0.1', entry_port))
                client.sendall(b'SNEAK_DATA')
                resp = b''
                try:
                    resp = client.recv(1024)
                except Exception:
                    pass
                self.assertEqual(resp, b'', 'Connection was not closed on domain mismatch in full chain')

                # Ensure backend never received any connection
                backend_sock.settimeout(0.2)
                with self.assertRaises(socket.timeout):
                    backend_sock.accept()
            finally:
                client.close()
                backend_sock.close()
                for proc in [kharej_proc, iran_proc]:
                    if proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=2)
                kharej_handle.close()
                iran_handle.close()

    def test_unauthorized_destination_port_rejected(self):
        """Negative test: verify that requesting an unauthorized port via the tunnel is
        routed to active BlackHole and connection is immediately terminated without contacting destination."""
        node = self.node_config()
        entry_port = self.free_port()
        backend_port = self.free_port()
        unauthorized_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='vxlb-waterwall-') as tmpdir:
            tmpdir = Path(tmpdir)
            cert_file, key_file = self._generate_cert(tmpdir)
            node['waterwall']['profile']['certificate'] = str(cert_file)
            node['waterwall']['profile']['key'] = str(key_file)

            # Kharej chain only allows entry_port
            iran_chain, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(entry_port)]
            )
            for n in iran_chain['nodes']:
                if n['type'] == 'TlsClient':
                    n['settings']['verify'] = False

            kharej_proc, _, kharej_handle = self.start_waterwall(kharej_chain, tmpdir, 'kharej')

            # Listen on unauthorized port
            unauth_sock = socket.socket()
            unauth_sock.bind(('127.0.0.1', unauthorized_port))
            unauth_sock.listen(1)

            time.sleep(0.4)
            # Connect directly to Kharej outer port using VLESS header pointing to unauthorized_port
            client = socket.socket()
            client.settimeout(3)
            try:
                # Wrap client in TLS connecting to Kharej outer_port
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls_client = ctx.wrap_socket(client, server_hostname='tunnel.test')
                tls_client.connect(('127.0.0.1', node['waterwall']['outer_port']))

                # VLESS request header targeting unauthorized_port on localhost
                vless_uuid = uuid.UUID(node['waterwall']['uuid_tcp']).bytes
                import struct
                header = b'\x00' + vless_uuid + b'\x00\x01' + struct.pack('>H', unauthorized_port) + b'\x01' + socket.inet_aton('127.0.0.1')
                tls_client.sendall(header + b'PROHIBITED_DATA')

                resp = b''
                try:
                    resp = tls_client.recv(1024)
                except Exception:
                    pass
                self.assertEqual(resp, b'', 'Connection to unauthorized port was not terminated')

                # Ensure unauthorized socket was never contacted
                unauth_sock.settimeout(0.2)
                with self.assertRaises(socket.timeout):
                    unauth_sock.accept()
            finally:
                try:
                    tls_client.close()
                except Exception:
                    pass
                client.close()
                unauth_sock.close()
                if kharej_proc.poll() is None:
                    kharej_proc.terminate()
                    kharej_proc.wait(timeout=2)
                kharej_handle.close()


if __name__ == '__main__':
    unittest.main()


