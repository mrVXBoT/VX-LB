#!/usr/bin/env python3
"""
Integration tests for WaterWall UDP tunnel and concurrent TCP/UDP routing.

Run: LD_BP_WATERWALL_BINARY=/path/to/waterwall python3 -m pytest tests/test_waterwall_udp.py -v -s

This suite tests:
1. UDP single datagram roundtrip
2. UDP multiple datagram sequence and integrity
3. UDP wrong UUID rejection (fail-closed)
4. Concurrent TCP and UDP multiplexing through the same tunnel entry port
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


class WaterWallUdpIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.environ.get('LD_BP_WATERWALL_BINARY')
        if not cls.binary or not Path(cls.binary).exists():
            raise unittest.SkipTest(f"LD_BP_WATERWALL_BINARY not set or not found: {cls.binary}")

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

        env = dict(os.environ)
        if trust_cert_path:
            env['SSL_CERT_FILE'] = str(trust_cert_path)

        log_file = tmpdir / f'{name}.log'
        log_handle = open(log_file, 'w+')

        process = subprocess.Popen(
            [self.binary, '--verbose', f'--config:{core_file}'],
            stdout=log_handle,
            stderr=log_handle,
            env=env
        )
        time.sleep(0.5)

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

    def test_udp_tunnel_basic(self):
        """Test basic UDP tunnel: datagram sent from Iran entry port reaches Kharej backend and replies."""
        node = self.node_config()
        entry_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='ldbp-waterwall-udp-') as tmpdir:
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

            try:
                backend_port = node['waterwall']['backend_port']
                test_payload = b'UDP-TEST-' + secrets.token_bytes(24)
                server_received = []

                def udp_echo_server():
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind(('127.0.0.1', backend_port))
                    sock.settimeout(4)
                    try:
                        data, addr = sock.recvfrom(2048)
                        server_received.append(data)
                        sock.sendto(b'UDP-REPLY:' + data, addr)
                    except socket.timeout:
                        pass
                    sock.close()

                server_thread = threading.Thread(target=udp_echo_server, daemon=True)
                server_thread.start()

                time.sleep(0.4)

                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.settimeout(4)
                client.sendto(test_payload, ('127.0.0.1', entry_port))
                reply, _ = client.recvfrom(2048)
                client.close()

                server_thread.join(timeout=3)

                self.assertEqual(len(server_received), 1)
                self.assertEqual(server_received[0], test_payload)
                self.assertEqual(reply, b'UDP-REPLY:' + test_payload)

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

    def test_udp_multiple_datagrams(self):
        """Test sending multiple UDP datagrams sequentially through the tunnel."""
        node = self.node_config()
        entry_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='ldbp-waterwall-udp-') as tmpdir:
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

            try:
                backend_port = node['waterwall']['backend_port']
                num_packets = 5
                packets = [f'DATAGRAM-{i}-'.encode() + secrets.token_bytes(64) for i in range(num_packets)]
                server_received = []

                stop_event = threading.Event()

                def udp_echo_server():
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind(('127.0.0.1', backend_port))
                    sock.settimeout(1)
                    while not stop_event.is_set() and len(server_received) < num_packets:
                        try:
                            data, addr = sock.recvfrom(2048)
                            server_received.append(data)
                            sock.sendto(b'ACK:' + data, addr)
                        except socket.timeout:
                            continue
                    sock.close()

                server_thread = threading.Thread(target=udp_echo_server, daemon=True)
                server_thread.start()

                time.sleep(0.4)

                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.settimeout(3)

                acks = []
                for p in packets:
                    client.sendto(p, ('127.0.0.1', entry_port))
                    try:
                        ack, _ = client.recvfrom(2048)
                        acks.append(ack)
                    except socket.timeout:
                        pass
                    time.sleep(0.05)
                client.close()

                stop_event.set()
                server_thread.join(timeout=3)

                self.assertEqual(len(server_received), num_packets)
                self.assertEqual(server_received, packets)
                self.assertEqual(acks, [b'ACK:' + p for p in packets])

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

    def test_udp_wrong_uuid_rejected(self):
        """Test that UDP client with unauthorized UUID is rejected (fail-closed)."""
        node = self.node_config()
        entry_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='ldbp-waterwall-udp-') as tmpdir:
            tmpdir = Path(tmpdir)
            cert_file, key_file = self._generate_cert(tmpdir)

            node['waterwall']['profile']['certificate'] = str(cert_file)
            node['waterwall']['profile']['key'] = str(key_file)

            iran_chain, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(entry_port)]
            )

            # Change UDP UUID to wrong UUID
            wrong_uuid = str(uuid.uuid4())
            for n in iran_chain['nodes']:
                if n.get('name', '').startswith('udp-vless-client-'):
                    n['settings']['uuid'] = wrong_uuid
                if n['type'] == 'TlsClient':
                    n['settings']['verify'] = False

            kharej_proc, _, kharej_handle = self.start_waterwall(kharej_chain, tmpdir, 'kharej')
            iran_proc, _, iran_handle = self.start_waterwall(iran_chain, tmpdir, 'iran')

            try:
                backend_port = node['waterwall']['backend_port']
                server_received = []

                def udp_receiver():
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind(('127.0.0.1', backend_port))
                    sock.settimeout(2)
                    try:
                        data, _ = sock.recvfrom(2048)
                        server_received.append(data)
                    except socket.timeout:
                        pass
                    sock.close()

                server_thread = threading.Thread(target=udp_receiver, daemon=True)
                server_thread.start()

                time.sleep(0.4)

                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.sendto(b'UNAUTHORIZED_UDP_PACKET', ('127.0.0.1', entry_port))
                client.close()

                server_thread.join(timeout=3)
                self.assertEqual(len(server_received), 0, 'Backend received unauthorized UDP packet!')

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

    def test_simultaneous_tcp_and_udp(self):
        """Test simultaneous TCP and UDP traffic entering the same listener port."""
        node = self.node_config()
        entry_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='ldbp-waterwall-both-') as tmpdir:
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

            try:
                backend_port = node['waterwall']['backend_port']
                tcp_received = []
                udp_received = []

                # TCP backend server
                def tcp_server():
                    sock = socket.socket()
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind(('127.0.0.1', backend_port))
                    sock.listen(1)
                    sock.settimeout(4)
                    try:
                        conn, _ = sock.accept()
                        data = conn.recv(1024)
                        tcp_received.append(data)
                        conn.sendall(b'TCP_RESP:' + data)
                        conn.close()
                    except socket.timeout:
                        pass
                    sock.close()

                # UDP backend server
                def udp_server():
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind(('127.0.0.1', backend_port))
                    sock.settimeout(4)
                    try:
                        data, addr = sock.recvfrom(1024)
                        udp_received.append(data)
                        sock.sendto(b'UDP_RESP:' + data, addr)
                    except socket.timeout:
                        pass
                    sock.close()

                t_tcp = threading.Thread(target=tcp_server, daemon=True)
                t_udp = threading.Thread(target=udp_server, daemon=True)
                t_tcp.start()
                t_udp.start()

                time.sleep(0.4)

                tcp_payload = b'CONCURRENT_TCP_DATA'
                udp_payload = b'CONCURRENT_UDP_DATA'

                # Send both simultaneously
                tcp_client = socket.socket()
                tcp_client.settimeout(4)
                tcp_client.connect(('127.0.0.1', entry_port))
                tcp_client.sendall(tcp_payload)

                udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_client.settimeout(4)
                udp_client.sendto(udp_payload, ('127.0.0.1', entry_port))

                tcp_reply = tcp_client.recv(1024)
                udp_reply, _ = udp_client.recvfrom(1024)

                tcp_client.close()
                udp_client.close()

                t_tcp.join(timeout=3)
                t_udp.join(timeout=3)

                self.assertEqual(tcp_received, [tcp_payload])
                self.assertEqual(udp_received, [udp_payload])
                self.assertEqual(tcp_reply, b'TCP_RESP:' + tcp_payload)
                self.assertEqual(udp_reply, b'UDP_RESP:' + udp_payload)

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

    def test_udp_unauthorized_destination_port_rejected(self):
        """Negative test: verify that sending a UDP request to an unauthorized destination
        port via the tunnel is routed to BlackHole and never reaches the backend socket."""
        import ssl
        import struct
        node = self.node_config()
        entry_port = self.free_port()
        backend_port = self.free_port()
        unauthorized_port = self.free_port()

        with tempfile.TemporaryDirectory(prefix='ldbp-waterwall-udp-') as tmpdir:
            tmpdir = Path(tmpdir)
            cert_file, key_file = self._generate_cert(tmpdir)
            node['waterwall']['profile']['certificate'] = str(cert_file)
            node['waterwall']['profile']['key'] = str(key_file)
            node['waterwall']['backend_port'] = backend_port

            # Generate Kharej chain: router whitelists entry_port & backend_port
            _, kharej_chain = waterwall.chain_configs(
                node, '127.0.0.1', [str(entry_port)]
            )

            kharej_proc, _, kharej_handle = self.start_waterwall(kharej_chain, tmpdir, 'kharej')

            # Listen on unauthorized UDP port
            unauth_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            unauth_sock.bind(('127.0.0.1', unauthorized_port))
            unauth_sock.settimeout(0.5)

            time.sleep(0.4)
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                raw_sock = socket.socket()
                tls_client = ctx.wrap_socket(raw_sock, server_hostname='tunnel.test')
                tls_client.connect(('127.0.0.1', node['waterwall']['outer_port']))

                # VLESS request header targeting unauthorized_port with command 2 (UDP)
                vless_uuid = uuid.UUID(node['waterwall']['uuid_udp']).bytes
                header = (
                    b'\x00' +
                    vless_uuid +
                    b'\x00\x02' +  # command 2 = UDP
                    struct.pack('>H', unauthorized_port) +
                    b'\x01' +  # address type 1 = IPv4
                    socket.inet_aton('127.0.0.1')
                )
                payload = b'UNAUTHORIZED_UDP_TRAFFIC'
                tls_client.sendall(header + struct.pack('>H', len(payload)) + payload)

                time.sleep(0.3)
                with self.assertRaises(socket.timeout):
                    unauth_sock.recvfrom(1024)
            finally:
                try:
                    tls_client.close()
                except Exception:
                    pass
                unauth_sock.close()
                if kharej_proc.poll() is None:
                    kharej_proc.terminate()
                    kharej_proc.wait(timeout=2)
                kharej_handle.close()


if __name__ == '__main__':
    unittest.main()
