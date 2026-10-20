"""Userspace UDP cryptographic mock lab.

توجه: این اسکریپت صرفاً یک شبیه‌سازی کاربرانه‌ای از تبادل کلید و رمزنگاری روی سوکت‌های UDP محلی است.
این آزمایش WireGuard واقعی، اینترفیس هسته یا Handshake واقعی محسوب نمی‌شود و مدرک تأیید آداپتور نیست.
آزمون واقعی WireGuard اجرا نشده است و باید روی محیط آزمایشی با دسترسی root و ابزار wg انجام شود.
"""

import base64
import os
import pathlib
import secrets
import socket
import sys
import threading
import time
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from core.wireguard_tools import (
    generate_wireguard_keypair,
    generate_preshared_key,
    public_key_from_private_key,
    allocate_private_ips,
    render_wireguard_config,
)


class UserspaceUdpCryptoMockEndpoint:
    """Mock UDP endpoint simulating application-level Curve25519 + ChaCha20-Poly1305 framing."""

    def __init__(
        self,
        name: str,
        private_key_b64: str,
        peer_public_key_b64: str,
        listen_port: int,
        peer_outer_endpoint: Tuple[str, int],
        private_ip: str,
        peer_private_ip: str,
        preshared_key_b64: Optional[str] = None,
    ):
        self.name = name
        self.private_key_b64 = private_key_b64
        self.peer_public_key_b64 = peer_public_key_b64
        self.listen_port = listen_port
        self.peer_outer_endpoint = peer_outer_endpoint
        self.private_ip = private_ip
        self.peer_private_ip = peer_private_ip

        # Diffie-Hellman Key Exchange (Curve25519)
        priv_bytes = base64.b64decode(private_key_b64)
        peer_pub_bytes = base64.b64decode(peer_public_key_b64)
        priv_obj = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
        peer_pub_obj = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        dh_secret = priv_obj.exchange(peer_pub_obj)

        if preshared_key_b64:
            psk_bytes = base64.b64decode(preshared_key_b64)
            # Combine DH secret and PSK for session key
            import hashlib
            session_key = hashlib.blake2s(dh_secret + psk_bytes).digest()
        else:
            session_key = dh_secret

        self.aead = ChaCha20Poly1305(session_key)

        # Telemetry
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.handshakes_completed = 1
        self.latest_handshake_time = time.time()
        self.seq_send = 0

        # Networking
        self.running = False
        self.sock: Optional[socket.socket] = None
        self.local_ingress_sock: Optional[socket.socket] = None
        self.local_ingress_port: Optional[int] = None

        # Packet dispatch callback
        self.packet_handler = None

    def start(self, ingress_port: Optional[int] = None):
        """Starts outer UDP WireGuard listener and local ingress socket."""
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.listen_port))
        self.sock.settimeout(0.5)

        if ingress_port:
            self.local_ingress_port = ingress_port
            self.local_ingress_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.local_ingress_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.local_ingress_sock.bind(("127.0.0.1", ingress_port))
            self.local_ingress_sock.settimeout(0.5)
            threading.Thread(target=self._ingress_loop, daemon=True).start()

        threading.Thread(target=self._listen_loop, daemon=True).start()

    def stop(self):
        """Stops the endpoint and closes sockets."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        if self.local_ingress_sock:
            try:
                self.local_ingress_sock.close()
            except Exception:
                pass
            self.local_ingress_sock = None

    def send_encapsulated(self, payload: bytes):
        """Encrypts payload with ChaCha20-Poly1305 and transmits over outer UDP."""
        if not self.running or not self.sock:
            raise RuntimeError(f"Endpoint {self.name} is stopped")

        self.seq_send += 1
        nonce = self.seq_send.to_bytes(12, "little")
        ciphertext = self.aead.encrypt(nonce, payload, None)

        # WireGuard data frame: [1 byte Type=4] [3 bytes Reserved] [12 bytes Nonce] [Ciphertext]
        packet = b"\x04\x00\x00\x00" + nonce + ciphertext
        self.sock.sendto(packet, self.peer_outer_endpoint)
        self.tx_bytes += len(packet)

    def _listen_loop(self):
        """Receives WireGuard UDP datagrams, decrypts, and dispatches to handler."""
        while self.running and self.sock:
            try:
                data, addr = self.sock.recvfrom(65535)
                if not data or len(data) < 16 or data[0] != 4:
                    continue

                self.rx_bytes += len(data)
                nonce = data[4:16]
                ciphertext = data[16:]
                plaintext = self.aead.decrypt(nonce, ciphertext, None)

                self.latest_handshake_time = time.time()
                if self.packet_handler:
                    self.packet_handler(plaintext)
            except (TimeoutError, OSError):
                continue
            except Exception as e:
                pass

    def _ingress_loop(self):
        """Receives local packets destined for the private link and encapsulates them."""
        while self.running and self.local_ingress_sock:
            try:
                data, client_addr = self.local_ingress_sock.recvfrom(65535)
                self.send_encapsulated(data)
            except (TimeoutError, OSError):
                continue
            except Exception:
                pass


def run_crypto_mock_lab() -> bool:
    print("=" * 70)
    print("  VX-LB Userspace UDP Crypto Mock Lab (Simulation - Not Real WireGuard)")
    print("=" * 70)

    # 1. Generate Curve25519 keypairs for mock exchange
    priv_ir, pub_ir = generate_wireguard_keypair()
    priv_kh, pub_kh = generate_wireguard_keypair()
    psk = generate_preshared_key()

    print(f"[*] Simulated Iran Public Key:   {pub_ir[:16]}... (Curve25519)")
    print(f"[*] Simulated Kharej Public Key: {pub_kh[:16]}... (Curve25519)")
    print(f"[*] Simulated Pre-Shared Key:    {psk[:16]}... (256-bit symmetric)")

    # 2. Port allocation for local UDP mock sockets
    outer_port_ir = 52821
    outer_port_kh = 52822
    ingress_port_ir = 31080
    responder_port_kh = 42890

    ip_ir = "10.100.2.1"
    ip_kh = "10.100.2.2"

    print(f"[*] Mock Outer UDP Ports: Iran={outer_port_ir}, Kharej={outer_port_kh}")
    print(f"[*] Mock Private IPs: Iran={ip_ir} <---> Kharej={ip_kh}")

    # 3. Initialize Kharej Mock Endpoint
    kharej_endpoint = UserspaceUdpCryptoMockEndpoint(
        name="kharej-mock",
        private_key_b64=priv_kh,
        peer_public_key_b64=pub_ir,
        listen_port=outer_port_kh,
        peer_outer_endpoint=("127.0.0.1", outer_port_ir),
        private_ip=ip_kh,
        peer_private_ip=ip_ir,
        preshared_key_b64=psk,
    )

    # 4. Initialize Iran Mock Endpoint
    iran_endpoint = UserspaceUdpCryptoMockEndpoint(
        name="iran-mock",
        private_key_b64=priv_ir,
        peer_public_key_b64=pub_kh,
        listen_port=outer_port_ir,
        peer_outer_endpoint=("127.0.0.1", outer_port_kh),
        private_ip=ip_ir,
        peer_private_ip=ip_kh,
        preshared_key_b64=psk,
    )

    # 5. Kharej Echo Responder attached to Kharej private IP stack
    responder_received = []

    def kharej_private_ip_stack(packet: bytes):
        """Simulates Kharej host receiving private IP packet through mock socket."""
        if packet.startswith(b"VX-LB-WG:"):
            nonce = packet[9:]
            responder_received.append(nonce)
            # Reply back over the mock UDP socket to Iran
            reply = b"VX-LB-WG-OK:" + nonce
            kharej_endpoint.send_encapsulated(reply)

    kharej_endpoint.packet_handler = kharej_private_ip_stack

    # Iran private IP stack receiving replies
    iran_probe_responses = []

    def iran_private_ip_stack(packet: bytes):
        """Simulates Iran host receiving reply through mock socket."""
        if packet.startswith(b"VX-LB-WG-OK:"):
            iran_probe_responses.append(packet)

    iran_endpoint.packet_handler = iran_private_ip_stack

    # Start endpoints
    kharej_endpoint.start()
    iran_endpoint.start(ingress_port=ingress_port_ir)
    time.sleep(0.3)

    try:
        # 6. Active Probe Phase: Send Nonce across mock UDP sockets
        nonce = secrets.token_hex(16).encode("ascii")
        probe_packet = b"VX-LB-WG:" + nonce

        print(f"\n[+] Executing Nonce probe across mock UDP sockets...")
        print(f"    Sending Nonce: {nonce.decode('ascii')}")

        t0 = time.monotonic()
        iran_endpoint.send_encapsulated(probe_packet)

        # Wait for round-trip response through mock sockets
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and not iran_probe_responses:
            time.sleep(0.02)

        elapsed_ms = round((time.monotonic() - t0) * 1000, 2)

        if not iran_probe_responses:
            print("[-] FAIL: No response received through mock socket")
            return False

        expected = b"VX-LB-WG-OK:" + nonce
        if iran_probe_responses[0] != expected:
            print(f"[-] FAIL: Corrupted response: {iran_probe_responses[0]}")
            return False

        print(f"[PASS] Nonce verified across mock UDP sockets!")
        print(f"       Round-trip Latency: {elapsed_ms} ms")
        print(f"       Iran TX: {iran_endpoint.tx_bytes} bytes | Kharej RX: {kharej_endpoint.rx_bytes} bytes")
        print(f"       Kharej TX: {kharej_endpoint.tx_bytes} bytes | Iran RX: {iran_endpoint.rx_bytes} bytes")

        # 7. Causality Phase: Stop the mock socket and verify probe fails
        print(f"\n[+] Testing Causality: Stopping Iran mock socket...")
        iran_endpoint.stop()
        time.sleep(0.2)

        # Clear previous responses
        iran_probe_responses.clear()
        responder_received.clear()

        # Send second probe challenge
        nonce2 = secrets.token_hex(16).encode("ascii")
        probe_packet2 = b"VX-LB-WG:" + nonce2

        print(f"    Sending Nonce 2 while mock socket is closed: {nonce2.decode('ascii')}")
        failed_as_expected = False
        try:
            iran_endpoint.send_encapsulated(probe_packet2)
        except RuntimeError as e:
            failed_as_expected = True
            print(f"    [Expected Failure] Mock endpoint refused transmission: {e}")

        # Also verify that Kharej never received the packet
        time.sleep(0.5)
        if len(responder_received) == 0 and len(iran_probe_responses) == 0:
            failed_as_expected = True
            print(f"    [Expected Failure] Zero packets delivered across closed mock socket")

        if not failed_as_expected:
            print("[-] FAIL: Probe did not fail when mock socket was closed!")
            return False

        print(f"[PASS] Causality verified: Probe strictly fails when mock socket is stopped.")
        print("\n" + "=" * 70)
        print("  UDP CRYPTO MOCKUP COMPLETED (NOTE: NOT REAL WIREGUARD EVIDENCE)")
        print("=" * 70)
        return True

    finally:
        iran_endpoint.stop()
        kharej_endpoint.stop()


# Alias for backward compatibility
run_lab = run_crypto_mock_lab

if __name__ == "__main__":
    ok = run_crypto_mock_lab()
    sys.exit(0 if ok else 1)
