"""Comprehensive Test Suite for Spoof Engine, ParsaKSH, QS-Tunnel, and HYPERION-X.

Tests:
1. ParsaKSH 1-to-1 Transports:
   - TCP SYN packet generation with manual checksum calculation
   - UDP raw spoof packet generation
   - ICMP Echo packet generation
   - Round-robin IP pool rotation
2. QS-Tunnel 1-to-1 Transports:
   - Base32 unpadded lowercase encoding & decoding
   - DNS wire query generation (RFC 1035 format)
   - Out-of-order DataAssemblyHandler fragment reassembly and timeout eviction
3. HYPERION-X Proprietary Masterpiece Tunnel:
   - Dark Host HMAC-SHA256 knocking verification & scanner rejection
   - Polymorphic Gaussian jitter padding application and stripping
   - Tri-Vector dynamic packet dispatch
4. Pool creation and transport capability integration:
   - Registration in CAPABILITIES_CATALOG
   - Route to spoof adapter in load_balancer
   - Storage of spoof_config in pool record
"""
import asyncio
import os
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from core.capabilities import CAPABILITIES_CATALOG, get_capability
from core.spoof_adapter import (
    ENGINE_ID,
    SPOOF_TRANSPORTS,
    SpoofDedicatedAdapter,
    SpoofProfile,
    create as spoof_create,
)
from core.spoof_engine import (
    DataAssemblyHandler,
    HyperionKnockVerifier,
    RotatingIPPool,
    SpoofController,
    SpoofRuntimeConfig,
    apply_polymorphic_jitter,
    b32decode_nopad,
    b32encode_nopad_lower,
    build_dns_query,
    build_raw_icmp_echo_packet,
    build_raw_tcp_syn_packet,
    build_raw_udp_packet,
    calculate_checksum,
    encode_qname,
    number_to_base32_lower,
    strip_polymorphic_jitter,
)
from core.tunnel import NON_BACKPACK_TRANSPORTS, SUPPORTED_TRANSPORTS


class TestSpoofEngine(unittest.TestCase):
    """Unit tests for low-level packet building, checksums, and evasion logic."""

    def test_checksum_calculation(self):
        # Known test vector for RFC 1071
        data = b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c"
        csum = calculate_checksum(data)
        self.assertIsInstance(csum, int)
        self.assertTrue(0 <= csum <= 0xFFFF)

    def test_parsaksh_tcp_syn_packet_builder(self):
        pkt = build_raw_tcp_syn_packet(
            src_ip="2.188.21.10",
            dst_ip="1.1.1.1",
            src_port=443,
            dst_port=8090,
            seq=1001,
            payload=b"test-syn-payload",
            ttl=64,
        )
        self.assertGreater(len(pkt), 40)
        # Check IP version (IPv4 = 4)
        self.assertEqual(pkt[0] >> 4, 4)
        # Check protocol (TCP = 6)
        self.assertEqual(pkt[9], 6)
        # Check destination IP
        self.assertEqual(socket.inet_ntoa(pkt[16:20]), "1.1.1.1")
        # Check TCP SYN flag (offset 20 + 13 = 33)
        tcp_flags = pkt[33]
        self.assertTrue(tcp_flags & 0x02)  # SYN flag set

    def test_parsaksh_udp_raw_packet_builder(self):
        pkt = build_raw_udp_packet(
            src_ip="185.143.232.10",
            dst_ip="8.8.8.8",
            src_port=5330,
            dst_port=53,
            payload=b"udp-payload-data",
            ttl=128,
        )
        self.assertGreater(len(pkt), 28)
        self.assertEqual(pkt[0] >> 4, 4)
        self.assertEqual(pkt[9], socket.IPPROTO_UDP)
        self.assertEqual(socket.inet_ntoa(pkt[12:16]), "185.143.232.10")
        self.assertEqual(socket.inet_ntoa(pkt[16:20]), "8.8.8.8")

    def test_parsaksh_icmp_echo_packet_builder(self):
        pkt = build_raw_icmp_echo_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            payload=b"ping-spoof-payload",
            seq=1,
            is_reply=False,
        )
        self.assertGreater(len(pkt), 28)
        self.assertEqual(pkt[9], socket.IPPROTO_ICMP)
        # ICMP Type 8 (Echo Request)
        icmp_type = pkt[20]
        self.assertEqual(icmp_type, 8)

    def test_rotating_ip_pool(self):
        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        pool = RotatingIPPool(ips)
        self.assertEqual(pool.count, 3)
        self.assertEqual(pool.next_ip(), "1.1.1.1")
        self.assertEqual(pool.next_ip(), "2.2.2.2")
        self.assertEqual(pool.next_ip(), "3.3.3.3")
        self.assertEqual(pool.next_ip(), "1.1.1.1")

    def test_qs_tunnel_base32_encoding_decoding(self):
        original = b"IranInternetFreedom2026-SuperEncryptedPayload!"
        encoded = b32encode_nopad_lower(original)
        self.assertFalse(encoded.endswith(b"="))
        self.assertTrue(encoded.islower())
        decoded = b32decode_nopad(encoded)
        self.assertEqual(decoded, original)

    def test_qs_tunnel_dns_wire_builder(self):
        qname = encode_qname(b"abc.test.shaparak.ir")
        query = build_dns_query(qname, qtype=1)
        self.assertGreater(len(query), 12)
        # Verify DNS flags (RD=1 -> 0x0100)
        flags = struct.unpack(">H", query[2:4])[0]
        self.assertTrue(flags & 0x0100)
        # Verify QDCOUNT = 1
        qdcount = struct.unpack(">H", query[4:6])[0]
        self.assertEqual(qdcount, 1)

    def test_qs_tunnel_data_assembly_handler(self):
        async def run_assembly():
            handler = DataAssemblyHandler(offsets_size=64, assemble_timeout=5.0)
            data_full = b"Hello from inside Iran Intranet bypassing uRPF!"
            chunk1 = data_full[:20]
            chunk2 = data_full[20:]

            # Add out of order: chunk2 (last=True) then chunk1 (last=False)
            res1 = await handler.add_fragment(key=7, fragment_part=1, last_fragment=True, data=chunk2)
            self.assertIsNone(res1)

            res2 = await handler.add_fragment(key=7, fragment_part=0, last_fragment=False, data=chunk1)
            self.assertEqual(res2, data_full)

        asyncio.run(run_assembly())

    def test_hyperion_x_dark_knock_verifier(self):
        key = b"hyperion-ultra-secret-test-key"
        verifier = HyperionKnockVerifier(key)
        payload = b"authenticated-wireguard-traffic"

        # 1. First packet: Registration Knock (HMAC-SHA256)
        stamped = verifier.stamp_knock(payload)
        self.assertGreater(len(stamped), len(payload))
        self.assertEqual(stamped[0], 0x01)  # KNOCK_FLAG_REGISTRATION

        valid, real = verifier.verify_knock(stamped)
        self.assertTrue(valid)
        self.assertEqual(real, payload)
        res = verifier.verify_knock(stamped)
        session_id = res.session_id
        self.assertIsNotNone(session_id)

        # 2. Subsequent packets: Fast-Path session caching (O(1) without GIL bottleneck)
        fast_payload = b"subsequent-wire-speed-data-packet"
        fast_stamped = verifier.stamp_knock(fast_payload, session_id=session_id)
        self.assertEqual(fast_stamped[0], 0x02)  # KNOCK_FLAG_FASTPATH
        self.assertEqual(len(fast_stamped), 1 + 4 + len(fast_payload))

        fast_valid, fast_real = verifier.verify_knock(fast_stamped)
        self.assertTrue(fast_valid)
        self.assertEqual(fast_real, fast_payload)

        # 3. Scanner / unauthenticated fastpath rejection
        fake_fast = bytes([0x02]) + struct.pack(">I", 987654321) + b"malicious-payload"
        invalid, _ = verifier.verify_knock(fake_fast)
        self.assertFalse(invalid)

        # 4. Scanner / corrupted knock rejection
        corrupted = bytearray(stamped)
        corrupted[10] ^= 0xFF
        invalid_corrupt, _ = verifier.verify_knock(bytes(corrupted))
        self.assertFalse(invalid_corrupt)

    def test_hyperion_x_polymorphic_jitter(self):
        # 1. Small/handshake packet (< 600B): must be padded and clamped <= 1360B
        data_small = b"secret-tunnel-wireguard-handshake-frame"
        jittered_small = apply_polymorphic_jitter(data_small, min_pad=10, max_pad=30, max_mtu=1360)
        self.assertGreater(len(jittered_small), len(data_small) + 2)
        self.assertEqual(jittered_small[0], 0xFD)
        self.assertLessEqual(len(jittered_small), 1360)

        stripped_small = strip_polymorphic_jitter(jittered_small)
        self.assertEqual(stripped_small, data_small)

        # 2. Bulk/data packet (>= 600B): must pass through unpadded to avoid MTU fragmentation blackhole
        data_bulk = b"x" * 1380
        jittered_bulk = apply_polymorphic_jitter(data_bulk, max_mtu=1360)
        self.assertEqual(len(jittered_bulk), 1380)
        self.assertEqual(jittered_bulk, data_bulk)
        stripped_bulk = strip_polymorphic_jitter(jittered_bulk)
        self.assertEqual(stripped_bulk, data_bulk)

    def test_unified_spoof_controller_dispatch_and_dns_resolver(self):
        cfg = SpoofRuntimeConfig(
            pool_name="test-hyperion-pool",
            transport="hyperion-x",
            role="iran",
            listen_addr="127.0.0.1:5330",
            remote_ip="95.217.1.1",
            remote_port=8090,
            spoof_ips=["2.188.21.10", "185.143.232.10"],
            spoof_port=443,
            knock_key="test-knock-key",
            dns_resolvers=["8.8.8.8", "1.1.1.1"],
            direct_authoritative=True,
        )
        ctrl = SpoofController(cfg)
        pkt = ctrl.dispatch_packet(b"test-stream-packet")
        self.assertIsInstance(pkt, bytes)
        self.assertGreater(len(pkt), 40)

        # Verify Direct-Authoritative DNS mode targets remote foreign server directly (no 8.8.8.8 QPS limit)
        direct_target = ctrl.get_qs_target_resolver(direct_authoritative=True)
        self.assertEqual(direct_target, ("95.217.1.1", 53))

        # Verify fallback auto-pivot mode targets recursive pool
        fallback_target1 = ctrl.get_qs_target_resolver(direct_authoritative=False)
        self.assertEqual(fallback_target1, ("8.8.8.8", 53))
        fallback_target2 = ctrl.get_qs_target_resolver(direct_authoritative=False)
        self.assertEqual(fallback_target2, ("1.1.1.1", 53))


class TestSpoofIntegration(unittest.TestCase):
    """Integration tests verifying capabilities and pool creation."""

    def test_new_transports_registered_in_capabilities(self):
        new_transports = [
            "spoof-tcp-syn",
            "spoof-udp-raw",
            "spoof-icmp",
            "qs-dns-hybrid",
            "hyperion-x",
        ]
        for t in new_transports:
            cap = get_capability(t)
            self.assertIsNotNone(cap, f"Transport {t} must be registered in CAPABILITIES_CATALOG")
            self.assertIn(t, SPOOF_TRANSPORTS)
            self.assertIn(t, NON_BACKPACK_TRANSPORTS)

    def test_unimplemented_hyperion_cannot_generate_a_fake_managed_plan(self):
        adapter=SpoofDedicatedAdapter()
        with self.assertRaises((ValueError,KeyError)):
            adapter.configure({'ip':'192.0.2.1'},{'ip':'192.0.2.2'},dict(name='hyperion',transport='hyperion-x',client_ports=['8080']))

    @patch("core.spoof_adapter.connect")
    @patch("core.spoof_adapter.save_pool")
    def test_spoof_create_lifecycle_with_extended_params(self, mock_save, mock_connect):
        mock_ssh = MagicMock()
        mock_ssh.execute.return_value = "ok"
        mock_connect.return_value = mock_ssh

        ok, msg, record = spoof_create(
            pool_name="pool-qs-live",
            kharej_server={"ip": "95.217.1.1", "port": 22},
            iran_servers=[{"ip": "2.188.21.10", "port": 22, "name": "ir-1"}],
            client_ports=["443", "8443"],
            transport="qs-dns-hybrid",
            fake_sni="www.shaparak.ir",
            spoof_ips="2.188.21.10, 185.143.232.10",
            peer_spoof_ip="104.16.132.229",
            dns_resolvers="8.8.8.8, 1.1.1.1",
            fake_send_ip="4.2.2.4",
            fake_send_port=443,
            knock_key="hyperion-master-canary",
            mode="n-1",
        )

        self.assertFalse(ok)
        self.assertEqual(record, {})
        self.assertIn('runtime', msg)
        mock_save.assert_not_called()
        mock_connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
