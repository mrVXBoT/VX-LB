"""Unit tests for LD-BP 13 Advanced Transports Engine and kernel-based telemetry.

Verifies:
1. Complete catalog registration and metadata for all 13 transports.
2. Parameter bounds and security validation.
3. kernel-based telemetry kernel tcp_info unpacking and EWMA health scoring.
4. HMAC canary challenge & response protocol.
5. Adapter configuration synthesis for tun, dc6, xhttps, nova, and quantum+.
"""
import copy
import struct
import unittest
from unittest.mock import MagicMock, patch

from core.transports_13 import (
    TRANSPORTS_13_CATALOG,
    CAT_WEB_STREAM,
    CAT_KCP_ACCELERATOR,
    CAT_L3_CARRIER,
    CAT_ANTI_CENSORSHIP,
    get_transport_spec,
    is_13_transport,
    list_transports_by_category,
    validate_transport_params,
    unpack_kernel_tcp_info,
    compute_ewma_score,
    generate_canary_challenge,
    verify_canary_response,
)
from core.capabilities import get_capability, CAPABILITIES_CATALOG
from core.tunnel import SUPPORTED_TRANSPORTS
from core.tun_adapter import TunDedicatedAdapter
from core.dc6_adapter import DC6Adapter
import core.https_tunnel as https_tunnel
import core.paqet_adapter as paqet_adapter
from core.load_balancer import LoadBalancerManager


class Transports13CatalogTests(unittest.TestCase):
    """Verifies that all 13 transports conform to specification."""

    EXPECTED_IDS = [
        "tcp", "ws", "wss", "http", "https",
        "quantum", "quantum+", "tun", "xhttp", "xhttps",
        "dc6", "quantum-gaming", "nova"
    ]

    def test_all_13_transports_registered(self):
        self.assertEqual(len(self.EXPECTED_IDS), 13)
        for tid in self.EXPECTED_IDS:
            self.assertTrue(is_13_transport(tid), f"Transport '{tid}' missing from 13 catalog")
            spec = get_transport_spec(tid)
            self.assertIsNotNone(spec)
            self.assertEqual(spec.id, tid)
            self.assertGreater(spec.header_overhead_bytes, 0)
            self.assertGreaterEqual(spec.min_mtu, 1200)
            self.assertLessEqual(spec.max_mtu, 1500)
            self.assertTrue(spec.min_mtu <= spec.default_mtu <= spec.max_mtu)

    def test_categories_partitioning(self):
        cats = list_transports_by_category()
        self.assertIn(CAT_WEB_STREAM, cats)
        self.assertIn(CAT_KCP_ACCELERATOR, cats)
        self.assertIn(CAT_L3_CARRIER, cats)
        self.assertIn(CAT_ANTI_CENSORSHIP, cats)

        total_transports = sum(len(c["transports"]) for c in cats.values())
        self.assertEqual(total_transports, 13)

    def test_capabilities_integration(self):
        for tid in self.EXPECTED_IDS:
            cap = get_capability(tid)
            self.assertIsNotNone(cap, f"Capability missing for transport '{tid}'")
            self.assertIn(cap.support_status, {"verified", "experimental"})

    def test_supported_transports_contains_13(self):
        all_protos = {proto for proto, _ in SUPPORTED_TRANSPORTS.values()}
        for tid in self.EXPECTED_IDS:
            self.assertIn(tid, all_protos, f"Transport '{tid}' missing from SUPPORTED_TRANSPORTS")


class ParameterValidationTests(unittest.TestCase):
    """Verifies bounds and sanity checks for transport configuration."""

    def test_mtu_bounds_validation(self):
        # Valid MTU for TCP
        ok, msg, p = validate_transport_params("tcp", {"mtu": 1420})
        self.assertTrue(ok)
        self.assertEqual(p["mtu"], 1420)

        # Invalid MTU (too low)
        ok, msg, _ = validate_transport_params("tcp", {"mtu": 1000})
        self.assertFalse(ok)
        self.assertIn("MTU نامعتبر", msg)

        # Invalid MTU (too high)
        ok, msg, _ = validate_transport_params("tcp", {"mtu": 1600})
        self.assertFalse(ok)

    def test_quantum_plus_fec_validation(self):
        # Valid FEC shards
        ok, _, p = validate_transport_params("quantum+", {"fec_datashard": 10, "fec_parityshard": 3})
        self.assertTrue(ok)
        self.assertEqual(p["fec_datashard"], 10)
        self.assertEqual(p["fec_parityshard"], 3)

        # Invalid FEC (sum > 32)
        ok, msg, _ = validate_transport_params("quantum+", {"fec_datashard": 20, "fec_parityshard": 15})
        self.assertFalse(ok)
        self.assertIn("FEC", msg)

    def test_dc6_carrier_validation(self):
        ok, _, p = validate_transport_params("dc6", {"carrier_type": "ip6gre"})
        self.assertTrue(ok)

        ok, msg, _ = validate_transport_params("dc6", {"carrier_type": "invalid_carrier"})
        self.assertFalse(ok)
        self.assertIn("حامل", msg)

    def test_nova_port_hopping_validation(self):
        ok, _, p = validate_transport_params("nova", {"port_hopping_min": 20000, "port_hopping_max": 40000})
        self.assertTrue(ok)

        # Min >= Max
        ok, msg, _ = validate_transport_params("nova", {"port_hopping_min": 50000, "port_hopping_max": 20000})
        self.assertFalse(ok)


class ZeroFakeTelemetryTests(unittest.TestCase):
    """Tests kernel telemetry extraction and EWMA calculations."""

    def test_unpack_kernel_tcp_info(self):
        # Build 104-byte mock struct tcp_info (8 uint8s + 24 uint32s)
        # Offset 8 uint8s
        u8s = [1, 0, 0, 0, 0, 0, 0, 0]
        # 24 uint32s
        u32s = [0] * 24
        # tcpi_rtt is index 15 (offset 8+15=23 fields total)
        u32s[15] = 25000  # 25,000 us = 25.0 ms
        u32s[16] = 3000   # 3.0 ms jitter (rttvar)
        u32s[18] = 45     # cwnd = 45 pkts
        u32s[23] = 2      # total retrans = 2

        payload = struct.pack("8B24I", *u8s, *u32s)
        parsed = unpack_kernel_tcp_info(payload)

        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["rtt_ms"], 25.0)
        self.assertEqual(parsed["rttvar_ms"], 3.0)
        self.assertEqual(parsed["cwnd_pkts"], 45)
        self.assertEqual(parsed["retransmits"], 2)

    def test_unpack_kernel_tcp_info_short_payload(self):
        parsed = unpack_kernel_tcp_info(b"too_short")
        self.assertFalse(parsed["valid"])

    def test_compute_ewma_score(self):
        # Perfect link: 20ms RTT, 0% loss
        score = compute_ewma_score(None, 20.0, 0.0)
        self.assertGreater(score, 90.0)

        # Severe degradation: 300ms RTT, 20% loss
        bad_score = compute_ewma_score(score, 300.0, 0.20, alpha=0.5)
        self.assertLess(bad_score, score)

    def test_canary_challenge_hmac(self):
        token = "secret_canary_token_123456789"
        nonce, expected = generate_canary_challenge(token)
        self.assertTrue(verify_canary_response(token, nonce, expected))
        self.assertFalse(verify_canary_response(token, nonce, "tampered_response"))
        self.assertFalse(verify_canary_response("wrong_token", nonce, expected))


class DedicatedAdaptersTests(unittest.TestCase):
    """Tests L3 TUN and DC6 adapter configuration synthesis."""

    def test_tun_probe_requires_an_implemented_data_path(self):
        result = TunDedicatedAdapter().probe({'ip': '192.0.2.1'}, {'ip': '192.0.2.2'})
        self.assertFalse(result['passed'])
        self.assertIsNone(result['latency_ms'])

    def test_tun_adapter_configure(self):
        adapter = TunDedicatedAdapter()
        cfg = adapter.configure(
            {"index": 1, "ip": "1.2.3.4"},
            {"ip": "5.6.7.8"},
            {"name": "testpool", "mtu": 1380}
        )
        self.assertIn("interface", cfg)
        self.assertEqual(cfg["mtu"], 1380)
        self.assertIn("10.210.", cfg["iran_inner"])
        self.assertIn("10.210.", cfg["kharej_inner"])
        import tomllib
        config = next(value for path, value in cfg["iran_files"].items() if path.endswith(".toml"))
        native = tomllib.loads(config)["l3"]
        self.assertEqual(native["carrier"], "udp")
        self.assertEqual(native["mode"], "dial")
        self.assertEqual(native["mtu"], 1380)
        self.assertEqual(native["peer_ip"], cfg["kharej_inner"])

    def test_dc6_adapter_configure(self):
        adapter = DC6Adapter()
        cfg = adapter.configure(
            {"node_name": "ir1", "ip": "2001:db8:1::1"},
            {"server_name": "kh.example.com", "ip": "2001:db8:2::2"},
            {"pool_name": "dc6pool", "carrier_type": "ip6gre", "mtu": 1400}
        )
        self.assertEqual(cfg["mode"], "ip6gre")
        self.assertEqual(cfg["mtu"], 1400)
        self.assertEqual(cfg["mss_clamp"], 1340)
        self.assertIn("encaplimit none", cfg["iran_service_unit"])
        self.assertIn("TCPMSS --set-mss 1340", cfg["mss_rule"])

    def test_xhttps_and_nova_configs(self):
        # Test xhttps with xmux
        node_xhttps = {
            "node_name": "ldh0123456789abcdef",
            "transport": "xhttps",
            "https": {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "path": "/xhttp-path",
                "outer_port": 8443,
                "probe_local": 11111,
                "probe_remote": 22222,
                "profile": {
                    "server_name": "example.com",
                    "certificate": "/etc/cert.pem",
                    "key": "/etc/key.pem",
                    "xmux_concurrency": 8,
                    "xmux_max_conns": 4,
                }
            }
        }
        iran_cfg, kharej_cfg = https_tunnel.configs(node_xhttps, "5.6.7.8", ["443"])
        # Verify xmux is populated
        self.assertFalse(iran_cfg["outbounds"][0]["mux"]["enabled"])
        self.assertEqual(iran_cfg["outbounds"][0]["streamSettings"]["xhttpSettings"]["xmux"], {"maxConcurrency": 8})

        # Test nova with fragment outbound
        node_nova = copy.deepcopy(node_xhttps)
        node_nova["transport"] = "nova"
        node_nova["https"]["profile"]["tls_fragment_min"] = 10
        node_nova["https"]["profile"]["tls_fragment_max"] = 30
        node_nova["https"]["profile"]["tls_fragment_delay"] = 10
        iran_nova, _ = https_tunnel.configs(node_nova, "5.6.7.8", ["443"])
        outbound_tags = [o["tag"] for o in iran_nova["outbounds"]]
        self.assertIn("fragment-out", outbound_tags)


if __name__ == "__main__":
    unittest.main()
