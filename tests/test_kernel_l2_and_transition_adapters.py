"""Comprehensive test suite for L2 Tap, Transition, and Special Kernel Adapters.

Coverage:
- GRETAP & GRE6TAP (L2 Ethernet tap over IPv4 / IPv6 GRE with isolated bridge & loop protection)
- GRE6TAP + IPsec (L2 Ethernet tap over IPv6 with IPsec encryption and leak-guard)
- ERSPAN + IPsec (ERSPAN session pairing with IPsec ESP protection)
- EOIP (MikroTik compatible L2 tunnel with tunnel ID)
- L2TP (L2TPv3 Ethernet pseudowire over UDP)
- ISATAP (RFC 5214 Intra-site transition with IPv4-embedded IPv6)
"""
import unittest
from unittest.mock import MagicMock

from core.adapter_registry import get_adapter
from core.gretap import validate_gretap_mtu, check_gretap_prerequisites, configure_gretap_link, FORBIDDEN_SYSTEM_BRIDGES
from core.eoip import validate_eoip_mtu, validate_tunnel_id, check_eoip_prerequisites, configure_eoip_link
from core.l2tp import validate_l2tp_mtu, check_l2tp_prerequisites, configure_l2tp_link
from core.isatap import validate_isatap_mtu, format_isatap_address, check_isatap_prerequisites, configure_isatap_link
from core.erspan import validate_erspan_mtu, validate_session_id, check_erspan_prerequisites, configure_erspan_link


class KernelL2AndTransitionAdaptersTests(unittest.TestCase):

    def setUp(self):
        self.mock_ssh = MagicMock()
        self.mock_ssh.execute.return_value = (0, "active", "")
        self.iran_v4 = {"ip": "192.0.2.1", "node_name": "ir_node"}
        self.kharej_v4 = {"ip": "198.51.100.2"}
        self.iran_v6 = {"ip": "2001:db8:1::1", "node_name": "ir_v6"}
        self.kharej_v6 = {"ip": "2001:db8:2::2"}

    # ---------------- 3.7: GRETAP & GRE6TAP ----------------
    def test_gretap_adapter_lifecycle(self):
        adapter = get_adapter("gretap")
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.engine_id, "gretap")

        # Configure
        cfg = adapter.configure(self.iran_v4, self.kharej_v4, {"mtu": 1400})
        self.assertEqual(cfg["engine"], "gretap")
        self.assertEqual(cfg["mode"], "gretap")
        self.assertEqual(cfg["mtu"], 1400)
        self.assertTrue(cfg["security"]["cleartext"])
        self.assertIn("SECURITY NOTICE", cfg["security"]["warning"])
        self.assertIn("type gretap", cfg["unit_script"])

        # System bridge protection
        with self.assertRaises(ValueError) as ctx:
            adapter.configure(self.iran_v4, self.kharej_v4, {"bridge_name": "docker0"})
        self.assertIn("strictly forbidden", str(ctx.exception).lower())

        # Isolated custom bridge
        cfg_br = adapter.configure(self.iran_v4, self.kharej_v4, {"bridge_name": "ldbp-br-test"})
        self.assertIn("stp_state 1", cfg_br["unit_script"])
        self.assertIn("master ldbp-br-test", cfg_br["unit_script"])

        # Status
        st = adapter.status(self.mock_ssh, "gtap-ir_node")
        self.assertEqual(st["engine"], "gretap")
        self.assertTrue(st["security"]["cleartext"])

        # MTU modify and rollback
        ok_mod, msg_mod = adapter.modify("pool1", {"ssh": self.mock_ssh, "interface": "gtap-ir_node", "mtu": 1380})
        self.assertTrue(ok_mod)
        ok_rb, msg_rb = adapter.rollback("pool1", {"ssh": self.mock_ssh, "interface": "gtap-ir_node", "mtu": 1400})
        self.assertTrue(ok_rb)

        # Clean
        ok_clean, _ = adapter.clean(self.mock_ssh, "gtap-ir_node")
        self.assertTrue(ok_clean)

    def test_gre6tap_adapter_lifecycle(self):
        adapter = get_adapter("gre6tap")
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.engine_id, "gre6tap")

        cfg = adapter.configure(self.iran_v6, self.kharej_v6, {"mtu": 1400})
        self.assertEqual(cfg["engine"], "gre6tap")
        self.assertEqual(cfg["mode"], "ip6gretap")
        self.assertEqual(cfg["underlay"]["family"], "ipv6")
        self.assertTrue(cfg["security"]["cleartext"])
        self.assertIn("type ip6gretap", cfg["unit_script"])

        # Status
        st = adapter.status(self.mock_ssh, "g6tap-ir_v6")
        self.assertEqual(st["engine"], "gre6tap")
        self.assertTrue(st["security"]["cleartext"])

    # ---------------- 3.8: GRE6TAP + IPsec ----------------
    def test_gre6tap_ipsec_adapter_lifecycle(self):
        adapter = get_adapter("gre6tap_ipsec")
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.engine_id, "gre6tap_ipsec")

        cfg = adapter.configure(self.iran_v6, self.kharej_v6, {"mtu": 1340})
        self.assertEqual(cfg["engine"], "gre6tap_ipsec")
        self.assertEqual(cfg["mode"], "ip6gretap")
        self.assertTrue(cfg["security"]["requires_encryption"])
        self.assertEqual(cfg["security"]["encryption_type"], "ipsec")
        self.assertFalse(cfg["security"]["cleartext"])
        self.assertIsNotNone(cfg["leak_guard_cmd"])
        self.assertIn("policy --dir in --pol none -j DROP", cfg["leak_guard_cmd"])

        # Status checks both link and IPsec SA
        self.mock_ssh.execute.return_value = (0, "src 2001:db8:1::1 dst 2001:db8:2::2 proto esp", "")
        st = adapter.status(self.mock_ssh, "g6sec-ir_v6")
        self.assertTrue(st["security"]["requires_encryption"])

        # Clean removes leak-guard
        ok_clean, _ = adapter.clean(self.mock_ssh, "g6sec-ir_v6")
        self.assertTrue(ok_clean)

    # ---------------- 3.19: ERSPAN + IPsec ----------------
    def test_erspan_adapter_lifecycle(self):
        adapter = get_adapter("erspan")
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.engine_id, "erspan")

        # Session ID validation
        self.assertEqual(validate_session_id(100), 100)
        with self.assertRaises(ValueError):
            validate_session_id(2000)

        cfg = adapter.configure(self.iran_v4, self.kharej_v4, {"session_id": 50, "mtu": 1340})
        self.assertEqual(cfg["engine"], "erspan")
        self.assertEqual(cfg["mode"], "erspan")
        self.assertEqual(cfg["session_id"], 50)
        self.assertTrue(cfg["security"]["requires_encryption"])
        self.assertIn("type erspan", cfg["unit_script"])
        self.assertIn("erspan 50", cfg["unit_script"])

        # Status
        st = adapter.status(self.mock_ssh, "ers-ir_node")
        self.assertEqual(st["engine"], "erspan")
        self.assertTrue(st["security"]["requires_encryption"])

    # ---------------- 3.20: EOIP ----------------
    def test_eoip_adapter_lifecycle(self):
        adapter = get_adapter("eoip")
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.engine_id, "eoip")

        # Tunnel ID validation
        self.assertEqual(validate_tunnel_id(42), 42)
        with self.assertRaises(ValueError):
            validate_tunnel_id(70000)

        cfg = adapter.configure(self.iran_v4, self.kharej_v4, {"tunnel_id": 101, "mtu": 1420})
        self.assertEqual(cfg["engine"], "eoip")
        self.assertEqual(cfg["mode"], "gretap")
        self.assertEqual(cfg["tunnel_id"], 101)
        self.assertTrue(cfg["security"]["cleartext"])
        self.assertIn("key 101", cfg["unit_script"])

        # Status
        st = adapter.status(self.mock_ssh, "eoip-ir_node")
        self.assertEqual(st["engine"], "eoip")
        self.assertTrue(st["security"]["cleartext"])

    # ---------------- 3.21: L2TP ----------------
    def test_l2tp_adapter_lifecycle(self):
        adapter = get_adapter("l2tp")
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.engine_id, "l2tp")

        cfg = adapter.configure(self.iran_v4, self.kharej_v4, {
            "udp_port": 1701,
            "iran_tunnel_id": 101,
            "kharej_tunnel_id": 102,
            "iran_session_id": 201,
            "kharej_session_id": 202,
            "mtu": 1380,
        })
        self.assertEqual(cfg["engine"], "l2tp")
        self.assertEqual(cfg["mode"], "l2tp")
        self.assertEqual(cfg["udp_port"], 1701)
        self.assertIn("ip l2tp add tunnel", cfg["unit_script"])
        self.assertIn("ip l2tp add session", cfg["unit_script"])
        self.assertTrue(cfg["security"]["cleartext"])

        # Status
        st = adapter.status(self.mock_ssh, "l2tp-ir_node")
        self.assertEqual(st["engine"], "l2tp")

    # ---------------- 3.24: ISATAP ----------------
    def test_isatap_adapter_lifecycle(self):
        adapter = get_adapter("isatap")
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.engine_id, "isatap")

        # RFC 5214 address formatting
        v6_addr = format_isatap_address("2001:db8:acad::", "192.0.2.1")
        # 192.0.2.1: 192.0 = 0xc000, 2.1 = 0x0201
        self.assertEqual(v6_addr, "2001:db8:acad:0:0:5efe:c000:201")

        cfg = adapter.configure(self.iran_v4, self.kharej_v4, {"mtu": 1440})
        self.assertEqual(cfg["engine"], "isatap")
        self.assertEqual(cfg["mode"], "isatap")
        self.assertIn("type sit", cfg["unit_script"])
        self.assertTrue(cfg["security"]["cleartext"])
        self.assertIn("5efe", cfg["addressing"]["iran_ipv6"])

        # Status
        st = adapter.status(self.mock_ssh, "isa-ir_node")
        self.assertEqual(st["engine"], "isatap")


if __name__ == "__main__":
    unittest.main()
