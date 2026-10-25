"""Unit tests for the Paqet engine, matching the source schema
(g3ntrix/paqet-tunnel + hanselime/paqet): server/client YAML, connection
string, firewall rules, and validation."""
import unittest
from unittest.mock import patch
from core import paqet_engine as paqet


NET = {"interface": "eth0", "local_ip": "10.0.0.5", "gateway_mac": "aa:bb:cc:dd:ee:ff"}


class PaqetConfigTests(unittest.TestCase):
    def test_kcp_modes(self):
        self.assertEqual(paqet.KCP_MODES, ("normal", "fast", "fast2", "fast3"))
        self.assertEqual(paqet.validate_kcp_mode("fast"), "fast")
        with self.assertRaises(ValueError):
            paqet.validate_kcp_mode("bogus")

    def test_server_config_matches_source_schema(self):
        cfg = paqet.build_server_config(8888, "SECRET", NET, "fast", 1, 1280)
        self.assertIn('role: "server"', cfg)
        self.assertIn('listen:\n  addr: ":8888"', cfg)
        self.assertIn('addr: "10.0.0.5:8888"', cfg)
        self.assertIn('router_mac: "aa:bb:cc:dd:ee:ff"', cfg)
        self.assertIn('local_flag: ["PA"]', cfg)
        self.assertIn('protocol: "kcp"', cfg)
        self.assertIn('mode: "fast"', cfg)
        self.assertIn('key: "SECRET"', cfg)
        self.assertIn("mtu: 1280", cfg)

    def test_client_config_matches_source_schema(self):
        cfg = paqet.build_client_config("198.51.100.9", 8888, "SECRET", [443, 2053], NET)
        self.assertIn('role: "client"', cfg)
        self.assertIn("forward:", cfg)
        self.assertIn('  - listen: "0.0.0.0:443"', cfg)
        self.assertIn('    target: "127.0.0.1:443"', cfg)
        self.assertIn('    protocol: "tcp"', cfg)
        self.assertIn('server:\n  addr: "198.51.100.9:8888"', cfg)
        self.assertIn('addr: "10.0.0.5:0"', cfg)

    def test_connection_string_roundtrip(self):
        cs = paqet.encode_connection_string("198.51.100.9", 8888, "SECRET", "443,2053", "v1.0.0-alpha.21")
        self.assertTrue(cs.startswith("paqet://"))
        dec = paqet.decode_connection_string(cs)
        self.assertEqual(dec["ip"], "198.51.100.9")
        self.assertEqual(dec["port"], "8888")
        self.assertEqual(dec["key"], "SECRET")
        self.assertEqual(dec["fwd"], "443,2053")
        self.assertEqual(dec["version"], "v1.0.0-alpha.21")

    def test_connection_string_legacy_no_version(self):
        dec = paqet.decode_connection_string(paqet.encode_connection_string("1.2.3.4", 8888, "K", "443"))
        self.assertIsNone(dec["version"])

    def test_connection_string_rejects_malformed(self):
        self.assertIsNone(paqet.decode_connection_string("not-a-valid-string"))

    def test_firewall_lines(self):
        srv = paqet._server_firewall_lines(8888)
        self.assertTrue(any("dport 8888" in l and "NOTRACK" in l for l in srv))
        cli = paqet._client_firewall_lines("198.51.100.9", 8888)
        self.assertTrue(any(f"-d 198.51.100.9 --dport 8888" in l and "NOTRACK" in l for l in cli))

    def test_unit_file(self):
        unit = paqet.unit_file("server", "/etc/vxlb/paqet/server.yaml", "/etc/vxlb/paqet/firewall-server.sh")
        self.assertIn("paqet run -c /etc/vxlb/paqet/server.yaml", unit)
        self.assertIn("ExecStartPre=/bin/sh /etc/vxlb/paqet/firewall-server.sh", unit)
        self.assertIn("CAP_NET_RAW", unit)

    def test_teardown_lines(self):
        srv = paqet._teardown_lines("server", "198.51.100.9", 8888)
        self.assertTrue(any("dport 8888" in l and "NOTRACK" in l for l in srv))
        cli = paqet._teardown_lines("client", "198.51.100.9", 8888)
        self.assertTrue(any("-d 198.51.100.9" in l and "NOTRACK" in l for l in cli))

    def test_create_validation(self):
        with patch.object(paqet, "get_pools", return_value={}):
            ok, msg, _ = paqet.create("p1", {"ip": "198.51.100.1"}, [{"ip": "192.0.2.1"}],
                                       ["443"], {"port": 8888, "kcp_mode": "bogus"})
            self.assertFalse(ok)
            self.assertIn("نامعتبر", msg)


if __name__ == "__main__":
    unittest.main()
