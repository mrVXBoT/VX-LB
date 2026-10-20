"""Unit tests for user-space tunnel software engine adapters."""
import json
import unittest
from unittest.mock import MagicMock

from core.adapter_registry import get_adapter
from core.software_engines_adapter import (
    BackhaulAdapter,
    FrpAdapter,
    GostAdapter,
    Hysteria2Adapter,
    RatholeAdapter,
    TrustTunnelAdapter,
)


class TestSoftwareEngineAdapters(unittest.TestCase):
    def setUp(self):
        self.iran_node = {"node_name": "node_ir", "ip": "192.0.2.1"}
        self.kharej_server = {"ip": "198.51.100.2"}
        self.pool_config = {
            "tunnel_port": 8443,
            "client_ports": [8080, 8443],
            "token": "test_token_secret_123",
        }

    def test_trusttunnel_configuration_generation(self):
        adapter = get_adapter("trusttunnel")
        self.assertIsInstance(adapter, TrustTunnelAdapter)

        conf = adapter.configure(self.iran_node, self.kharej_server, self.pool_config)
        self.assertEqual(conf["engine"], "trusttunnel")
        self.assertEqual(conf["tunnel_port"], 8443)

        ir_json = json.loads(conf["iran_config"]["content"])
        self.assertEqual(ir_json["mode"], "client")
        self.assertEqual(ir_json["server"], "198.51.100.2:8443")
        self.assertEqual(ir_json["token"], "test_token_secret_123")
        self.assertEqual(len(ir_json["forwards"]), 2)

        kh_json = json.loads(conf["kharej_config"]["content"])
        self.assertEqual(kh_json["mode"], "server")
        self.assertEqual(kh_json["listen"], "0.0.0.0:8443")
        self.assertTrue(kh_json["tls"]["enabled"])

        self.assertIn("ExecStart=/usr/local/bin/trusttunnel -c", conf["iran_config"]["unit"])

    def test_backhaul_configuration_generation(self):
        adapter = get_adapter("backhaul")
        self.assertIsInstance(adapter, BackhaulAdapter)

        conf = adapter.configure(self.iran_node, self.kharej_server, self.pool_config)
        self.assertEqual(conf["engine"], "backhaul")

        ir_toml = conf["iran_config"]["content"]
        self.assertIn('[client]', ir_toml)
        self.assertIn('remote_addr = "198.51.100.2:8443"', ir_toml)
        self.assertIn('token = "test_token_secret_123"', ir_toml)
        self.assertIn('"8080=127.0.0.1:8080"', ir_toml)

        kh_toml = conf["kharej_config"]["content"]
        self.assertIn('[server]', kh_toml)
        self.assertIn('bind_addr = "0.0.0.0:8443"', kh_toml)
        self.assertIn('token = "test_token_secret_123"', kh_toml)

    def test_frp_configuration_generation(self):
        adapter = get_adapter("frp")
        self.assertIsInstance(adapter, FrpAdapter)

        conf = adapter.configure(self.iran_node, self.kharej_server, self.pool_config)
        self.assertEqual(conf["engine"], "frp")

        ir_toml = conf["iran_config"]["content"]
        self.assertIn('serverAddr = "198.51.100.2"', ir_toml)
        self.assertIn('serverPort = 8443', ir_toml)
        self.assertIn('auth.token = "test_token_secret_123"', ir_toml)
        self.assertIn('name = "p8080"', ir_toml)

        kh_toml = conf["kharej_config"]["content"]
        self.assertIn('bindPort = 8443', kh_toml)
        self.assertIn('auth.token = "test_token_secret_123"', kh_toml)

    def test_rathole_configuration_generation(self):
        adapter = get_adapter("rathole")
        self.assertIsInstance(adapter, RatholeAdapter)

        conf = adapter.configure(self.iran_node, self.kharej_server, self.pool_config)
        self.assertEqual(conf["engine"], "rathole")

        ir_toml = conf["iran_config"]["content"]
        self.assertIn('[client]', ir_toml)
        self.assertIn('remote_addr = "198.51.100.2:8443"', ir_toml)
        self.assertIn('[client.services.p8080]', ir_toml)

        kh_toml = conf["kharej_config"]["content"]
        self.assertIn('[server]', kh_toml)
        self.assertIn('bind_addr = "0.0.0.0:8443"', kh_toml)
        self.assertIn('[server.services.p8080]', kh_toml)

        self.assertIn("--client", conf["iran_config"]["unit"])
        self.assertIn("--server", conf["kharej_config"]["unit"])

    def test_gost_configuration_generation(self):
        adapter = get_adapter("gost")
        self.assertIsInstance(adapter, GostAdapter)

        conf = adapter.configure(self.iran_node, self.kharej_server, self.pool_config)
        self.assertEqual(conf["engine"], "gost")

        ir_yaml = conf["iran_config"]["content"]
        self.assertIn("services:", ir_yaml)
        self.assertIn("forward-8080", ir_yaml)
        self.assertIn("chains:", ir_yaml)
        self.assertIn("198.51.100.2:8443", ir_yaml)

        kh_yaml = conf["kharej_config"]["content"]
        self.assertIn("services:", kh_yaml)
        self.assertIn('addr: ":8443"', kh_yaml)

    def test_hysteria2_configuration_generation(self):
        adapter = get_adapter("hysteria2")
        self.assertIsInstance(adapter, Hysteria2Adapter)

        conf = adapter.configure(
            self.iran_node,
            self.kharej_server,
            dict(self.pool_config, sni="cdn.example.com", password="pass_secret_456"),
        )
        self.assertEqual(conf["engine"], "hysteria2")
        self.assertEqual(conf["sni"], "cdn.example.com")

        ir_yaml = conf["iran_config"]["content"]
        self.assertIn("server: 198.51.100.2:8443", ir_yaml)
        self.assertIn('auth: "pass_secret_456"', ir_yaml)
        self.assertIn('sni: "cdn.example.com"', ir_yaml)
        self.assertIn("tcpTunnels:", ir_yaml)

        kh_yaml = conf["kharej_config"]["content"]
        self.assertIn("listen: :8443", kh_yaml)
        self.assertIn('password: "pass_secret_456"', kh_yaml)

    def test_common_lifecycle_start_stop_clean(self):
        for eng in ["trusttunnel", "backhaul", "frp", "rathole", "gost", "hysteria2"]:
            adapter = get_adapter(eng)
            ssh = MagicMock()
            ssh.execute.return_value = (0, "active", "")

            ok_start, _ = adapter.start(ssh, "test_node")
            self.assertTrue(ok_start)

            ok_stop, _ = adapter.stop(ssh, "test_node")
            self.assertTrue(ok_stop)

            ok_clean, _ = adapter.clean(ssh, "test_node")
            self.assertTrue(ok_clean)
            self.assertIn("systemctl stop", ssh.execute.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
