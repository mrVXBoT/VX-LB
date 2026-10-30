"""Unit tests for the FRP engine (TOML config generation, modes, validation)."""
import unittest
from unittest.mock import patch
from core import frp_engine as frp


class FrpEngineTests(unittest.TestCase):
    def test_modes(self):
        self.assertEqual(frp.MODES, ("tcp", "udp", "dual"))
        self.assertEqual(frp.normalize_mode("tcp"), "tcp")
        with self.assertRaises(ValueError):
            frp.normalize_mode("grpc")

    def test_server_config_toml(self):
        cfg = frp._server_config(7000, "SECRET-token-1234")
        self.assertIn("bindPort = 7000", cfg)
        self.assertIn('auth.token = "SECRET-token-1234"', cfg)

    def test_client_config_tcp(self):
        cfg = frp._client_config("203.0.113.5", 7000, "SECRET-token-1234", "tcp", ["2255"])
        self.assertIn('serverAddr = "203.0.113.5"', cfg)
        self.assertIn("serverPort = 7000", cfg)
        self.assertIn('type = "tcp"', cfg)
        self.assertIn("localPort = 2255", cfg)
        self.assertIn("remotePort = 2255", cfg)
        self.assertNotIn("udp", cfg)

    def test_client_config_udp_keeps_tcp_port(self):
        cfg = frp._client_config("203.0.113.5", 7000, "SECRET-token-1234", "udp", ["2255"])
        self.assertIn('type = "tcp"', cfg)
        self.assertIn('type = "udp"', cfg)
        self.assertIn("remotePort = 2255", cfg)

    def test_client_config_dual(self):
        cfg = frp._client_config("203.0.113.5", 7000, "SECRET-token-1234", "dual", ["2255"])
        self.assertIn('type = "tcp"', cfg)
        self.assertIn('type = "udp"', cfg)
        self.assertIn('name = "p2255"', cfg)
        self.assertIn('name = "p2255u"', cfg)

    def test_create_validation(self):
        with patch.object(frp, "get_pools", return_value={}):
            ok, msg, _ = frp.create("p1", {"ip": "198.51.100.1"}, [{"ip": "192.0.2.1"}],
                                     ["2255"], {"mode": "bad", "token": "x"})
            self.assertFalse(ok)
            self.assertIn("نامعتبر", msg)
            ok, msg, _ = frp.create("p1", {"ip": "198.51.100.1"}, [{"ip": "192.0.2.1"}],
                                     ["2255"], {"mode": "tcp", "token": "short"})
            self.assertFalse(ok)
            self.assertIn("توکن FRP", msg)


if __name__ == "__main__":
    unittest.main()
