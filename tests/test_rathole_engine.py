"""Unit tests for the Rathole engine, matching upstream (rapiz1/rathole):
transport types tcp/tls/noise/websocket and per-service proto tcp/udp."""
import unittest
from unittest.mock import patch
from core import rathole_engine as rathole


class RatholeEngineTests(unittest.TestCase):
    def test_transports_and_proto(self):
        self.assertEqual(rathole.TRANSPORTS, ("tcp", "tls", "noise", "websocket"))
        self.assertEqual(rathole.SERVICE_PROTOCOLS, ("tcp", "udp"))
        self.assertEqual(rathole.validate_transport("noise"), "noise")
        with self.assertRaises(ValueError):
            rathole.validate_transport("dual")
        with self.assertRaises(ValueError):
            rathole.validate_proto("sctp")

    def test_server_config_tcp(self):
        cfg = rathole._server_config(2333, "SECRET-token-1234", "tcp", "tcp", ["2264"], {})
        self.assertIn('bind_addr = "0.0.0.0:2333"', cfg)
        self.assertIn('default_token = "SECRET-token-1234"', cfg)
        self.assertIn("heartbeat_interval = 30", cfg)
        self.assertIn("[server.transport]\ntype = \"tcp\"", cfg)
        self.assertIn('[server.transport.tcp]\nnodelay = true', cfg)
        self.assertIn("[server.services.2264]", cfg)
        self.assertIn('type = "tcp"', cfg)
        self.assertIn('bind_addr = "0.0.0.0:2264"', cfg)

    def test_server_config_udp(self):
        cfg = rathole._server_config(2333, "SECRET-token-1234", "tcp", "udp", ["2264"], {})
        self.assertIn("[server.services.2264]", cfg)
        self.assertIn('type = "udp"', cfg)

    def test_client_config_tcp(self):
        cfg = rathole._client_config("203.0.113.5", 2333, "SECRET-token-1234", "tcp", "tcp", ["2264"], {})
        self.assertIn('remote_addr = "203.0.113.5:2333"', cfg)
        self.assertIn('default_token = "SECRET-token-1234"', cfg)
        self.assertIn("heartbeat_timeout = 40", cfg)
        self.assertIn("retry_interval = 1", cfg)
        self.assertIn("[client.transport]\ntype = \"tcp\"", cfg)
        self.assertIn('[client.transport.tcp]\nnodelay = true', cfg)
        self.assertIn("[client.services.2264]", cfg)
        self.assertIn('local_addr = "127.0.0.1:2264"', cfg)

    def test_noise_transport_requires_keys(self):
        with self.assertRaises(RuntimeError):
            rathole._transport_lines("server", "noise", {})
        with self.assertRaises(RuntimeError):
            rathole._transport_lines("client", "noise", {})
        cfg = rathole._server_config(2333, "tk", "noise", "tcp", ["2264"],
                                     {"noise_local_priv": "ABC"})
        self.assertIn('type = "noise"', cfg)
        self.assertIn('local_private_key = "ABC"', cfg)
        self.assertNotIn("remote_public_key", cfg)
        cfg_c = rathole._client_config("203.0.113.5", 2333, "tk", "noise", "tcp", ["2264"],
                                       {"noise_remote_pub": "XYZ"})
        self.assertIn('remote_public_key = "XYZ"', cfg_c)
        self.assertNotIn("local_private_key", cfg_c)

    def test_tls_transport_requires_certs(self):
        with self.assertRaises(RuntimeError):
            rathole._transport_lines("server", "tls", {})
        with self.assertRaises(RuntimeError):
            rathole._transport_lines("client", "tls", {})
        s = rathole._transport_lines("server", "tls", {"pkcs12": "/x.pfx", "pkcs12_password": "pw"})
        self.assertIn("pkcs12 = \"/x.pfx\"", "".join(s))
        c = rathole._transport_lines("client", "tls", {"trusted_root": "/ca.crt"})
        self.assertIn("trusted_root = \"/ca.crt\"", "".join(c))

    def test_genkey_parses(self):
        ssh = type("S", (), {})()
        ssh.execute = lambda cmd, timeout=30: (0, "Private Key:\ncQ/vwIqNPJZmuM/OikglzBo/+jlYGrOt9i0k5h5vn1Q=\n\nPublic Key:\nGQYTKSbWLBUSZiGfdWPSgek9yoOuaiwGD/GIX8Z1kkE=\n", "")
        priv, pub = rathole.genkey(ssh)
        self.assertTrue(priv.startswith("cQ/"))
        self.assertTrue(pub.startswith("GQY"))

    def test_service_name_and_unit(self):
        node = {"node_name": "rath12345678"}
        self.assertTrue(rathole._service_name(node, "s").endswith("rath12345678.service"))
        unit = rathole._unit("server", "/etc/vxlb/rathole/server-rath12345678.toml")
        self.assertNotIn("--server", unit)
        self.assertIn("rathole /etc/vxlb/rathole/server-rath12345678.toml", unit)

    def test_create_validation(self):
        with patch.object(rathole, "get_pools", return_value={}):
            ok, msg, _ = rathole.create("p1", {"ip": "198.51.100.1"}, [{"ip": "192.0.2.1"}],
                                         ["2264"], {"transport": "bad", "token": "x"})
            self.assertFalse(ok)
            self.assertIn("نامعتبر", msg)
            ok, msg, _ = rathole.create("p1", {"ip": "198.51.100.1"}, [{"ip": "192.0.2.1"}],
                                         ["2264"], {"transport": "tcp", "proto": "bad"})
            self.assertFalse(ok)
            self.assertIn("نامعتبر", msg)
            ok, msg, _ = rathole.create("p1", {"ip": "198.51.100.1"}, [{"ip": "192.0.2.1"}],
                                         ["2264"], {"transport": "tcp", "token": "short"})
            self.assertFalse(ok)
            self.assertIn("توکن Rathole", msg)

    def test_status_serialization_fields(self):
        p_val = {
            "engine": "rathole",
            "transport": "rathole",
            "rathole_transport": "noise",
            "camouflage": {
                "transport": "noise",
                "proto": "tcp",
                "token": "secret1234",
                "port": 2333,
            }
        }
        cam = {key: p_val.get("camouflage", {}).get(key) for key in ("mode", "server_name", "profile", "persona", "transport", "proto", "port")} if (p_val.get("engine") in ("waterwall", "gost", "frp", "hedioum", "rathole") or p_val.get("transport") in ("waterwall", "gost", "frp", "hedioum", "rathole")) else None
        self.assertIsNotNone(cam)
        self.assertEqual(cam.get("transport"), "noise")
        self.assertEqual(cam.get("proto"), "tcp")
        self.assertEqual(cam.get("port"), 2333)


if __name__ == "__main__":
    unittest.main()
