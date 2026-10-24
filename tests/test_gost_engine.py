"""Unit tests for the GOST engine (profiles, config URL generation, validation)."""
import unittest
from unittest.mock import patch
from core import gost_engine as gost


class GostProfileTests(unittest.TestCase):
    def test_profiles_defined(self):
        expected = {
            "shadowsocks-tcp", "shadowsocks-udp", "shadowsocks-tls", "shadowsocks-ws",
            "obfs4", "obfs4-tls", "grpc", "grpc-tls", "ssh",
            "kcp-obfs4", "web-tunnel", "gaming-socks5-kcp", "quic-socks5",
        }
        self.assertEqual(set(gost.PROFILES), expected)
        for name in expected:
            self.assertIn(name, gost.PROFILE_LABELS)

    def test_normalize_profile(self):
        self.assertEqual(gost.normalize_profile("grpc"), "grpc")
        with self.assertRaises(ValueError):
            gost.normalize_profile("does-not-exist")

    def test_server_listen_url(self):
        url = gost._server_listen_url("shadowsocks-tcp", 8443, "secret-pass-1234")
        self.assertTrue(url.startswith("ss://:8443?"))
        self.assertIn("aes-256-gcm", url)
        self.assertIn("key=secret-pass-1234", url)
        tls_url = gost._server_listen_url("obfs4-tls", 8443, "secret-pass-1234",
                                           ("/etc/vxlb/gost/x.crt", "/etc/vxlb/gost/x.key"))
        self.assertIn("cert=/etc/vxlb/gost/x.crt", tls_url)
        self.assertIn("key=/etc/vxlb/gost/x.key", tls_url)

    def test_client_forward_url(self):
        url = gost._client_forward_url("grpc-tls", "203.0.113.5", 8443, "secret-pass-1234")
        self.assertTrue(url.startswith("relay+grpc+tls://203.0.113.5:8443?"))
        self.assertIn("key=secret-pass-1234", url)

    def test_cmd_client_has_port_forward(self):
        node = {"gost": {"profile": "shadowsocks-tcp", "port": 8443, "password": "secret-pass-1234",
                          "binary": "/usr/local/bin/gost", "host": "/etc/vxlb/gost/xyz"}}
        class FakeSSH:
            pass
        cmd = gost._cmd(FakeSSH(), node, "client", outside_ip="203.0.113.5", ports=["2255"])
        self.assertIn("-F", cmd)
        self.assertTrue(any(c == "tcp://:2255/127.0.0.1:2255" for c in cmd))

    def test_create_validation(self):
        with patch.object(gost, "get_pools", return_value={}):
            ok, msg, _ = gost.create("p1", {"ip": "198.51.100.1"}, [{"ip": "192.0.2.1"}],
                                     ["2255"], {"profile": "bad-profile", "password": "x"})
            self.assertFalse(ok)
            self.assertIn("نامعتبر", msg)
            ok, msg, _ = gost.create("p1", {"ip": "198.51.100.1"}, [{"ip": "192.0.2.1"}],
                                     ["2255"], {"profile": "grpc", "password": "short"})
            self.assertFalse(ok)
            self.assertIn("رمز GOST", msg)


if __name__ == "__main__":
    unittest.main()
