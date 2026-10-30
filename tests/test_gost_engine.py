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
        self.assertIn("certFile=/etc/vxlb/gost/x.crt", tls_url)
        self.assertIn("keyFile=/etc/vxlb/gost/x.key", tls_url)
        self.assertIn("key=secret-pass-1234", tls_url)

    def test_web_tunnel_uses_wss_and_http_auth(self):
        url = gost._server_listen_url("web-tunnel", 8443, "secret-pass-1234",
                                       ("/etc/vxlb/gost/x.crt", "/etc/vxlb/gost/x.key"))
        self.assertTrue(url.startswith("http+wss://vxlb:secret-pass-1234@:8443?"))
        self.assertIn("path=/ws", url)
        self.assertIn("certFile=/etc/vxlb/gost/x.crt", url)
        self.assertIn("keyFile=/etc/vxlb/gost/x.key", url)
        self.assertNotIn("key=secret-pass-1234", url)
        self.assertNotIn("mwss", url)
        forward = gost._client_forward_url("web-tunnel", "203.0.113.5", 8443, "secret-pass-1234")
        self.assertTrue(forward.startswith("http+wss://vxlb:secret-pass-1234@203.0.113.5:8443?"))

    def test_client_forward_url(self):
        url = gost._client_forward_url("grpc-tls", "203.0.113.5", 8443, "secret-pass-1234")
        self.assertTrue(url.startswith("relay+grpc+tls://203.0.113.5:8443?"))
        self.assertIn("key=secret-pass-1234", url)

    def test_gaming_kcp_publishes_tcp_port(self):
        node = {"gost": {"profile": "gaming-socks5-kcp", "port": 8443, "password": "secret-pass-1234",
                          "binary": "/usr/local/bin/gost", "host": "/etc/vxlb/gost/xyz"}}
        cmd = gost._cmd(object(), node, "client", outside_ip="203.0.113.5", ports=["2255"])
        self.assertIn("tcp://:2255/127.0.0.1:2255", cmd)
        self.assertNotIn("udp://:2255/127.0.0.1:2255", cmd)
        forward = next(part for part in cmd if part.startswith("socks5+kcp://"))
        self.assertIn("mode=fast3", forward)
        self.assertIn("key=secret-pass-1234", forward)

    def test_kcp_obfs4_publishes_tcp_port(self):
        node = {"gost": {"profile": "kcp-obfs4", "port": 8443, "password": "secret-pass-1234",
                          "binary": "/usr/local/bin/gost", "host": "/etc/vxlb/gost/xyz"}}
        cmd = gost._cmd(object(), node, "client", outside_ip="203.0.113.5", ports=["2255"])
        self.assertIn("tcp://:2255/127.0.0.1:2255", cmd)
        forward = next(part for part in cmd if part.startswith("relay+kcp+obfs4://"))
        self.assertIn("iat-mode=0", forward)

    def test_quic_socks5_publishes_tcp_port(self):
        node = {"gost": {"profile": "quic-socks5", "port": 8443, "password": "secret-pass-1234",
                          "binary": "/usr/local/bin/gost", "host": "/etc/vxlb/gost/xyz"}}
        cmd = gost._cmd(object(), node, "client", outside_ip="203.0.113.5", ports=["2255"])
        self.assertIn("tcp://:2255/127.0.0.1:2255", cmd)
        self.assertNotIn("udp://:2255/127.0.0.1:2255", cmd)
        forward = next(part for part in cmd if part.startswith("socks5+quic://"))
        self.assertIn("timeout=60", forward)
        self.assertIn("key=secret-pass-1234", forward)

    def test_ssh_uses_relay_and_every_tcp_profile_publishes_tcp(self):
        url = gost._server_listen_url("ssh", 8443, "secret-pass-1234")
        self.assertTrue(url.startswith("relay+ssh://:8443?"))
        self.assertNotIn("forward+ssh", url)
        for name, info in gost.PROFILES.items():
            node = {"gost": {"profile": name, "port": 8443, "password": "secret-pass-1234",
                              "binary": "/usr/local/bin/gost", "host": "/etc/vxlb/gost/xyz"}}
            cmd = gost._cmd(object(), node, "client", outside_ip="203.0.113.5", ports=["2255"])
            self.assertIn("tcp://:2255/127.0.0.1:2255", cmd, name)
            self.assertFalse(any(str(part).startswith("forward+") for part in cmd), name)

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
