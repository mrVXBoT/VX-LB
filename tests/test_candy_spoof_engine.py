"""Unit tests for the Candy-Spoof engine integration in VX-LB.

Covers:
  1. Transport registration in SUPPORTED_TRANSPORTS and NON_BACKPACK_TRANSPORTS.
  2. Capability registration and engine resolution (load balancer / transport_change).
  3. Dependency manifests for the client and server binaries.
  4. CandomL config generation for both endpoints.
  5. Pool creation validation, success and rejection paths.
  6. Binary install guard for unsupported architectures.
"""
import unittest
from unittest.mock import MagicMock, patch

from core.capabilities import get_capability
from core.candy_spoof_transport import (
    TRANSPORT,
    _client_config,
    _server_config,
    create,
    install_binary,
)
from core.tunnel import NON_BACKPACK_TRANSPORTS, SUPPORTED_TRANSPORTS
from core.transport_change import get_engine_for_transport
from core.dependency_manifest import get_dependency_manifest


class TestCandySpoofRegistration(unittest.TestCase):
    def test_transport_lists(self):
        self.assertTrue(any(v[0] == TRANSPORT for v in SUPPORTED_TRANSPORTS.values()))
        self.assertIn(TRANSPORT, NON_BACKPACK_TRANSPORTS)

    def test_capability_registered(self):
        cap = get_capability(TRANSPORT)
        self.assertIsNotNone(cap)
        self.assertEqual(cap.engine_id, TRANSPORT)
        self.assertTrue(cap.supports_raw_link)
        self.assertIn("cap_net_raw", cap.kernel_requirements)

    def test_engine_resolution(self):
        self.assertEqual(get_engine_for_transport(TRANSPORT), TRANSPORT)

    def test_dependency_manifests(self):
        client = get_dependency_manifest("candy-spoof-client")
        server = get_dependency_manifest("candy-spoof-server")
        self.assertIsNotNone(client)
        self.assertIsNotNone(server)
        self.assertIn("x86_64", client.architectures)
        self.assertTrue(client.architectures["x86_64"]["is_verified"])
        self.assertTrue(server.architectures["x86_64"]["is_verified"])


class TestCandySpoofConfig(unittest.TestCase):
    def setUp(self):
        self.base = {
            "data_port": 51820,
            "icmp_id": 17185,
            "pre_shared_key": "a" * 32,
            "tunnel_count": 4,
            "mtu": 1380,
            "initial_cwnd": 10.0,
            "interface": "eth0",
            "client_spoofed_ip": "8.8.4.4",
            "server_spoofed_ip": "1.2.3.4",
            "spoofed_ip_pool": ["8.8.4.4", "1.1.1.1"],
            "socks5_port": 1080,
        }

    def test_client_config_keys(self):
        cfg = _client_config("10.0.0.1", "203.0.113.1", self.base)
        for expected in (
            'real_ip = "10.0.0.1"',
            'peer_real_ip = "203.0.113.1"',
            'spoofed_ip = "8.8.4.4"',
            'peer_spoofed_ip = "1.2.3.4"',
            "data_port = 51820",
            "icmp_id = 17185",
            "socks5_port = 1080",
            'interface = "eth0"',
            'tunnel_count = 4',
            "mtu = 1380",
        ):
            self.assertIn(expected, cfg)
        self.assertIn('"8.8.4.4", "1.1.1.1"', cfg)

    def test_server_config_keys(self):
        cfg = _server_config("203.0.113.1", "10.0.0.1", self.base)
        for expected in (
            'real_ip = "203.0.113.1"',
            'peer_real_ip = "10.0.0.1"',
            'spoofed_ip = "1.2.3.4"',
            'peer_spoofed_ip = "8.8.4.4"',
            "data_port = 51820",
        ):
            self.assertIn(expected, cfg)


class TestCandySpoofCreate(unittest.TestCase):
    def test_create_rejects_short_psk(self):
        ok, msg, record = create(
            "pool-candy",
            {"ip": "203.0.113.10"},
            [{"ip": "10.0.0.5"}],
            ["1080"],
            {"pre_shared_key": "short", "data_port": 51820},
        )
        self.assertFalse(ok)
        self.assertEqual(record, {})

    def test_create_rejects_duplicate_endpoints(self):
        ok, msg, record = create(
            "pool-candy",
            {"ip": "203.0.113.10"},
            [{"ip": "203.0.113.10"}],
            ["1080"],
            {"pre_shared_key": "a" * 32},
        )
        self.assertFalse(ok)
        self.assertEqual(record, {})

    @patch("core.candy_spoof_transport.get_pools")
    @patch("core.candy_spoof_transport.add")
    @patch("core.candy_spoof_transport.save_pool")
    def test_create_success_path(self, mock_save, mock_add, mock_get_pools):
        pool = {
            "name": "pool-candy",
            "transport": TRANSPORT,
            "engine": TRANSPORT,
            "client_ports": ["1080"],
            "camouflage": {},
        }
        state = {"calls": 0}

        def fake_get_pools(name=None):
            if name is None:
                state["calls"] += 1
                if state["calls"] >= 2:
                    return {"pool-candy": pool}
                return {}
            return {name: pool}

        mock_get_pools.side_effect = fake_get_pools
        mock_add.return_value = (True, "ok")
        ok, msg, record = create(
            "pool-candy",
            {"ip": "203.0.113.10", "port": 22},
            [{"ip": "10.0.0.5", "name": "ir-1"}],
            ["1080"],
            {},
        )
        self.assertTrue(ok)
        self.assertEqual(record["transport"], TRANSPORT)
        self.assertEqual(record["engine"], TRANSPORT)
        saved = mock_save.call_args[0][1]
        self.assertEqual(saved["transport"], TRANSPORT)
        self.assertEqual(saved["camouflage"]["data_port"], 51820)
        self.assertEqual(saved["camouflage"]["socks5_port"], 1080)
        self.assertEqual(len(saved["camouflage"]["pre_shared_key"]), 48)


class TestCandySpoofInstall(unittest.TestCase):
    def test_install_rejects_non_x86_64(self):
        ssh = MagicMock()
        ssh.execute.side_effect = [
            (1, "", ""),  # first pre-check fails -> attempt install
            (0, "aarch64\n", ""),  # uname -m
        ]
        ok, msg = install_binary(ssh, "client")
        self.assertFalse(ok)
        self.assertIn("x86_64", msg)


if __name__ == "__main__":
    unittest.main()
