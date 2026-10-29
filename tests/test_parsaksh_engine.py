"""Unit tests for the ParsaKSH Spoof Tunnel engine integration."""
import unittest
from unittest.mock import MagicMock, patch

from core.capabilities import get_capability
from core.parsaksh_transport import TRANSPORT, _client_config, _server_config, create
from core.tunnel import NON_BACKPACK_TRANSPORTS, SUPPORTED_TRANSPORTS
from core.transport_change import get_engine_for_transport
from core.dependency_manifest import get_dependency_manifest


class TestParsaKSHRegistration(unittest.TestCase):
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

    def test_dependency_manifest_both_arch(self):
        manifest = get_dependency_manifest(TRANSPORT)
        self.assertIsNotNone(manifest)
        self.assertIn("x86_64", manifest.architectures)
        self.assertIn("aarch64", manifest.architectures)
        self.assertTrue(manifest.architectures["x86_64"]["is_verified"])
        self.assertTrue(manifest.architectures["aarch64"]["is_verified"])


class TestParsaKSHConfig(unittest.TestCase):
    def setUp(self):
        self.base = {
            'data_port': 8090,
            'recv_port': 5001,
            'spoof_port': 443,
            'client_udp_port': 53248,
            'spoof_ip': '8.8.4.4',
            'server_spoof_ip': '1.2.3.4',
            'forward_target': '192.0.2.1:51820',
            'transport': 'udp',
        }

    def test_client_config(self):
        cfg = _client_config('192.0.2.2', '192.0.2.1', self.base)
        self.assertIn('"mode": "local"', cfg)
        self.assertIn('"listen": "0.0.0.0:53248"', cfg)
        self.assertIn('"remote": "192.0.2.1"', cfg)
        self.assertIn('"remote_port": 8090', cfg)
        self.assertIn('"spoof_ip": "8.8.4.4"', cfg)
        self.assertIn('"peer_spoof_ip": "1.2.3.4"', cfg)

    def test_server_config(self):
        cfg = _server_config('192.0.2.1', '192.0.2.2', self.base)
        self.assertIn('"mode": "remote"', cfg)
        self.assertIn('"listen_port": 8090', cfg)
        self.assertIn('"forward": "192.0.2.1:51820"', cfg)
        self.assertIn('"client_ip": "192.0.2.2"', cfg)
        self.assertIn('"spoof_ip": "1.2.3.4"', cfg)


class TestParsaKSHCreate(unittest.TestCase):
    def test_create_rejects_invalid_transport(self):
        ok, msg, record = create(
            'pool-pk', {'ip': '203.0.113.10'}, [{'ip': '10.0.0.5'}],
            ['53248'], {'transport': 'bogus'},
        )
        self.assertFalse(ok)
        self.assertEqual(record, {})

    def test_create_rejects_duplicate_endpoints(self):
        ok, msg, record = create(
            'pool-pk', {'ip': '203.0.113.10'}, [{'ip': '203.0.113.10'}],
            ['53248'], {},
        )
        self.assertFalse(ok)
        self.assertEqual(record, {})

    @patch("core.parsaksh_transport.get_pools")
    @patch("core.parsaksh_transport.add")
    @patch("core.parsaksh_transport.save_pool")
    def test_create_success_path(self, mock_save, mock_add, mock_get_pools):
        pool = {
            'name': 'pool-pk', 'transport': TRANSPORT, 'engine': TRANSPORT,
            'client_ports': ['53248'], 'camouflage': {},
        }
        state = {'calls': 0}

        def fake_get_pools(name=None):
            if name is None:
                state['calls'] += 1
                if state['calls'] >= 2:
                    return {'pool-pk': pool}
                return {}
            return {name: pool}

        mock_get_pools.side_effect = fake_get_pools
        mock_add.return_value = (True, 'ok')
        ok, msg, record = create(
            'pool-pk', {'ip': '203.0.113.10'}, [{'ip': '10.0.0.5'}],
            ['53248'], {'transport': 'icmp'},
        )
        self.assertTrue(ok)
        self.assertEqual(record['transport'], TRANSPORT)
        saved = mock_save.call_args[0][1]
        self.assertEqual(saved['camouflage']['transport'], 'icmp')
        self.assertEqual(saved['camouflage']['client_udp_port'], 53248)


if __name__ == "__main__":
    unittest.main()
