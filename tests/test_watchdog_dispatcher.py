"""Verify the watchdog dispatches health probes to the correct engine-specific
monitor for every supported transport, instead of falling back to the generic
BackPack path (which previously produced wrong / missing monitoring for several
engines)."""
import unittest
from unittest.mock import patch, MagicMock

from core.watchdog import TelemetryWatchdog

# engine -> module that exports health()
ENGINE_MODULES = {
    'spoof': 'core.spoof_transport',
    'http': 'core.http_transport',
    'https': 'core.http_transport',
    'slipstream': 'core.slipstream_adapter',
    'waterwall': 'core.waterwall',
    'gre': 'core.gre',
    'geneve': 'core.geneve',
    'geneve_ipsec': 'core.geneve',
    'gre6': 'core.gre6',
    'ip6ip6': 'core.ip6ip6',
    'dc6': 'core.dc6_runtime',
    'tun': 'core.tun_runtime',
    'vxlan_ipsec': 'core.vxlan_ipsec',
    'vxlan': 'core.vxlan_adapter',
    'wireguard': 'core.wireguard_adapter',
    'gost': 'core.gost_engine',
    'frp': 'core.frp_engine',
    'hedioum': 'core.hedioum_engine',
    'rathole': 'core.rathole_engine',
    'paqet': 'core.paqet_engine',
    'candy-spoof': 'core.candy_spoof_transport',
    'parsaksh': 'core.parsaksh_transport',
}


class DispatcherTests(unittest.TestCase):
    def _make_watchdog(self):
        w = TelemetryWatchdog()
        w._analyze_backpack_health = MagicMock(return_value=('HEALTHY', 'bp', [], {}))
        w.save_node_telemetry = MagicMock()
        w.get_node_telemetry = MagicMock(return_value={})
        return w

    def test_every_engine_resolves_to_its_own_health_module(self):
        # node has no 'spoof' dict, but engine matches
        for engine, module in ENGINE_MODULES.items():
            node = {'ip': '192.0.2.1', 'engine': engine}
            if engine == 'spoof':
                node['spoof'] = {'profile': 'fake-sni'}
            with patch(f'{module}.health', return_value=('HEALTHY', f'{engine}-ok', {})) as mock_health:
                w = self._make_watchdog()
                status, reason, logs, details = w.analyze_node_health('pool', node, ['8443'])
                self.assertEqual(status, 'HEALTHY', f'{engine} should be routed to its own health')
                self.assertIn(f'{engine}-ok', reason)
                mock_health.assert_called_once()
                # backpack fallback must NOT be used for these engines
            w._analyze_backpack_health.assert_not_called()

    def test_backpack_uses_generic_fallback(self):
        nodes = [
            {'ip': '192.0.2.1', 'engine': 'backpack'},
            {'ip': '192.0.2.2', 'engine': 'other'},
            {'ip': '192.0.2.3', 'engine': '', 'transport': 'tcp'},
            {'ip': '192.0.2.4', 'transport': 'wss'},
        ]
        for node in nodes:
            w = self._make_watchdog()
            status, reason, logs, details = w.analyze_node_health('pool', node, ['8443'])
            self.assertEqual(status, 'HEALTHY', f'{node} should use backpack fallback')
            self.assertEqual(reason, 'bp')
            w._analyze_backpack_health.assert_called_once()

    def test_spoof_requires_engine_and_spoof_dict(self):
        node = {'ip': '192.0.2.1', 'engine': 'spoof', 'spoof': {'profile': 'fake-sni'}}
        with patch('core.spoof_transport.health', return_value=('HEALTHY', 'spoof-ok', {})) as mock_health:
            w = self._make_watchdog()
            status, reason, _, _ = w.analyze_node_health('pool', node, ['8443'])
            self.assertEqual(status, 'HEALTHY')
            mock_health.assert_called_once()

    def test_unknown_engine_falls_back_to_backpack(self):
        node = {'ip': '192.0.2.1', 'engine': 'totally-unknown'}
        w = self._make_watchdog()
        status, _, _, _ = w.analyze_node_health('pool', node, ['8443'])
        self.assertEqual(status, 'HEALTHY')
        w._analyze_backpack_health.assert_called_once()


if __name__ == "__main__":
    unittest.main()
