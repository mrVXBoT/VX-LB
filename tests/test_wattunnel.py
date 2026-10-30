"""WatTunnel carrier configs, health vocabulary, and connection-monitor ports."""
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

from core import wattunnel


def settings(**overrides):
    base = dict(profile='tcp', proto='tcp', key='k' * 16, listen=4443, reverse=False,
                sni='', path='/wat', fake_sni='', fake_mode='seq', icmp_type='echo', fp='chrome')
    base.update(overrides)
    return wattunnel.normalize_settings(base)


class ConfigTests(unittest.TestCase):
    def test_catalog_matches_wattunnel_carriers(self):
        self.assertEqual(wattunnel.PROFILES, (
            'icmp', 'udp', 'udp-dns', 'tcp', 'tls', 'ws', 'wss', 'h2', 'h2c', 'grpc', 'fortress',
        ))
        self.assertEqual(wattunnel.carrier_name('udp-dns'), 'udp')
        self.assertEqual(wattunnel.carrier_name('fortress'), 'icmp+tcp+tls+wss+udp')

    def test_tcp_sides_do_not_embed_the_key(self):
        cfg = settings()
        client = wattunnel.render_config('client', cfg, '192.0.2.1', '198.51.100.10', ['443'], 19801, '/etc/vxlb/wattunnel/key-wtabcd')
        server = wattunnel.render_config('server', cfg, '192.0.2.1', '198.51.100.10', ['443'], 19800, '/etc/vxlb/wattunnel/key-wtabcd')
        self.assertIn('mode: client', client)
        self.assertIn('mode: server', server)
        self.assertIn('carrier: tcp', client)
        self.assertIn('peer: 198.51.100.10:4443', client)
        self.assertIn('listen: :4443', server)
        self.assertNotIn('peer:', server)
        self.assertIn('key-file: /etc/vxlb/wattunnel/key-wtabcd', client)
        self.assertNotIn('k' * 16, client)
        self.assertIn('  - 443\n', client)
        self.assertIn('metrics: 127.0.0.1:19801', client)
        self.assertIn('tcp-mimic: true', client)

    def test_udp_dns_and_icmp_and_reverse(self):
        dns = settings(profile='udp-dns', listen=53)
        server = wattunnel.render_config('server', dns, '192.0.2.1', '198.51.100.10', ['53'], 19800, '/etc/vxlb/wattunnel/key-wtabcd')
        client = wattunnel.render_config('client', dns, '192.0.2.1', '198.51.100.10', ['53'], 19801, '/etc/vxlb/wattunnel/key-wtabcd')
        self.assertIn('carrier: udp', server)
        self.assertIn('udp-dns: true', server)
        self.assertIn('listen: 198.51.100.10:53', server)
        self.assertNotIn('listen: :53', server)
        self.assertIn('peer: 198.51.100.10:53', client)
        udp = settings(profile='udp', listen=4443)
        udp_client = wattunnel.render_config('client', udp, '192.0.2.1', '198.51.100.10', ['443'], 19801, '/etc/vxlb/wattunnel/key-wtabcd')
        self.assertIn('peer: 198.51.100.10:4443', udp_client)
        self.assertNotIn('peer: 198.51.100.10\n', udp_client)
        icmp = settings(profile='icmp', listen=None)
        icmp_client = wattunnel.render_config('client', icmp, '192.0.2.1', '198.51.100.10', ['443'], 19801, '/etc/vxlb/wattunnel/key-wtabcd')
        icmp_server = wattunnel.render_config('server', icmp, '192.0.2.1', '198.51.100.10', ['443'], 19800, '/etc/vxlb/wattunnel/key-wtabcd')
        self.assertIn('peer: 198.51.100.10\n', icmp_client)
        self.assertNotIn('listen:', icmp_client)
        self.assertNotIn('peer:', icmp_server)
        self.assertIn('icmp-type: echo', icmp_client)
        reverse = settings(profile='tcp', reverse=True)
        rev_server = wattunnel.render_config('server', reverse, '2001:db8::1', '198.51.100.10', ['8443'], 19800, '/etc/vxlb/wattunnel/key-wtabcd')
        rev_client = wattunnel.render_config('client', reverse, '2001:db8::1', '198.51.100.10', ['8443'], 19801, '/etc/vxlb/wattunnel/key-wtabcd')
        self.assertIn('reverse: true', rev_server)
        self.assertIn('peer: [2001:db8::1]:4443', rev_server)
        self.assertIn('pool-rotate: 30m', rev_server)
        self.assertIn('listen: :4443', rev_client)
        self.assertNotIn('peer:', rev_client)
        self.assertNotIn('pool-rotate', rev_client)

    def test_reverse_icmp_and_udp_keep_both_sides_addressable(self):
        icmp = settings(profile='icmp', listen=None, reverse=True)
        client = wattunnel.render_config('client', icmp, '192.0.2.1', '198.51.100.10', ['443'], 19801, '/etc/vxlb/wattunnel/key-wtabcd')
        server = wattunnel.render_config('server', icmp, '192.0.2.1', '198.51.100.10', ['443'], 19800, '/etc/vxlb/wattunnel/key-wtabcd')
        self.assertIn('peer: 198.51.100.10\n', client)
        self.assertIn('peer: 192.0.2.1\n', server)
        self.assertNotIn('listen:', client)
        self.assertNotIn('listen:', server)
        udp = settings(profile='udp', listen=4443, reverse=True)
        udp_client = wattunnel.render_config('client', udp, '192.0.2.1', '198.51.100.10', ['443'], 19801, '/etc/vxlb/wattunnel/key-wtabcd')
        udp_server = wattunnel.render_config('server', udp, '192.0.2.1', '198.51.100.10', ['443'], 19800, '/etc/vxlb/wattunnel/key-wtabcd')
        self.assertIn('listen: :4443', udp_client)
        self.assertNotIn('peer:', udp_client)
        self.assertIn('listen: :4443', udp_server)
        self.assertIn('peer: 192.0.2.1:4443', udp_server)

    def test_fortress_and_dual_ports(self):
        cfg = settings(profile='fortress', proto='both', listen=4500, fake_sni='www.cloudflare.com', fake_mode='rst')
        client = wattunnel.render_config('client', cfg, '192.0.2.8', '198.51.100.9', ['443', '53'], 19803, '/etc/vxlb/wattunnel/key-wtabcd')
        self.assertIn('carrier: icmp+tcp+tls+wss+udp', client)
        self.assertIn('peer: 198.51.100.9\n', client)
        self.assertIn('peer-udp: 198.51.100.9:4500', client)
        self.assertIn('peer-tcp: 198.51.100.9:4501', client)
        self.assertIn('peer-wss: 198.51.100.9:4503', client)
        self.assertIn('fake-sni: www.cloudflare.com', client)
        self.assertIn('pool-rotate: 30m', client)
        self.assertNotIn('listen:', client)
        self.assertIn('  - 443\n', client)
        self.assertIn('  - 443/udp\n', client)
        self.assertIn('  - 53/udp\n', client)
        server = wattunnel.render_config('server', cfg, '192.0.2.8', '198.51.100.9', ['443'], 19802, '/etc/vxlb/wattunnel/key-wtabcd')
        self.assertIn('listen: :4500', server)
        self.assertIn('listen-udp: :4500', server)
        self.assertIn('listen-tls: :4502', server)
        self.assertNotIn('peer:', server)
        self.assertNotIn('pool-rotate', server)
        ws = settings(profile='ws', fake_sni='www.cloudflare.com')
        ws_client = wattunnel.render_config('client', ws, '192.0.2.8', '198.51.100.9', ['443'], 19803, '/etc/vxlb/wattunnel/key-wtabcd')
        self.assertNotIn('fake-sni', ws_client)

    def test_rejects_bad_settings(self):
        with self.assertRaises(ValueError):
            wattunnel.normalize_settings({'profile': 'quic'})
        with self.assertRaises(ValueError):
            wattunnel.normalize_settings({'profile': 'tcp', 'key': 'short'})
        with self.assertRaises(ValueError):
            wattunnel.normalize_settings({'profile': 'tcp', 'key': 'k' * 16, 'path': 'wat'})
        with self.assertRaises(ValueError):
            wattunnel.normalize_settings({'profile': 'fortress', 'listen': 65534, 'key': 'k' * 16})

    def test_stats_vocabulary(self):
        status, reason, details = wattunnel.interpret_stats({'alive': True, 'last_rx_age_ms': 100, 'srtt_ms': 41.2, 'streams': 2})
        self.assertEqual(status, 'HEALTHY')
        self.assertEqual(details['link']['latency_ms'], 41.2)
        self.assertIn('41.2', reason)
        status, _, _ = wattunnel.interpret_stats({'alive': True, 'last_rx_age_ms': 60000})
        self.assertEqual(status, 'DEGRADED')
        status, reason, details = wattunnel.interpret_stats({'alive': False, 'last_rx_age_ms': 180000})
        self.assertEqual(status, 'DOWN')
        self.assertIn('قطع', reason)
        self.assertEqual(details['link']['status'], 'DOWN')
        status, _, _ = wattunnel.interpret_stats({'alive': False, 'last_rx_age_ms': 10})
        self.assertEqual(status, 'DEGRADED')
        status, _, _ = wattunnel.interpret_stats({'alive': True})
        self.assertEqual(status, 'DEGRADED')
        status, reason, details = wattunnel.interpret_stats({'alive': True, 'last_rx_age_ms': -1})
        self.assertEqual(status, 'DOWN')
        self.assertIn('معتبر', reason)
        self.assertEqual(details['link']['status'], 'DOWN')
        self.assertEqual(wattunnel.interpret_stats('nope')[0], 'DOWN')

    def test_metrics_stay_on_a_private_pair(self):
        server, client = wattunnel.metrics_ports('wtabcd')
        self.assertEqual(client, server + 1)
        self.assertGreaterEqual(server, 19800)
        self.assertLess(client, 20200)
        self.assertEqual(wattunnel.metrics_ports('wtabcd'), (server, client))

    def test_create_reports_the_node_error(self):
        saved = {}
        with patch.object(wattunnel, 'get_pools', side_effect=lambda: saved), \
             patch.object(wattunnel, 'save_pool', side_effect=lambda name, record: saved.__setitem__(name, record)), \
             patch.object(wattunnel, 'add', return_value=(False, 'binary checksum mismatch')):
            ok, message, _ = wattunnel.create('pool', {'ip': '198.51.100.1'}, [{'ip': '192.0.2.1'}], ['443'], {'profile': 'tcp', 'key': 'k' * 16})
        self.assertFalse(ok)
        self.assertIn('binary checksum mismatch', message)
        self.assertNotIn('نتیجهٔ نصب', message)

    def test_create_rejects_before_saving(self):
        with patch.object(wattunnel, 'get_pools', return_value={}), patch.object(wattunnel, 'save_pool') as save:
            ok, message, _ = wattunnel.create('pool', {'ip': '198.51.100.1'}, [{'ip': '192.0.2.1'}], ['443'], {'profile': 'nope'})
        self.assertFalse(ok)
        self.assertIn('Invalid WatTunnel profile', message)
        save.assert_not_called()

    def test_provisioning_health_does_not_open_ssh(self):
        with patch.object(wattunnel, 'connect') as connect:
            status, reason, _ = wattunnel.health('pool', {'provisioning': True, 'ip': '192.0.2.1'}, ['443'])
        self.assertEqual(status, 'DOWN')
        self.assertIn('کامل نشده', reason)
        connect.assert_not_called()

    def test_units_are_stable(self):
        self.assertEqual(wattunnel.client_unit('wtabcd'), 'vxlb-wattun-c-wtabcd.service')
        self.assertEqual(wattunnel.server_unit('wtabcd'), 'vxlb-wattun-s-wtabcd.service')
        unit = wattunnel._unit('client', '/etc/vxlb/wattunnel/client-wtabcd.yml')
        self.assertIn('/usr/local/bin/wattun -config /etc/vxlb/wattunnel/client-wtabcd.yml', unit)
        self.assertIn('CAP_NET_RAW', unit)


class PlacementTests(unittest.TestCase):
    def test_direct_second_node_reuses_the_kharej_server(self):
        state = {'pools': {'pool': {
            'name': 'pool', 'transport': 'wattunnel', 'engine': 'wattunnel',
            'camouflage': {'profile': 'tcp', 'proto': 'tcp', 'key': 'k' * 16, 'listen': 4443, 'reverse': False},
            'kharej_server': {'ip': '198.51.100.10'}, 'client_ports': ['443'],
            'nodes': [{'ip': '192.0.2.1', 'node_name': 'wt11111111', 'wattunnel': {'reverse': False, 'server_unit': 'vxlb-wattun-s-pool.service'}}],
        }}}
        written = []
        enabled = []

        class SSH:
            def execute(self, command, timeout=30):
                if 'is-active' in command:
                    return 0, '', ''
                if 'enable --now' in command:
                    enabled.append(command)
                return 0, 'x86_64\n', ''
            def close(self):
                pass
            def ensure_conn_monitor_installed(self):
                return True, ''

        def remember(ssh, path, content):
            written.append(path)

        with patch.object(wattunnel, 'get_pools', side_effect=lambda: state['pools']), \
             patch.object(wattunnel, 'atomic_update', side_effect=lambda fn: fn({'pools': state['pools']})), \
             patch.object(wattunnel, 'connect', return_value=SSH()), \
             patch.object(wattunnel, 'install_binary', return_value=(True, 'ok')), \
             patch.object(wattunnel, 'write', side_effect=remember):
            ok, message = wattunnel.add('pool', {'ip': '192.0.2.2', 'name': 'two'})
        self.assertTrue(ok, message)
        self.assertTrue(any(path.endswith('client-' + state['pools']['pool']['nodes'][-1]['node_name'] + '.yml') for path in written))
        self.assertFalse(any(path.endswith('server-pool.yml') for path in written))
        self.assertTrue(any('vxlb-wattun-c-' in command for command in enabled))
        self.assertFalse(any('vxlb-wattun-s-' in command for command in enabled))

    def test_reverse_udp_rejects_a_second_iran_node(self):
        pool = {
            'pool': {
                'nodes': [{'ip': '192.0.2.1', 'node_name': 'wt11111111'}],
                'camouflage': {'profile': 'udp', 'proto': 'tcp', 'key': 'k' * 16, 'listen': 4443, 'reverse': True},
                'kharej_server': {'ip': '198.51.100.10'}, 'client_ports': ['443'],
            }
        }
        with patch.object(wattunnel, 'get_pools', return_value=pool), patch.object(wattunnel, 'connect') as connect:
            ok, message = wattunnel.add('pool', {'ip': '192.0.2.2'})
        self.assertFalse(ok)
        self.assertIn('یک نود', message)
        connect.assert_not_called()

    def test_remove_keeps_shared_server_while_another_node_remains(self):
        removed = []

        class SSH:
            def execute(self, command, timeout=30):
                removed.append(command)
                return 0, '', ''
            def close(self):
                pass

        pool = {'pool': {
            'kharej_server': {'ip': '198.51.100.10'},
            'camouflage': {'reverse': False},
            'nodes': [
                {'ip': '192.0.2.1', 'node_name': 'wt11111111', 'wattunnel': {'reverse': False, 'server_unit': 'vxlb-wattun-s-pool.service'}},
                {'ip': '192.0.2.2', 'node_name': 'wt22222222', 'wattunnel': {'reverse': False, 'server_unit': 'vxlb-wattun-s-pool.service'}},
            ],
        }}
        with patch.object(wattunnel, 'get_pools', side_effect=lambda: pool), \
             patch.object(wattunnel, 'atomic_update', side_effect=lambda fn: fn({'pools': pool})), \
             patch.object(wattunnel, 'connect', return_value=SSH()):
            ok, message = wattunnel.remove('pool', '192.0.2.1')
        self.assertTrue(ok, message)
        self.assertTrue(any('vxlb-wattun-c-wt11111111' in command for command in removed))
        self.assertFalse(any('vxlb-wattun-s-pool' in command for command in removed))

    def test_existing_binary_must_match_the_pinned_checksum(self):
        from core.dependency_manifest import get_dependency_manifest
        expected = get_dependency_manifest('wattunnel').architectures['x86_64']['sha256']

        class SSH:
            def execute(self, command, timeout=30):
                if 'uname' in command:
                    return 0, 'x86_64\n', ''
                if 'sha256sum' in command:
                    return 0, 'deadbeef\n', ''
                return 0, '', ''

        with patch.object(wattunnel, '_ensure_local_binary', return_value=('', 'depot missing')):
            ok, message = wattunnel.install_binary(SSH())
        self.assertFalse(ok)
        self.assertIn('depot missing', message)
        self.assertEqual(len(expected), 64)

        class Matching(SSH):
            def execute(self, command, timeout=30):
                if 'uname' in command:
                    return 0, 'x86_64\n', ''
                if 'sha256sum' in command:
                    return 0, expected + '\n', ''
                return 0, '', ''

        ok, message = wattunnel.install_binary(Matching())
        self.assertTrue(ok, message)


class MonitorTests(unittest.TestCase):
    def test_client_yaml_ports_join_the_connection_monitor(self):
        path = Path(__file__).resolve().parents[1] / 'scripts' / 'vxlb-conn-monitor.py'
        spec = importlib.util.spec_from_file_location('vxlb_conn_monitor', path)
        monitor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(monitor)
        text = '''mode: client
carrier: tcp
ports:
  - 443
  - 8443:443
  - 53/udp
  - 5353:53/udp
# ports: 9
'''
        self.assertEqual(monitor.ports_from_wattunnel_yaml(text), {'443', '8443', '53', '5353'})
        self.assertEqual(monitor.ports_from_wattunnel_yaml('mode: client\n'), set())


if __name__ == '__main__':
    unittest.main()
