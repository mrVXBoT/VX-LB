"""Stateful deployment contract tests; actual binary evidence is in separate labs.

All SSH is mocked. These checks must not be described as remote systemd or
public recursive DNS acceptance tests.
"""
import copy
from contextlib import nullcontext
import unittest
from unittest.mock import MagicMock, patch

from core import slipstream_adapter as adapter
from core import slipstream_deploy as deploy


class SlipstreamDeploymentContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.security = deploy.identity_material()

    def setUp(self):
        self.pools = {}
        self.iran = {'ip': '192.0.2.10', 'name': 'iran', 'password': 'do-not-log'}
        self.outside = {'ip': '198.51.100.20', 'name': 'outside'}
        self.clients = {}
        def connect(server):
            ssh = self.clients.setdefault(server['ip'], MagicMock())
            ssh.execute.return_value = (0, '/usr/sbin/iptables', '')
            return ssh
        def save(name, pool):
            self.pools[name] = copy.deepcopy(pool)
        def reserve(ssh, excluded, preferred=None, **kwargs):
            return preferred if preferred else 25001 + len(excluded)
        targets = [
            patch('core.transport_change.mutation_lock', side_effect=lambda: nullcontext()),
            patch('core.slipstream_adapter.get_pools', side_effect=lambda: copy.deepcopy(self.pools)),
            patch('core.slipstream_adapter.save_pool', side_effect=save),
            patch('core.load_balancer.LoadBalancerManager.check_port_conflicts', autospec=True, return_value=(True, '')),
            patch('core.slipstream_deploy.connection', side_effect=connect),
            patch('core.slipstream_adapter.SlipstreamAdapter.install', return_value=(True, 'verified')),
            patch('core.paqet_probe.reserve_probe_port', side_effect=reserve),
            patch('core.slipstream_deploy.identity_material', return_value=self.security),
        ]
        for target in targets:
            target.start()
            self.addCleanup(target.stop)
        self.publisher = patch('core.slipstream_deploy.deploy').start()
        self.addCleanup(patch.stopall)
        self.prober = patch('core.slipstream_deploy.probe', return_value={'passed': True, 'protocols': ['tcp'], 'latency_ms': 4, 'udp_application': 'UNVERIFIED'}).start()
        self.cleaner = patch('core.slipstream_deploy.cleanup').start()
        patch('core.slipstream_deploy.time.sleep').start()

    def create(self, **updates):
        arguments = dict(name='dns', kharej=self.outside, servers=[self.iran], ports=[443],
                         domain='tunnel.example.com', resolvers=['1.1.1.1:53'])
        arguments.update(updates)
        return adapter.create(**arguments)

    def test_success_requires_deployment_and_authenticated_data(self):
        ok, _, pool = self.create()
        self.assertTrue(ok)
        self.assertEqual(self.publisher.call_count, 2)
        self.prober.assert_called_once()
        self.assertFalse(pool['nodes'][0]['provisioning'])
        self.assertEqual(pool['nodes'][0]['status'], 'ready')
        for ssh in self.clients.values():
            ssh.close.assert_called()

    def test_probe_failure_never_marks_node_ready_and_keeps_ownership(self):
        self.prober.return_value = {'passed': False}
        ok, _, pool = self.create()
        self.assertFalse(ok)
        self.assertTrue(pool['nodes'][0]['provisioning'])
        self.assertEqual(pool['nodes'][0]['status'], 'failed')
        self.assertIn('slipstream_config_path', pool['nodes'][0])
        self.assertEqual(self.prober.call_count, 5)

    def test_publish_failure_retains_partial_node_for_cleanup(self):
        self.publisher.side_effect = RuntimeError('upload failed')
        ok, _, pool = self.create()
        self.assertFalse(ok)
        self.assertEqual(pool['nodes'][0]['status'], 'failed')
        self.prober.assert_not_called()

    def test_second_node_reuses_owned_server_without_restart(self):
        self.assertTrue(self.create()[0])
        before = self.publisher.call_count
        self.assertTrue(adapter.add('dns', {'ip': '192.0.2.11'})[0])
        self.assertEqual(self.publisher.call_count, before + 1)
        self.assertEqual(len(self.pools['dns']['nodes']), 2)

    def test_missing_domain_never_synthesizes_example_test(self):
        self.assertFalse(self.create(domain=None)[0])
        self.assertEqual(self.pools, {})
        self.publisher.assert_not_called()

    def test_missing_resolver_is_rejected(self):
        self.assertFalse(self.create(resolvers=[])[0])
        self.assertEqual(self.pools, {})

    def test_dns_application_port_collision_is_rejected(self):
        self.assertFalse(self.create(ports=[53])[0])
        self.publisher.assert_not_called()

    def test_second_pool_cannot_own_same_outside_dns_port(self):
        self.assertTrue(self.create()[0])
        self.assertFalse(self.create(name='another')[0])
        self.assertNotIn('another', self.pools)

    def test_occupied_outside_dns_listener_is_not_replaced(self):
        with patch('core.paqet_probe.reserve_probe_port', return_value=49000):
            self.assertFalse(self.create()[0])
        self.publisher.assert_not_called()
        self.prober.assert_not_called()

    def test_missing_credentials_retain_inventory_on_remove(self):
        self.assertTrue(self.create()[0])
        with patch('core.storage.load_data', return_value={'iran_servers': []}):
            self.assertFalse(adapter.remove('dns', self.iran['ip'])[0])
        self.assertEqual(len(self.pools['dns']['nodes']), 1)
        self.cleaner.assert_not_called()

    def test_cleanup_failure_retain_inventory(self):
        self.assertTrue(self.create()[0])
        self.cleaner.side_effect = RuntimeError('still running')
        with patch('core.storage.load_data', return_value={'iran_servers': [self.iran]}):
            self.assertFalse(adapter.remove('dns', self.iran['ip'])[0])
        self.assertEqual(len(self.pools['dns']['nodes']), 1)

    def test_remove_cleans_client_but_preserves_shared_server(self):
        self.assertTrue(self.create()[0])
        with patch('core.storage.load_data', return_value={'iran_servers': [self.iran]}):
            self.assertTrue(adapter.remove('dns', self.iran['ip'])[0])
        self.assertEqual(self.pools['dns']['nodes'], [])
        self.assertTrue(self.pools['dns']['slipstream_server_ready'])
        self.cleaner.assert_called_once()
        self.assertEqual(self.cleaner.call_args.args[0], self.clients[self.iran['ip']])

    def test_pool_delete_clears_creation_history_only_after_remote_cleanup(self):
        self.assertTrue(self.create()[0])
        with patch('core.storage.load_data', return_value={'iran_servers': [self.iran]}), patch('core.storage.delete_pool', return_value=True) as erase:
            self.assertTrue(adapter.delete_pool('dns')[0])
        erase.assert_called_once_with('dns')
        self.assertEqual(self.cleaner.call_count, 2)

    def test_pool_delete_preserves_inventory_if_server_cleanup_fails(self):
        self.assertTrue(self.create()[0])
        self.cleaner.side_effect = [None, RuntimeError('server stop failed')]
        with patch('core.storage.load_data', return_value={'iran_servers': [self.iran]}), patch('core.storage.delete_pool') as erase:
            self.assertFalse(adapter.delete_pool('dns')[0])
        erase.assert_not_called()
        self.assertIn('dns', self.pools)

    def test_metadata_only_modify_is_not_reported_as_runtime_success(self):
        self.assertFalse(adapter.SlipstreamAdapter().modify('dns', {'domain': 'bad.example.com'})[0])
        self.assertFalse(adapter.SlipstreamAdapter().rollback('dns', {})[0])



class SlipstreamResourceHelpers(unittest.TestCase):
    def test_failed_stop_does_not_remove_artifacts(self):
        ssh = MagicMock()
        ssh.execute.side_effect = [(0, 'loaded', ''), (1, '', 'failed')]
        with self.assertRaisesRegex(RuntimeError, 'stop'):
            deploy.cleanup(ssh, ['/etc/vxlb/slipstream/owned/client.json'], ['vxlb-slipstream-owned.service'])
        self.assertFalse(any('rm -f' in call.args[0] for call in ssh.execute.call_args_list))

    def test_partial_deployment_missing_units_can_be_cleaned(self):
        ssh = MagicMock()
        ssh.execute.side_effect = [(0, 'not-found', ''), (0, '', '')]
        deploy.cleanup(ssh, ['/etc/vxlb/slipstream/owned/client.json'], ['vxlb-slipstream-owned.service'])
        self.assertIn('rm -f', ssh.execute.call_args.args[0])

    def test_probe_failure_is_not_a_positive_latency(self):
        ssh = MagicMock()
        ssh.execute.return_value = (1, '', 'TLS failed')
        result = deploy.probe(ssh, '/etc/vxlb/slipstream/test/client.json')
        self.assertFalse(result['passed'])
        self.assertIsNone(result['latency_ms'])
