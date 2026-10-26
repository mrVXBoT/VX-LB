import copy
import unittest
from contextlib import nullcontext
from unittest.mock import patch
from core import node_removal


class NodeRemovalTests(unittest.TestCase):
    def setUp(self):
        self.data = {'pools': {'one': {'nodes': [{'ip': '192.0.2.1'}]}}}
        def atomic(fn):
            fn(self.data)
        self.patches = [patch.object(node_removal, 'load_data', lambda: copy.deepcopy(self.data)),
                        patch.object(node_removal, 'atomic_update', atomic),
                        patch.object(node_removal, 'mutation_lock', nullcontext),
                        patch.object(node_removal.threading, 'Thread')]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_queue_progress_and_completion(self):
        ok, job = node_removal.start('one', '192.0.2.1')
        self.assertTrue(ok)
        self.assertEqual(job['status'], 'queued')
        self.assertFalse(node_removal.start('one', '192.0.2.1')[0])
        self.assertFalse(node_removal.start('one', '192.0.2.1', forget=True)[0])
        def remove(pool, ip, callback):
            callback('Tearing down tunnel from Iran server...')
            self.assertEqual(self.data['pools']['one']['node_removals'][ip]['status'], 'running')
            self.assertIn('ایران', self.data['pools']['one']['node_removals'][ip]['message'])
            self.data['pools'][pool]['nodes'] = []
            return True, 'done'
        with patch.object(node_removal.LoadBalancerManager, 'remove_node', remove):
            node_removal.run('one', '192.0.2.1')
        self.assertEqual(self.data['pools']['one']['nodes'], [])
        self.assertEqual(job['status'], 'succeeded')

    def test_failure_and_restart_are_visible(self):
        _, job = node_removal.start('one', '192.0.2.1')
        with patch.object(node_removal.LoadBalancerManager, 'remove_node', side_effect=RuntimeError('SSH failed')):
            node_removal.run('one', '192.0.2.1')
        self.assertEqual(job['status'], 'failed')
        self.assertIn('SSH failed', job['message'])
        job['status'] = 'running'
        node_removal.recover()
        self.assertEqual(job['status'], 'failed')
        self.assertEqual(len(self.data['pools']['one']['nodes']), 1)

    def test_failed_cleanup_can_be_followed_by_explicit_inventory_removal(self):
        self.data['pools']['one']['nodes'][0]['password'] = 'fixture-private'
        self.data['pools']['one']['engine'] = 'wireguard'
        self.data['pools']['one']['kharej_server'] = {'ip': '198.51.100.1'}
        self.data['resource_reservations'] = {'keep-unverified': {'port': 443}}
        self.data['node_telemetry'] = {'one:192.0.2.1': {'status': 'DOWN'}}
        _, failed = node_removal.start('one', '192.0.2.1')
        with patch.object(node_removal.LoadBalancerManager, 'remove_node', return_value=(False, 'SSH unavailable')):
            node_removal.run('one', '192.0.2.1')
        self.assertEqual(failed['status'], 'failed')
        self.assertEqual(len(self.data['pools']['one']['nodes']), 1)
        ok, job = node_removal.start('one', '192.0.2.1', forget=True)
        self.assertTrue(ok)
        with patch('core.load_balancer.atomic_update', side_effect=lambda fn: fn(self.data)), \
             patch('core.load_balancer.SSHManager') as ssh, \
             patch('core.load_balancer.stop_and_remove_tunnel') as cleanup:
            node_removal.run('one', '192.0.2.1', forget=True)
        ssh.assert_not_called()
        cleanup.assert_not_called()
        self.assertEqual(self.data['pools']['one']['nodes'], [])
        self.assertEqual(job['status'], 'succeeded')
        self.assertTrue(job['cleanup_pending'])
        self.assertIn('تأیید نشده', job['message'])
        self.assertNotIn('fixture-private', str(job))
        pending = next(iter(self.data['pending_node_cleanup'].values()))
        self.assertEqual(pending['node']['password'], 'fixture-private')
        self.assertEqual(pending['engine'], 'wireguard')
        self.assertEqual(self.data['resource_reservations']['keep-unverified']['port'], 443)
        self.assertNotIn('one:192.0.2.1', self.data['node_telemetry'])

    def test_forget_preserves_other_members_and_rejects_missing_node(self):
        from core.load_balancer import LoadBalancerManager
        other = {'ip': '192.0.2.2'}
        self.data['pools']['one']['nodes'].append(other)
        with patch('core.load_balancer.atomic_update', side_effect=lambda fn: fn(self.data)):
            self.assertTrue(LoadBalancerManager.forget_node('one', '192.0.2.1')[0])
            self.assertEqual(self.data['pools']['one']['nodes'], [other])
            self.assertFalse(LoadBalancerManager.forget_node('one', '192.0.2.1')[0])
        self.assertEqual(len(self.data['pending_node_cleanup']), 1)

    def test_internal_type_error_never_replays_remote_removal(self):
        _, job = node_removal.start('one', '192.0.2.1')
        with patch.object(node_removal.LoadBalancerManager, 'remove_node', side_effect=TypeError('internal failure')) as remove:
            node_removal.run('one', '192.0.2.1', job_id=job['id'])
        remove.assert_called_once()
        self.assertEqual(job['status'], 'failed')
        self.assertEqual(len(self.data['pools']['one']['nodes']), 1)

    def test_stale_worker_cannot_execute_new_job_or_replay_finished_job(self):
        _, job = node_removal.start('one', '192.0.2.1')
        with patch.object(node_removal.LoadBalancerManager, 'remove_node') as remove:
            node_removal.run('one', '192.0.2.1', job_id='outdated')
            job['status'] = 'succeeded'
            node_removal.run('one', '192.0.2.1', job_id=job['id'])
        remove.assert_not_called()

    def test_remote_failure_redacts_inventory_credentials(self):
        self.data['pools']['one']['nodes'][0]['password'] = 'fixture-private'
        _, job = node_removal.start('one', '192.0.2.1')
        with patch.object(node_removal.LoadBalancerManager, 'remove_node', side_effect=RuntimeError('SSH fixture-private')):
            node_removal.run('one', '192.0.2.1')
        self.assertNotIn('fixture-private', str(job))
        self.assertIn('[REDACTED]', job['error'])
