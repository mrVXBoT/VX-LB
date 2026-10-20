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
