import copy
import unittest
from contextlib import nullcontext
from unittest.mock import patch
from core import node_addition


class NodeAdditionTests(unittest.TestCase):
    def setUp(self):
        self.data = {'pools': {'one': {'nodes': [{'ip': '192.0.2.1'}]}}}
        def atomic(fn):
            fn(self.data)
        self.patches = [patch.object(node_addition, 'load_data', lambda: copy.deepcopy(self.data)),
                        patch.object(node_addition, 'atomic_update', atomic),
                        patch.object(node_addition, 'mutation_lock', nullcontext),
                        patch.object(node_addition.threading, 'Thread')]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_queue_duplicate_and_completion(self):
        server = {'ip':'192.0.2.2', 'name':'new', 'password':'private'}
        ok, job = node_addition.start('one', server)
        self.assertTrue(ok)
        self.assertNotIn('password', job)
        self.assertFalse(node_addition.start('one', server)[0])
        def add(pool, server, callback):
            callback('Deploying tunnel for new node...')
            self.assertIn('دو سمت', job['message'])
            return True, 'done'
        with patch.object(node_addition.LoadBalancerManager, 'add_node', add):
            node_addition.run('one', server)
        self.assertEqual(job['status'], 'succeeded')

    def test_failure_and_restart(self):
        server = {'ip':'192.0.2.2', 'name':'new'}
        _, job = node_addition.start('one', server)
        with patch.object(node_addition.LoadBalancerManager, 'add_node', side_effect=RuntimeError('SSH failed')):
            node_addition.run('one', server)
        self.assertEqual(job['status'], 'failed')
        self.assertIn('SSH failed', job['error'])
        job['status'] = 'running'
        node_addition.recover()
        self.assertEqual(job['status'], 'failed')
        self.assertEqual(len(self.data['pools']['one']['nodes']), 1)
