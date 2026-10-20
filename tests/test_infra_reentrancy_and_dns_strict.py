import os
import unittest
from unittest.mock import patch, MagicMock
from contextlib import nullcontext
from core import transport_change as change
from core.watchdog import TelemetryWatchdog
from core.dns_routing import route_key

CONFIG = {'enabled': True, 'api_token': 'fake', 'zone_id': 'zone1', 'subdomain': 'edge.example.test', 'scope': 'single'}

class InfraReentrancyAndDnsStrictTests(unittest.TestCase):
    def test_mutation_lock_is_reentrant_and_does_not_deadlock(self):
        """Verify that nested mutation_lock calls in the same thread succeed without blocking."""
        executed = []
        with change.mutation_lock():
            executed.append('outer')
            with change.mutation_lock():
                executed.append('inner1')
                with change.mutation_lock():
                    executed.append('inner2')
            executed.append('outer_exit')

        self.assertEqual(executed, ['outer', 'inner1', 'inner2', 'outer_exit'])

    def test_dns_strict_policy_rejects_canary_degraded_idle(self):
        """failover DNS only selects nodes with verified complete path health (HEALTHY)."""
        data = {
            'cloudflare': CONFIG,
            'pools': {
                'PoolStrict': {
                    'dns_policy': 'strict',
                    'nodes': [{'ip': '192.0.2.1'}, {'ip': '192.0.2.2'}, {'ip': '192.0.2.3'}],
                    'client_ports': ['443']
                }
            }
        }
        watchdog = TelemetryWatchdog()
        # Node 1: CANARY, Node 2: DEGRADED, Node 3: IDLE -> NO node is HEALTHY
        node_health_returns = [
            ('CANARY', 'canary testing', [], {}),
            ('DEGRADED', 'one drop', [], {}),
            ('IDLE', 'no traffic', [], {})
        ]
        with patch('core.watchdog.load_data', return_value=data), \
             patch('core.watchdog.routing_lock', side_effect=nullcontext), \
             patch.object(watchdog, 'analyze_node_health', side_effect=node_health_returns), \
             patch('core.watchdog.CloudflareManager') as manager:

            report = watchdog.run_check_cycle()

        # In strict mode, sync_subdomain must NOT be called with unverified nodes
        manager.return_value.sync_subdomain.assert_not_called()
        pool_rep = report['pool_reports']['PoolStrict']
        self.assertEqual(pool_rep['healthy_ips'], [])
        self.assertEqual(pool_rep['cloudflare_sync']['status'], 'SUSPENDED_NO_HEALTHY_NODES')

    def test_dns_strict_policy_routes_only_healthy_nodes(self):
        """When healthy nodes exist, only HEALTHY nodes enter DNS (canary/degraded excluded)."""
        data = {
            'cloudflare': CONFIG,
            'pools': {
                'PoolStrict': {
                    'dns_policy': 'strict',
                    'nodes': [{'ip': '192.0.2.1'}, {'ip': '192.0.2.2'}, {'ip': '192.0.2.3'}],
                    'client_ports': ['443']
                }
            }
        }
        watchdog = TelemetryWatchdog()
        # Node 1: HEALTHY, Node 2: CANARY, Node 3: DEGRADED
        node_health_returns = [
            ('HEALTHY', 'clean data flow', [], {}),
            ('CANARY', 'canary testing', [], {}),
            ('DEGRADED', 'one drop', [], {})
        ]
        with patch('core.watchdog.load_data', return_value=data), \
             patch('core.watchdog.routing_lock', side_effect=nullcontext), \
             patch.object(watchdog, 'analyze_node_health', side_effect=node_health_returns), \
             patch('core.watchdog.CloudflareManager') as manager:
            manager.return_value.sync_subdomain.return_value = {'added': ['192.0.2.1'], 'deleted': [], 'kept': []}
            manager.return_value.record_snapshot.return_value = {'success': True, 'records': [{'name': 'edge.example.test', 'content': '192.0.2.1'}]}

            report = watchdog.run_check_cycle()

        manager.return_value.sync_subdomain.assert_called_once_with('edge.example.test', ['192.0.2.1'], proxied=False, ttl=60)
        pool_rep = report['pool_reports']['PoolStrict']
        self.assertEqual(pool_rep['healthy_ips'], ['192.0.2.1'])

    def test_dns_permissive_policy_retains_legacy_behavior(self):
        """When dns_policy is 'permissive', canary and idle nodes can receive traffic as trial."""
        data = {
            'cloudflare': CONFIG,
            'pools': {
                'PoolPermissive': {
                    'dns_policy': 'permissive',
                    'nodes': [{'ip': '192.0.2.1'}, {'ip': '192.0.2.2'}],
                    'client_ports': ['443']
                }
            }
        }
        watchdog = TelemetryWatchdog()
        node_health_returns = [
            ('CANARY', 'canary testing', [], {}),
            ('IDLE', 'no traffic', [], {})
        ]
        with patch('core.watchdog.load_data', return_value=data), \
             patch('core.watchdog.routing_lock', side_effect=nullcontext), \
             patch.object(watchdog, 'analyze_node_health', side_effect=node_health_returns), \
             patch('core.watchdog.CloudflareManager') as manager:
            manager.return_value.sync_subdomain.return_value = {'added': ['192.0.2.1', '192.0.2.2'], 'deleted': [], 'kept': []}
            manager.return_value.record_snapshot.return_value = {'success': True, 'records': []}

            report = watchdog.run_check_cycle()

        manager.return_value.sync_subdomain.assert_called_once_with('edge.example.test', ['192.0.2.1', '192.0.2.2'], proxied=False, ttl=60)
        pool_rep = report['pool_reports']['PoolPermissive']
        self.assertEqual(pool_rep['healthy_ips'], ['192.0.2.1', '192.0.2.2'])
