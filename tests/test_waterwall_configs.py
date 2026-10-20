"""
Test WaterWall chain configs for syntax and structure correctness.
Does NOT run the actual WaterWall binary (requires separate test with real binary).
"""
import json
import unittest
import uuid
from pathlib import Path
from core import waterwall


class WaterWallConfigTests(unittest.TestCase):
    def node(self):
        """Create a test node."""
        p = waterwall.profile('waterwall', {'server_name': 'tunnel.example.com'})
        return {
            'node_name': 'ldw' + 'a' * 16,
            'waterwall': {
                'profile': p,
                'uuid_tcp': str(uuid.uuid4()),
                'uuid_udp': str(uuid.uuid4()),
                'outer_port': 8443,
                'backend_port': 9443
            }
        }

    def test_chain_config_structure(self):
        """Verify chain JSON structure."""
        node = self.node()
        iran_chain, kharej_chain = waterwall.chain_configs(node, '192.0.2.1', ['443', '2053'])

        # Iran chain structure
        self.assertEqual(iran_chain['name'], f"iran-secure-{node['node_name']}")
        self.assertIsInstance(iran_chain['nodes'], list)
        self.assertGreater(len(iran_chain['nodes']), 0)

        # Kharej chain structure
        self.assertEqual(kharej_chain['name'], f"kharej-secure-{node['node_name']}")
        self.assertIsInstance(kharej_chain['nodes'], list)
        self.assertGreater(len(kharej_chain['nodes']), 0)

    def test_router_node_structure(self):
        """Verify Router node has correct syntax."""
        node = self.node()
        iran_chain, kharej_chain = waterwall.chain_configs(node, '192.0.2.1', ['443'])

        # Find router nodes
        iran_router = next((n for n in iran_chain['nodes'] if n['type'] == 'Router'), None)
        kharej_router = next((n for n in kharej_chain['nodes'] if n['type'] == 'Router'), None)

        self.assertIsNotNone(iran_router, 'Iran chain missing Router')
        self.assertIsNotNone(kharej_router, 'Kharej chain missing Router')

        # Check Router has rules with network + target and required next fallback
        for router, side in [(iran_router, 'Iran'), (kharej_router, 'Kharej')]:
            self.assertIn('next', router, f'{side} Router missing next')
            self.assertIn('rules', router['settings'], f'{side} Router missing rules')
            for rule in router['settings']['rules']:
                self.assertIn('network', rule, f'{side} rule missing network')
                self.assertIn('target', rule, f'{side} rule missing target')
                self.assertIn(rule['network'], ('tcp', 'udp'), f'{side} rule invalid network: {rule["network"]}')

    def test_vless_client_nodes(self):
        """Verify separate UUID for TCP and UDP VlessClient."""
        node = self.node()
        uuid_tcp = node['waterwall']['uuid_tcp']
        uuid_udp = node['waterwall']['uuid_udp']

        iran_chain, kharej_chain = waterwall.chain_configs(node, '192.0.2.1', ['443'])

        # Find VLESS clients in Iran (one per client port per protocol)
        tcp_vless = next((n for n in iran_chain['nodes'] if n.get('name') == 'tcp-vless-client-443'), None)
        udp_vless = next((n for n in iran_chain['nodes'] if n.get('name') == 'udp-vless-client-443'), None)

        self.assertIsNotNone(tcp_vless, 'Missing tcp-vless-client')
        self.assertIsNotNone(udp_vless, 'Missing udp-vless-client')

        self.assertEqual(tcp_vless['settings']['uuid'], uuid_tcp)
        self.assertEqual(tcp_vless['settings']['protocol'], 'tcp')

        self.assertEqual(udp_vless['settings']['uuid'], uuid_udp)
        self.assertEqual(udp_vless['settings']['protocol'], 'udp')

    def test_vless_server_settings(self):
        """Verify VlessServer authenticates both TCP and UDP UUIDs and supports both protocols."""
        node = self.node()
        uuid_tcp = node['waterwall']['uuid_tcp']
        uuid_udp = node['waterwall']['uuid_udp']
        iran_chain, kharej_chain = waterwall.chain_configs(node, '192.0.2.1', ['443'])

        # Find VLESS server in Kharej
        vless_server = next((n for n in kharej_chain['nodes'] if n.get('name') == 'vless-server'), None)
        self.assertIsNotNone(vless_server)

        # Must authenticate both UUIDs
        self.assertIn(uuid_tcp, vless_server['settings']['users'])
        self.assertIn(uuid_udp, vless_server['settings']['users'])

        # Must enable both TCP connect and UDP
        self.assertEqual(vless_server['settings']['connect'], True)
        self.assertEqual(vless_server['settings']['udp'], True)

    def test_tls_settings(self):
        """Verify TLS is configured with TLS 1.3 minimum."""
        node = self.node()
        iran_chain, kharej_chain = waterwall.chain_configs(node, '192.0.2.1', ['443'])

        # Find TLS nodes
        tls_client = next((n for n in iran_chain['nodes'] if n['type'] == 'TlsClient'), None)
        tls_server = next((n for n in kharej_chain['nodes'] if n['type'] == 'TlsServer'), None)

        self.assertIsNotNone(tls_client)
        self.assertIsNotNone(tls_server)

        # Verify TLS 1.3
        self.assertIn('h2', tls_client['settings'].get('alpns', []))
        self.assertEqual(tls_server['settings'].get('min-version'), 'TLSv1.3')
        self.assertEqual(tls_server['settings'].get('max-version'), 'TLSv1.3')

    def test_config_json_valid(self):
        """Verify configs are valid JSON."""
        node = self.node()
        iran_chain, kharej_chain = waterwall.chain_configs(node, '192.0.2.1', ['443', '2053'])

        # Should not raise
        iran_json = json.dumps(iran_chain)
        kharej_json = json.dumps(kharej_chain)

        # Should be parseable
        self.assertEqual(json.loads(iran_json), iran_chain)
        self.assertEqual(json.loads(kharej_json), kharej_chain)

    def test_node_names_unique_within_chain(self):
        """Verify all node names are unique within a chain."""
        node = self.node()
        iran_chain, kharej_chain = waterwall.chain_configs(node, '192.0.2.1', ['443'])

        iran_names = [n['name'] for n in iran_chain['nodes']]
        kharej_names = [n['name'] for n in kharej_chain['nodes']]

        self.assertEqual(len(iran_names), len(set(iran_names)), 'Duplicate node names in Iran chain')
        self.assertEqual(len(kharej_names), len(set(kharej_names)), 'Duplicate node names in Kharej chain')

    def test_all_next_targets_exist(self):
        """Verify all next/target references point to existing nodes."""
        node = self.node()
        iran_chain, kharej_chain = waterwall.chain_configs(node, '192.0.2.1', ['443'])

        for chain, side in [(iran_chain, 'Iran'), (kharej_chain, 'Kharej')]:
            node_names = {n['name'] for n in chain['nodes']}

            for n in chain['nodes']:
                # Check 'next' field if present
                if 'next' in n:
                    self.assertIn(n['next'], node_names, f"{side} {n['name']} references unknown next: {n['next']}")

                # Check Router 'target' fields
                if n['type'] == 'Router':
                    for rule in n['settings'].get('rules', []):
                        if 'target' in rule:
                            self.assertIn(rule['target'], node_names, f"{side} {n['name']} rule references unknown target: {rule['target']}")

    def test_router_destination_port_whitelist_and_blackhole(self):
        """Verify Kharej router enforces destination-port whitelist and routes non-whitelisted ports to active BlackHole."""
        node = self.node()
        node['waterwall']['probe_port'] = 9999
        iran_chain, kharej_chain = waterwall.chain_configs(node, '192.0.2.1', ['443', '8443'])

        kharej_router = next(n for n in kharej_chain['nodes'] if n['name'] == 'backend-router')
        self.assertEqual(kharej_router['next'], 'blackhole-reject')

        # Blackhole node must exist and have active mode
        blackhole = next(n for n in kharej_chain['nodes'] if n['name'] == 'blackhole-reject')
        self.assertEqual(blackhole['type'], 'BlackHole')
        self.assertEqual(blackhole['settings']['mode'], 'active')

        # Check rules require destination-port
        for rule in kharej_router['settings']['rules']:
            self.assertIn('destination-port', rule)
            self.assertEqual(rule['destination-port'], [443, 8443, 9443, 9999])

    def test_probe_listener_bound_to_localhost_only(self):
        """Verify probe port listener is strictly bound to 127.0.0.1, not 0.0.0.0."""
        node = self.node()
        node['waterwall']['probe_port'] = 9999
        iran_chain, _ = waterwall.chain_configs(node, '192.0.2.1', ['443'])

        # Main listener for user traffic on 0.0.0.0
        main_listener = next(n for n in iran_chain['nodes'] if n['name'] == 'tcp-udp-listener')
        self.assertEqual(main_listener['settings']['address'], '0.0.0.0')
        self.assertEqual(main_listener['settings']['port'], 443)

        # Probe listener on 127.0.0.1 only
        probe_listener = next(n for n in iran_chain['nodes'] if n['name'] == 'tcp-udp-probe-listener')
        self.assertEqual(probe_listener['settings']['address'], '127.0.0.1')
        self.assertEqual(probe_listener['settings']['port'], 9999)


if __name__ == '__main__':
    unittest.main()

