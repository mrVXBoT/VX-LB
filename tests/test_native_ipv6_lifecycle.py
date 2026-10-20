"""Native IPv6 creation must retain ownership until verified cleanup completes."""
import importlib
from unittest.mock import MagicMock, patch
import pytest


@pytest.mark.parametrize('engine', ['gre6', 'ip6ip6'])
@pytest.mark.parametrize('cleanup_fails', [False, True])
def test_failed_data_probe_never_marks_native_node_healthy(engine, cleanup_fails):
    module = importlib.import_module('core.' + engine)
    source = {'ip': '2001:db8::1', 'password': 'test'}
    target = {'ip': '2001:db8::2', 'password': 'test'}
    data = {'pools': {'qa': {'kharej_server': target, 'client_ports': [443], 'nodes': []}}}
    iface = 'native-test'
    conf = dict(interface=iface, service_name=f'ldbp-{engine}-{iface}.service',
                config_path=f'/etc/ldbp/{engine}/{iface}.json',
                iran_service_unit='test unit', kharej_service_unit='test unit', mtu=1280,
                local_ip=source['ip'], remote_ip=target['ip'],
                private_addressing=dict(iran_ipv4='10.206.1.1', kharej_ipv4='10.206.1.2',
                                        iran_ipv6='fd00:1::1', kharej_ipv6='fd00:1::2'))
    adapter = MagicMock()
    adapter.install.return_value = (True, 'ready')
    adapter.configure.return_value = conf
    adapter.start.return_value = (True, 'started')
    ssh = MagicMock()
    ssh.execute.return_value = (0, '', '')
    def write(path, content):
        # Ownership must already exist before any artifact reaches a server.
        assert data['pools']['qa']['nodes'][0]['provisioning'] is True
        return True
    ssh.write_file.side_effect = write
    with patch('core.storage.get_pools', side_effect=lambda: data['pools']), \
         patch('core.storage.atomic_update', side_effect=lambda update: update(data)), \
         patch('core.adapter_registry.get_adapter', return_value=adapter), \
         patch.object(module, 'connect', return_value=ssh), \
         patch('core.private_link_health.probe_pair', side_effect=RuntimeError('large TCP failed')), \
         patch('core.native_ipv6_lifecycle.cleanup_endpoint', side_effect=RuntimeError('cleanup failed') if cleanup_fails else None):
        ok, message = module.add('qa', source)
    assert ok is False
    assert 'large TCP failed' in message
    nodes = data['pools']['qa']['nodes']
    if cleanup_fails:
        assert len(nodes) == 1
        assert nodes[0]['status'] == 'FAILED'
        assert nodes[0]['provisioning'] is True
        assert 'cleanup failed' in nodes[0]['cleanup_error']
    else:
        assert nodes == []


def test_deferred_annotations_resolve_on_supported_python_versions():
    from typing import get_type_hints
    from core.gre6 import connect
    from core.overlay_tunnels_adapter import GeneveIpsecAdapter
    assert get_type_hints(connect)['return']
    assert get_type_hints(GeneveIpsecAdapter.probe)['return'] is dict


@pytest.mark.parametrize('engine', ['gre6', 'ip6ip6'])
@pytest.mark.parametrize('rollback_fails', [False, True])
def test_partial_mtu_update_rolls_back_both_attempted_endpoints(engine, rollback_fails):
    module = importlib.import_module('core.' + engine)
    node = {'ip': '2001:db8::1', 'node_name': 'native-test', engine: {'local_private': 'fd00:1::1', 'remote_private': 'fd00:1::2'}}
    state = {'pools': {'qa': {'kharej_server': {'ip': '2001:db8::2'}, engine + '_mtu': 1280, 'nodes': [node]}}}
    adapter = MagicMock()
    adapter.modify.side_effect = [(True, 'Iran changed'), (False, 'Kharej persistence failed')]
    adapter.rollback.return_value = (not rollback_fails, 'restore failed' if rollback_fails else 'restored')
    with patch('core.storage.get_pools', return_value=state['pools']), \
         patch('core.storage.atomic_update', side_effect=lambda update: update(state)), \
         patch('core.adapter_registry.get_adapter', return_value=adapter), \
         patch('core.kernel_relay_ports.node_credentials', side_effect=lambda value: value), \
         patch.object(module, 'connect', side_effect=[MagicMock(), MagicMock()]), \
         patch('core.private_link_health.probe_pair', return_value={'passed': True}):
        ok, message = module.change_mtu('qa', 1288)
    assert ok is False
    assert state['pools']['qa'][engine + '_mtu'] == 1280
    assert adapter.rollback.call_count == 2
    assert ('rollback unverified' in message) is rollback_fails
    assert ('restored MTU 1280' in message) is not rollback_fails
