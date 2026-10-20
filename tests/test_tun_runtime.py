"""Managed TUN config/lifecycle checks; real carrier acceptance runs on the VPS pair."""
from contextlib import nullcontext
import copy
import json
import tomllib
from unittest.mock import MagicMock
import pytest
from core import tun_runtime as tun
from core import tun_firewall_agent as firewall


@pytest.fixture
def inventory(monkeypatch):
    state = {'pools': {}}
    monkeypatch.setattr(tun, 'get_pools', lambda: state['pools'])
    monkeypatch.setattr(tun, 'save_pool', lambda name, pool: state['pools'].__setitem__(name, copy.deepcopy(pool)))
    monkeypatch.setattr(tun, 'delete_pool', lambda name: state['pools'].pop(name, None))
    monkeypatch.setattr(tun, 'atomic_update', lambda update: update(state))
    monkeypatch.setattr(tun, 'mutation_lock', nullcontext)
    from core.load_balancer import LoadBalancerManager
    monkeypatch.setattr(LoadBalancerManager, 'check_port_conflicts', lambda *args, **kwargs: (True, ''))
    return state


def test_native_toml_has_separate_endpoints_and_authentication(inventory):
    node = tun.allocate({'ip': '192.0.2.1'}, {'ip': '192.0.2.2'}, 1280, 51000)
    for role, mode, private_key, peer_key in [('iran', 'dial', 'local_private', 'remote_private'), ('kharej', 'listen', 'remote_private', 'local_private')]:
        files, services = tun.artifacts(node, role, ['443'])
        native = tomllib.loads(next(value for path, value in files.items() if path.endswith('.toml')))['l3']
        assert native['mode'] == mode
        assert native['local_ip'] == node['tun'][private_key]+'/30'
        assert native['peer_ip'] == node['tun'][peer_key]
        assert native['iface'] == node['tun']['interface']
        assert native['carrier'] == 'udp' and len(native['token']) == 64
        assert native['auto_mtu'] is False
        assert native['mtu'] == 1280
        assert len(services) == (2 if role == 'iran' else 1)
        if role == 'iran':
            relay = next(value for path, value in files.items() if path.endswith('-relay.service'))
            assert f'Requires={services[0]}' in relay
            assert f'PartOf={services[0]}' in relay


@pytest.mark.parametrize('value', [None, '', 0, 1199, 1421, 'fast', 1280.5])
def test_invalid_mtu_never_silently_uses_a_default(value):
    with pytest.raises(ValueError):
        tun.validate_mtu(value)


@pytest.mark.parametrize('probe_pass,cleanup_fails', [(True, False), (False, False), (False, True)])
def test_ownership_and_large_data_challenge_gate_readiness(inventory, monkeypatch, probe_pass, cleanup_fails):
    ssh = MagicMock()
    monkeypatch.setattr(tun, 'connect', lambda server: ssh)
    monkeypatch.setattr(tun, 'install', lambda client: None)
    monkeypatch.setattr(tun, 'reserve_probe_port', lambda *args, **kwargs: 51000)
    def deploy(client, files, services):
        assert inventory['pools']['qa']['nodes'][0]['provisioning'] is True
    monkeypatch.setattr(tun, 'deploy', deploy)
    monkeypatch.setattr(tun, 'verify_listeners', lambda *args: None)
    def probe(*args):
        if not probe_pass:
            raise RuntimeError('TCP 64KiB failed')
        return {'passed': True, 'latency_ms': 1}
    monkeypatch.setattr(tun, 'probe_pair', probe)
    monkeypatch.setattr(tun.time, 'sleep', lambda _: None)
    def cleanup(*args):
        if cleanup_fails:
            raise RuntimeError('SSH cleanup failed')
    monkeypatch.setattr(tun, 'cleanup', cleanup)
    ok, message, pool = tun.create('qa', {'ip': '192.0.2.2'}, [{'ip': '192.0.2.1'}], ['443'])
    assert ok is probe_pass
    if probe_pass:
        assert len(pool['nodes']) == 1
        assert pool['nodes'][0]['status'] == 'HEALTHY'
        assert pool['nodes'][0]['provisioning'] is False
    elif cleanup_fails:
        assert len(pool['nodes']) == 1
        assert pool['nodes'][0]['status'] == 'FAILED'
        assert pool['nodes'][0]['provisioning'] is True
        assert 'cleanup failed' in pool['nodes'][0]['cleanup_error']
    else:
        assert pool['nodes'] == []


def test_failed_removal_retains_owned_pool(inventory, monkeypatch):
    inventory['pools']['qa'] = {'engine': 'tun', 'nodes': [{'ip': '192.0.2.1'}]}
    monkeypatch.setattr(tun, 'remove', lambda *args: (False, 'SSH failed'))
    assert tun.remove_pool('qa') == (False, 'SSH failed')
    assert 'qa' in inventory['pools']


def test_firewall_removes_only_exact_owned_comment(monkeypatch):
    config = dict(interface='lbt1234567890', role='kharej', remote_ip='192.0.2.1', peer_private='10.210.1.1', port=51000, mtu=1280)
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        chain = args[-1]
        output = f'-A {chain} -p udp -m comment --comment vxlb-tun:lbt1234567890 -j ACCEPT\n-A {chain} -p udp -m comment --comment unrelated -j ACCEPT\n' if '-S' in args else ''
        return MagicMock(stdout=output, returncode=0)
    monkeypatch.setattr(firewall, 'command', run)
    firewall.remove(config)
    deleted = [args for args in calls if '-D' in args]
    assert len(deleted) == 3
    assert all('vxlb-tun:lbt1234567890' in args and 'unrelated' not in args for args in deleted)
    assert not any('-F' in args or 'iptables-restore' in args for args in calls)
    for table, chain, rule in firewall.rules(config):
        assert '--comment' in rule
        assert 'vxlb-tun:lbt1234567890' in rule
        if table == 'mangle':
            assert rule[-1] == '1240'
