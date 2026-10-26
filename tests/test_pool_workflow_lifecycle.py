"""Creation/migration contract tests: no real server or privileged command runs."""
import copy
import io
import json
import threading
from contextlib import nullcontext
from unittest.mock import MagicMock, patch

import pytest

from core import pool_creation as creation
from core import transport_change as change
from core.load_balancer import LoadBalancerManager
from core.pool_workflow import pool_ready, operation_options, public_change_job
from core.tunnel import SUPPORTED_TRANSPORTS


@pytest.fixture
def state(monkeypatch):
    pool = dict(name='prod', engine='gost', transport='gost', client_ports=['443', '80'],
                kharej_server={'ip': '198.51.100.1'},
                nodes=[{'ip': '192.0.2.1', 'node_name': 'first'},
                       {'ip': '192.0.2.2', 'node_name': 'second'}],
                camouflage={'profile': 'shadowsocks-tcp', 'password': 'source-secret'},
                subdomain='edge.example.com', dns_routing={}, dns_policy='strict',
                cloudflare={'profile_id': 'dns'}, standby_ip='198.51.100.99')
    data = {'pools': {'prod': pool}, 'pool_creations': {}}
    for module in (creation, change):
        monkeypatch.setattr(module, 'load_data', lambda: copy.deepcopy(data))
        monkeypatch.setattr(module, 'atomic_update', lambda update: update(data))
        monkeypatch.setattr(module, 'mutation_lock', nullcontext)
    monkeypatch.setattr(change, 'routing_lock', nullcontext)
    monkeypatch.setattr(change, '_resolve_server', lambda server, role: copy.deepcopy(server))
    monkeypatch.setattr(change, 'connect', lambda server: MagicMock())
    return data


def queue(state, target='waterwall', **arguments):
    original = copy.deepcopy(state['pools']['prod'])
    state['pools']['prod']['transport_change'] = dict(
        id='migration-test', status='queued', **{'from': original['transport'], 'to': target},
        from_engine=original['engine'], to_engine=change.get_engine_for_transport(target),
        arguments=arguments, changed=[], completed=0, total=2)
    return original


def deploy_result(state, transport, complete=True):
    pool = dict(name='prod', transport=transport, engine=change.get_engine_for_transport(transport),
                client_ports=['443', '80'], kharej_server={'ip': '198.51.100.1'},
                nodes=[dict(ip=ip, node_name=ip, provisioning=False) for ip in
                       (['192.0.2.1', '192.0.2.2'] if complete else ['192.0.2.1'])])
    state['pools']['prod'] = pool
    return True, 'created', copy.deepcopy(pool)


@pytest.mark.parametrize('failure', ['partial', 'exception', 'returned_error'])
def test_universal_target_failure_restores_source_and_metadata(state, failure):
    original = queue(state)
    calls = []
    def deploy(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            if failure == 'exception':
                raise RuntimeError('target start failed')
            if failure == 'returned_error':
                return False, 'target failed', {}
            return deploy_result(state, 'waterwall', complete=False)
        return deploy_result(state, 'gost')
    with patch.object(change, 'teardown_pool_runtime'), patch.object(LoadBalancerManager, 'create_pool', side_effect=deploy):
        change.run_change('prod')
    pool = state['pools']['prod']
    assert pool['transport_change']['status'] == 'rolled_back'
    for key in ('transport', 'client_ports', 'subdomain', 'dns_routing', 'dns_policy', 'cloudflare', 'standby_ip'):
        assert pool[key] == original[key]
    assert calls[1]['camouflage'] == original['camouflage']
    assert {n['ip'] for n in pool['nodes']} == {n['ip'] for n in original['nodes']}


def test_backup_is_durable_before_any_remote_teardown(state):
    queue(state)
    def teardown(pool):
        assert state['pool_backups']['prod']['nodes'] == pool['nodes']
        raise RuntimeError('cleanup failed')
    with patch.object(change, 'teardown_pool_runtime', side_effect=teardown), patch.object(LoadBalancerManager, 'create_pool') as deploy:
        change.run_change('prod')
    # A failed cleanup may not be reported as target success.
    assert state['pools']['prod']['transport_change']['status'] in {'failed', 'rollback_failed'}
    assert state['pools']['prod']['transport'] == 'gost'
    deploy.assert_not_called()


def test_universal_restart_recovers_pool_even_during_inventory_swap(state):
    original = queue(state)
    backup = copy.deepcopy(state['pools'].pop('prod'))
    state['pool_backups'] = {'prod': backup}
    assert change.busy(state)
    assert creation.project(state)['prod']['transport_change']['status'] == 'queued'
    with patch.object(change, 'teardown_pool_runtime'), patch.object(LoadBalancerManager, 'create_pool', side_effect=lambda **kw: deploy_result(state, 'gost')):
        change.run_change('prod', recovering=True)
    assert state['pools']['prod']['transport_change']['status'] == 'rolled_back'
    assert state['pools']['prod']['transport'] == original['transport']
    assert 'prod' not in state.get('pool_backups', {})


def test_universal_restart_recovers_after_target_replaced_the_job_record(state):
    queue(state)
    state['pool_backups'] = {'prod': copy.deepcopy(state['pools']['prod'])}
    deploy_result(state, 'waterwall')
    assert 'transport_change' not in state['pools']['prod']
    assert creation.project(state)['prod']['transport_change']['status'] == 'queued'
    with patch.object(change, 'teardown_pool_runtime'), patch.object(LoadBalancerManager, 'create_pool', side_effect=lambda **kw: deploy_result(state, 'gost')):
        change.run_change('prod', recovering=True, job_id='migration-test')
    assert state['pools']['prod']['transport_change']['status'] == 'rolled_back'
    assert state['pools']['prod']['transport'] == 'gost'


def test_explicit_abandonment_archives_backup_and_releases_lock(state):
    queue(state)
    state['pools']['prod']['transport_change']['status'] = 'rollback_failed'
    state['pool_backups'] = {'prod': copy.deepcopy(state['pools']['prod'])}
    # force_clear_change imports the real storage entry point separately.
    with patch('core.storage.load_data', side_effect=lambda: copy.deepcopy(state)):
        assert change.force_clear_change('prod')[0]
    assert not change.busy(state)
    assert 'prod' in state['abandoned_pool_backups']


def test_universal_rollback_failure_remains_visible_and_locked(state):
    queue(state)
    with patch.object(change, 'teardown_pool_runtime'), patch.object(LoadBalancerManager, 'create_pool', side_effect=RuntimeError('deployment failed')):
        change.run_change('prod')
    assert state['pools']['prod']['transport_change']['status'] == 'rollback_failed'
    assert 'prod' in state['pool_backups']
    assert change.busy(state)


@pytest.mark.parametrize('transport,settings', [
    ('gost', {'profile': 'grpc-tls'}), ('waterwall', {'mode': 'reverse'}),
    ('frp', {'mode': 'udp'}), ('rathole', {'transport': 'noise'}),
])
def test_same_transport_new_profile_is_admitted(state, transport, settings):
    pool = state['pools']['prod']
    pool.update(transport=transport, engine=transport, camouflage={})
    ok, message = change.start_change('prod', transport, background=False, camouflage=settings)
    assert ok, message
    assert pool['transport_change']['arguments']['camouflage'] == settings


def test_migration_thread_failure_does_not_leave_queued_lock(state):
    with patch.object(change.threading, 'Thread', side_effect=RuntimeError('cannot start')):
        ok, _ = change.start_change('prod', 'waterwall')
    assert not ok
    assert not change.busy(state)
    assert state['pools']['prod']['transport_change']['status'] == 'failed'


@pytest.mark.parametrize('target', ['http', 'https'])
def test_connect_engine_is_not_misclassified_as_backpack(target):
    assert change.get_engine_for_transport(target) == target


def test_internal_call_cannot_bypass_packet_migration_policy(state):
    assert not change.start_change('prod', 'fake-sni', background=False)[0]


def test_worker_does_not_replay_finished_change(state):
    queue(state)
    state['pools']['prod']['transport_change']['status'] = 'succeeded'
    with patch.object(change, 'teardown_pool_runtime') as teardown:
        change.run_change('prod')
    teardown.assert_not_called()


@pytest.mark.parametrize('value', [None, [], {}, 5])
def test_creation_rejects_malformed_requests_without_job(state, value):
    with patch.object(creation.threading, 'Thread') as thread:
        ok, _ = creation.start(value)
    assert not ok
    assert not state['pool_creations']
    thread.assert_not_called()


def test_creation_worker_requires_every_node_to_be_ready(state):
    arguments = dict(pool_name='new', transport='tcp', client_ports=['443'],
                     kharej_server={'ip': '198.51.100.1'}, iran_servers=[{'ip': '192.0.2.1'}])
    with patch.object(creation.threading, 'Thread'):
        assert creation.start(arguments)[0]
    def deploy(**kwargs):
        state['pools']['new'] = {'nodes': [{'ip': '192.0.2.1', 'status': 'FAILED', 'provisioning': False}]}
        return True, 'partial success', {}
    with patch.object(LoadBalancerManager, 'create_pool', side_effect=deploy):
        creation.run(arguments)
    assert state['pool_creations']['new']['status'] == 'failed'


ENGINE_TRANSPORTS = {
    'backpack': ('tcp', 'stealth', 'pck', 'kcp', 'wss', 'quic', 'ws'),
    **{name: (name,) for name in ('waterwall', 'gost', 'frp', 'hedioum', 'rathole', 'paqet',
        'gre', 'gre6', 'ip6ip6', 'tun', 'dc6', 'wireguard', 'vxlan', 'vxlan_ipsec', 'slipstream', 'http', 'https')},
    'geneve': ('geneve_ipsec',),
    'spoof': ('fake-sni', 'split-tls', 'hop-ttl-injection', 'tcp-state-desync', 'l3-ip-spoof',
        'l7-header-mutation', 'udp-raw-spoof', 'dns-spoof', 'spoof-tcp-syn', 'spoof-udp-raw',
        'spoof-icmp', 'qs-dns-hybrid', 'hyperion-x'),
}
MATRIX = [(transport, engine) for engine, transports in ENGINE_TRANSPORTS.items() for transport in transports]


@pytest.mark.parametrize('transport,engine', MATRIX)
def test_every_catalog_transport_resolves_to_expected_engine(transport, engine):
    assert change.get_engine_for_transport(transport) == engine


def test_engine_matrix_covers_the_entire_supported_catalog():
    assert {transport for transport, _ in MATRIX} == {item[0] for item in SUPPORTED_TRANSPORTS.values()}


@pytest.mark.parametrize('transport,engine', [(t, e) for t, e in MATRIX if e not in {'spoof', 'http', 'https'}])
def test_migration_admission_matrix(state, transport, engine):
    kwargs = {'domain': 'dns.example.com'} if transport == 'slipstream' else {}
    if transport == 'gost':
        kwargs['camouflage'] = {'profile': 'grpc'}
    ok, message = change.start_change('prod', transport, background=False, **kwargs)
    assert ok, message
    assert state['pools']['prod']['transport_change']['to_engine'] == engine


@pytest.mark.parametrize('options', [
    {'engine': 'backpack'}, {'engine': 'not-an-engine'}, {'mtu': 'bad'},
    {'mtu': -1}, {'camouflage': []}, {'camouflage': {'mode': 'invalid'}},
    {'allow_experimental': 'false'}, {'is_production': 'false'},
])
def test_bad_migration_options_never_queue_or_touch_runtime(state, options):
    with patch.object(change.threading, 'Thread') as thread:
        assert not change.start_change('prod', 'waterwall', **options)[0]
    assert 'transport_change' not in state['pools']['prod']
    thread.assert_not_called()


@pytest.mark.parametrize('status', ['FAILED', 'WARNING', 'PROVISIONING', 'DOWN', 'NEW_STATUS'])
def test_readiness_never_accepts_explicit_unready_states(status):
    assert not pool_ready({'nodes': [{'ip': '192.0.2.1', 'status': status}]}, [{'ip': '192.0.2.1'}])


@pytest.mark.parametrize('nodes', [[], [{'ip': '192.0.2.1'}]*2, [{'ip': '192.0.2.1', 'provisioning': True}],
                                 [{'ip': '192.0.2.1'}, {'ip': '192.0.2.2'}]])
def test_readiness_requires_exactly_the_requested_members(nodes):
    assert not pool_ready({'nodes': nodes}, [{'ip': '192.0.2.1'}])


def test_public_job_never_exposes_backup_arguments_or_error_credentials(state):
    queue(state, camouflage={'password': 'new-secret'})
    job = state['pools']['prod']['transport_change']
    job['error'] = 'failed using new-secret and source-secret'
    job['changed'] = [{'backup': {'token': 'node-token'}}]
    public = public_change_job(job, state)
    assert 'new-secret' not in repr(public) and 'source-secret' not in repr(public)
    assert 'arguments' not in public and 'changed' not in public


@pytest.mark.parametrize('transport', ['waterwall', 'gost', 'frp', 'rathole', 'wireguard', 'vxlan_ipsec', 'slipstream'])
def test_create_and_change_api_option_parser_keeps_values_and_types(transport):
    fields = dict(mtu=1280, tunnel_port=25000, vni=42, dst_port=14789, enable_psk=True,
                  domain='dns.example.com', resolvers=['1.1.1.1:53'], rate_limit=123,
                  camouflage={'server_name': 'edge.example.com'})
    assert operation_options(fields, transport) == fields


def test_worker_id_prevents_old_creation_thread_replaying_new_job(state):
    arguments = dict(pool_name='new', transport='tcp', client_ports=['443'],
                     kharej_server={'ip': '198.51.100.1'}, iran_servers=[{'ip': '192.0.2.1'}])
    with patch.object(creation.threading, 'Thread'):
        ok, job = creation.start(arguments)
    assert ok
    with patch.object(LoadBalancerManager, 'create_pool') as deploy:
        creation.run(arguments, job_id='stale-id')
    deploy.assert_not_called()
    assert job['status'] == 'queued'


def kernel_fakes(state):
    state['pools']['prod'].update(engine='tun', transport='tun')
    original = queue(state, 'gre', mtu=1280)
    def remove(name, node, engine, pool):
        # Checkpoint must precede a remote mutation, even if removal crashes.
        assert state['pools'][name]['transport_change']['changed']
        assert name in state['pool_backups']
        state['pools'][name]['nodes'] = [n for n in state['pools'][name]['nodes'] if n['ip'] != node['ip']]
        return True, 'removed'
    def deploy(name, server, callback=None):
        engine = state['pools'][name]['engine']
        state['pools'][name]['nodes'].append(dict(ip=server['ip'], node_name='new-'+server['ip'],
            engine=engine, provisioning=False, status='active'))
        return True, 'created'
    return original, remove, deploy


def test_kernel_partial_success_is_rejected_and_configuration_is_restored(state):
    original, remove, deploy = kernel_fakes(state)
    def partial(name, server, callback=None):
        if state['pools'][name]['engine'] == 'gre':
            return True, 'reported success but never stored node'
        return deploy(name, server)
    with patch.object(change, '_remove_node_engine', side_effect=remove), patch.object(change, '_deploy_node', side_effect=partial):
        change.run_change('prod')
    pool = state['pools']['prod']
    assert pool['transport_change']['status'] == 'rolled_back'
    for key in ('transport', 'engine', 'camouflage', 'cloudflare', 'dns_routing', 'dns_policy'):
        assert pool[key] == original[key]
    assert 'gre_mtu' not in pool


def test_kernel_restart_after_source_removal_uses_durable_checkpoint(state):
    original, remove, deploy = kernel_fakes(state)
    state['pool_backups'] = {'prod': copy.deepcopy(state['pools']['prod'])}
    pool = state['pools']['prod']
    removed = pool['nodes'].pop(0)
    pool.update(engine='gre', transport='gre')
    pool['transport_change'].update(status='changing', changed=[dict(ip=removed['ip'], backup=removed)])
    with patch.object(change, '_remove_node_engine', side_effect=remove), patch.object(change, '_deploy_node', side_effect=deploy):
        change.run_change('prod', recovering=True)
    assert pool['transport_change']['status'] == 'rolled_back'
    assert pool['engine'] == original['engine']
    assert {node['ip'] for node in pool['nodes']} == {node['ip'] for node in original['nodes']}
    assert not state['pool_backups']


CREATION_DISPATCH = {
    'http': 'core.http_transport', 'https': 'core.http_transport', 'tun': 'core.tun_adapter',
    'dc6': 'core.dc6_adapter', 'gre': 'core.gre', 'gre6': 'core.gre6', 'ip6ip6': 'core.ip6ip6',
    'waterwall': 'core.waterwall', 'gost': 'core.gost_engine', 'frp': 'core.frp_engine',
    'hedioum': 'core.hedioum_engine', 'rathole': 'core.rathole_engine', 'paqet': 'core.paqet_engine',
    'wireguard': 'core.wireguard_adapter', 'vxlan': 'core.vxlan_adapter',
    'vxlan_ipsec': 'core.vxlan_ipsec', 'geneve_ipsec': 'core.geneve', 'slipstream': 'core.slipstream_adapter',
}


@pytest.mark.parametrize('transport,module', CREATION_DISPATCH.items())
def test_creation_dispatches_to_the_concrete_adapter_after_validation(state, monkeypatch, transport, module):
    from core import load_balancer as manager
    monkeypatch.setattr(manager, 'get_pools', lambda: {})
    with patch(module+'.create', return_value=(True, 'adapter-called', {})) as create:
        ok, message, _ = LoadBalancerManager.create_pool('New Pool', {'ip': '198.51.100.1'},
            [{'ip': '192.0.2.1', 'name': 'source'}], transport, ['0443', '80'])
    assert ok and message == 'adapter-called'
    assert create.call_count == 1
    # Canonical names and ports are used even by adapter-specific entry points.
    arguments = create.call_args
    assert 'new_pool' in arguments.args or 'new_pool' in arguments.kwargs.values()
    assert ['443', '80'] in arguments.args or ['443', '80'] in arguments.kwargs.values()


@pytest.mark.parametrize('transport,module', CREATION_DISPATCH.items())
def test_invalid_creation_never_calls_any_adapter(state, monkeypatch, transport, module):
    from core import load_balancer as manager
    monkeypatch.setattr(manager, 'get_pools', lambda: {})
    with patch(module+'.create') as create:
        ok, _, _ = LoadBalancerManager.create_pool('invalid;name', {'ip': '198.51.100.1'},
            [{'ip': '192.0.2.1'}], transport, ['443'])
    assert not ok
    create.assert_not_called()


@pytest.mark.parametrize('transport', ['l3-ip-spoof', 'udp-raw-spoof', 'dns-spoof', 'spoof-tcp-syn',
    'spoof-udp-raw', 'spoof-icmp', 'qs-dns-hybrid', 'hyperion-x'])
def test_unavailable_creation_is_rejected_before_queue(state, transport):
    with patch.object(creation.threading, 'Thread') as thread:
        ok, _ = creation.start(dict(pool_name='new', transport=transport, client_ports=['443'],
            kharej_server={'ip': '198.51.100.1'}, iran_servers=[{'ip': '192.0.2.1'}]))
    assert not ok
    thread.assert_not_called()


def test_old_migration_worker_cannot_run_a_replacement_job(state):
    queue(state)
    with patch.object(change, 'teardown_pool_runtime') as teardown:
        change.run_change('prod', job_id='old-job')
    teardown.assert_not_called()


def test_simultaneous_admission_accepts_only_one_operation(state, monkeypatch):
    lock = threading.RLock()
    monkeypatch.setattr(change, 'mutation_lock', lambda: lock)
    monkeypatch.setattr(creation, 'mutation_lock', lambda: lock)
    barrier = threading.Barrier(2)
    results = []
    def create():
        barrier.wait()
        results.append(creation.start(dict(pool_name='new', transport='tcp', client_ports=['80'],
            kharej_server={'ip': '198.51.100.1'}, iran_servers=[{'ip': '192.0.2.1'}]))[0])
    def migrate():
        barrier.wait()
        results.append(change.start_change('prod', 'waterwall', background=False)[0])
    # Construct real workers before mocking the deployment thread factory.
    workers = [threading.Thread(target=create), threading.Thread(target=migrate)]
    with patch.object(creation.threading, 'Thread'):
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=3)
    assert sorted(results) == [False, True]


@pytest.mark.parametrize('path', ['/api/pools/create', '/api/pools/transport'])
def test_api_round_trip_preserves_profile_and_network_options(state, path):
    from core import web_server as web
    payload = dict(name='new', pool='prod', transport='vxlan_ipsec', engine='kernel',
        kharej_ip='198.51.100.1', iran_ips=['192.0.2.1'], client_ports=['443'],
        vni=42, dst_port=14789, mtu=1280, enable_psk=True,
        resolvers=['1.1.1.1:53'], camouflage={'profile': 'grpc'})
    handler = web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
    raw = json.dumps(payload).encode()
    handler.path, handler.headers, handler.rfile = path, {'Content-Length': str(len(raw))}, io.BytesIO(raw)
    handler._is_authenticated = MagicMock(return_value=True)
    handler._send_json = MagicMock()
    with patch.object(web, 'get_servers', side_effect=lambda role: [{'ip': '198.51.100.1' if role == 'kharej' else '192.0.2.1'}]), \
         patch.object(web, 'get_pools', return_value=state['pools']), \
         patch.object(creation, 'start', return_value=(True, {'status': 'queued'})) as create, \
         patch.object(web, 'start_change', return_value=(True, 'queued')) as migrate:
        handler._do_POST()
    assert handler._send_json.call_args.args[1] == 202
    admitted = create.call_args.args[0] if path.endswith('create') else migrate.call_args.kwargs
    for key in ('vni', 'dst_port', 'mtu', 'enable_psk', 'resolvers', 'camouflage'):
        assert admitted[key] == payload[key]


@pytest.mark.parametrize('invalid', [None, [], 42, '192.0.2.1', [{}]])
def test_api_creation_rejects_invalid_server_selection(state, invalid):
    from core import web_server as web
    handler = web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
    raw = json.dumps(dict(name='new', transport='tcp', kharej_ip='198.51.100.1', iran_ips=invalid, client_ports=['443'])).encode()
    handler.path, handler.headers, handler.rfile = '/api/pools/create', {'Content-Length': str(len(raw))}, io.BytesIO(raw)
    handler._is_authenticated = MagicMock(return_value=True)
    handler._send_json = MagicMock()
    with patch.object(creation, 'start') as create:
        handler._do_POST()
    assert handler._send_json.call_args.args[1] == 400
    create.assert_not_called()
