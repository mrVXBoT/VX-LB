"""Durable Slipstream runtime update contracts, with every SSH call mocked."""
import copy
from contextlib import nullcontext
from unittest.mock import MagicMock, patch
import pytest

from core import slipstream_update as update


@pytest.fixture
def state():
    pool = dict(name='dns', engine='slipstream', transport='slipstream', domain='tunnel.example.com',
                resolvers=['1.1.1.1:53'], dns_port=53, client_ports=['443'],
                slipstream_id='a'*16, slipstream_relay_port=25001,
                slipstream_security=dict(server_cert='CERT', server_key='SERVER-PRIVATE', client_cert='CERT', client_key='CLIENT-PRIVATE'),
                kharej_server={'ip': '198.51.100.10'},
                nodes=[dict(ip='192.0.2.10', slipstream_carrier_port=25002, provisioning=False)])
    data = dict(pools={'dns': pool}, iran_servers=[{'ip': '192.0.2.10'}])
    sessions = {('server', '198.51.100.10'): MagicMock(ip='198.51.100.10'),
                ('client', '192.0.2.10'): MagicMock(ip='192.0.2.10')}
    for ssh in sessions.values():
        ssh.execute.return_value = (0, '', '')
    with patch.object(update, 'load_data', side_effect=lambda: copy.deepcopy(data)), \
         patch.object(update, 'atomic_update', side_effect=lambda function: function(data)), \
         patch.object(update, 'mutation_lock', side_effect=lambda: nullcontext()), \
         patch.object(update, 'busy', return_value=False), \
         patch.object(update, 'open_sessions', return_value=sessions), \
         patch('core.load_balancer.LoadBalancerManager.check_port_conflicts', autospec=True, return_value=(True, '')), \
         patch.object(update.runtime, 'deploy') as publish, \
         patch.object(update.runtime, 'probe', return_value={'passed': True}) as probe, \
         patch.object(update, 'verify_listeners') as listeners:
        yield data, sessions, publish, probe, listeners


def test_commit_after_all_hosts_publish_and_verify(state):
    data, sessions, publish, probe, listeners = state
    def assert_old(*args):
        assert data['pools']['dns']['client_ports'] == ['443']
    publish.side_effect = assert_old
    assert update.change('dns', {'client_ports': ['443', '8443']})[0]
    pool = data['pools']['dns']
    assert pool['client_ports'] == ['443', '8443']
    assert pool['gre_update']['status'] == 'succeeded'
    assert publish.call_count == 2
    assert len(pool['gre_update']['backups']) == 2
    assert 'SERVER-PRIVATE' not in repr(pool['gre_update'])
    assert 'CLIENT-PRIVATE' not in repr(pool['gre_update'])
    assert pool['composition']['camouflage']['domain'] == pool['domain']
    for ssh in sessions.values():
        ssh.close.assert_called_once()
    listeners.assert_called_once()
    probe.assert_called_once()


def test_port_update_restarts_only_secure_relays(state):
    data, _, publish, _, _ = state
    assert update.change('dns', {'client_ports': ['8443']})[0]
    for call in publish.call_args_list:
        assert len(call.args[2]) == 1
        assert call.args[2][0].endswith('-secure.service')
        assert all(path.endswith('.json') for path in call.args[1])


def test_domain_update_restarts_carriers_and_relays(state):
    data, _, publish, _, _ = state
    assert update.change('dns', {'domain': 'other.example.com'})[0]
    assert data['pools']['dns']['domain'] == 'other.example.com'
    for call in publish.call_args_list:
        assert len(call.args[2]) == 2


def test_bad_probe_restores_files_services_and_old_inventory(state):
    data, sessions, _, probe, listeners = state
    probe.side_effect = [{'passed': False}, {'passed': True}]
    assert not update.change('dns', {'client_ports': ['8443']})[0]
    pool = data['pools']['dns']
    assert pool['client_ports'] == ['443']
    assert pool['gre_update']['status'] == 'failed'
    assert probe.call_count == 2
    for ssh in sessions.values():
        assert any('.restore-' in call.args[0] for call in ssh.execute.call_args_list)


def test_failed_rollback_keeps_recovery_lock_and_remote_snapshot_ids(state):
    data, _, _, probe, _ = state
    probe.return_value = {'passed': False}
    assert not update.change('dns', {'client_ports': ['8443']})[0]
    job = data['pools']['dns']['gre_update']
    assert job['status'] == 'rollback_failed'
    assert job['rollback_failed_nodes'] == ['data-path']
    assert job['backups']


def test_recover_uses_saved_backups_after_failed_rollback(state):
    data, _, _, probe, _ = state
    probe.return_value = {'passed': False}
    assert not update.change('dns', {'client_ports': ['8443']})[0]
    probe.return_value = {'passed': True}
    assert update.recover('dns')[0]
    assert data['pools']['dns']['gre_update']['status'] == 'failed'
    assert data['pools']['dns']['client_ports'] == ['443']


def test_recovery_rejects_tampered_backup_path_without_remote_writes(state):
    data, sessions, _, probe, _ = state
    probe.return_value = {'passed': False}
    update.change('dns', {'client_ports': ['8443']})
    data['pools']['dns']['gre_update']['backups'][0]['files'][0]['backup'] = '/etc/shadow'
    for ssh in sessions.values():
        ssh.reset_mock()
    assert not update.recover('dns')[0]
    for ssh in sessions.values():
        ssh.execute.assert_not_called()


@pytest.mark.parametrize('values', [dict(client_ports=[]), dict(client_ports=['25002']), dict(client_ports=['25001']),
                                    dict(client_ports=['53']), dict(client_ports=['bad']),
                                    dict(domain='bad; echo hacked'), dict(resolvers=[]), dict(rate_limit=200), dict(client_ports=['443'])])
def test_bad_update_never_mutates_hosts(state, values):
    data, sessions, publish, probe, _ = state
    assert not update.change('dns', values)[0]
    assert data['pools']['dns']['client_ports'] == ['443']
    assert 'gre_update' not in data['pools']['dns']
    publish.assert_not_called()
    probe.assert_not_called()
    for ssh in sessions.values():
        ssh.execute.assert_not_called()


def test_snapshot_failure_cannot_require_a_missing_backup_for_recovery(state):
    data, sessions, publish, _, _ = state
    server = sessions[('server', '198.51.100.10')]
    server.execute.return_value = (1, '', 'disk full')
    assert not update.change('dns', {'client_ports': ['8443']})[0]
    assert data['pools']['dns']['gre_update']['status'] == 'failed'
    publish.assert_not_called()
    assert not any('cp -p' in call.args[0] and 'restore-' in call.args[0] for call in server.execute.call_args_list)


def test_recovery_rejects_missing_snapshot_entries(state):
    data, sessions, _, probe, _ = state
    probe.return_value = {'passed': False}
    update.change('dns', {'client_ports': ['8443']})
    data['pools']['dns']['gre_update']['backups'] = []
    for ssh in sessions.values():
        ssh.reset_mock()
    assert not update.recover('dns')[0]
    for ssh in sessions.values():
        ssh.execute.assert_not_called()


def test_recovery_also_restores_metadata_from_saved_old_settings(state):
    data, _, _, probe, _ = state
    probe.return_value = {'passed': False}
    update.change('dns', {'client_ports': ['8443']})
    data['pools']['dns']['client_ports'] = ['8443']  # interrupted/uncertain commit
    probe.return_value = {'passed': True}
    assert update.recover('dns')[0]
    assert data['pools']['dns']['client_ports'] == ['443']


def test_manager_dispatches_port_changes_to_slipstream_without_backpack(state):
    data, *_ = state
    from core import load_balancer
    pool = data['pools']['dns']
    pool['client_ports'] = ['443', '8443']
    with patch.object(load_balancer, 'get_pools', return_value={'dns': pool}), patch.object(update, 'change', return_value=(True, 'ok')) as change:
        assert load_balancer.LoadBalancerManager.add_client_ports('dns', ['2053'])[0]
        change.assert_called_with('dns', {'client_ports': ['443', '8443', '2053']})
        assert load_balancer.LoadBalancerManager.remove_client_port('dns', '8443')[0]
        change.assert_called_with('dns', {'client_ports': ['443']})


def test_existing_recovery_endpoint_dispatches_to_slipstream():
    from core import gre
    pool = {'gre_update': {'status': 'rollback_failed', 'kind': 'slipstream_runtime'}}
    with patch.object(gre, 'get_pools', return_value={'dns': pool}), patch.object(update, 'recover', return_value=(True, 'restored')) as recover:
        assert gre.recover_update('dns')[0]
    recover.assert_called_once_with('dns')


def test_query_rate_update_applies_owned_rule_without_restarting_carrier(state):
    data, _, publish, _, _ = state
    pool = data['pools']['dns']
    pool.update(slipstream_runtime_version=2, rate_limit=200)
    assert update.change('dns', {'rate_limit': 300})[0]
    assert pool['rate_limit'] == 300
    publish.assert_called_once()
    assert publish.call_args.args[2] == []
    assert all(path.endswith('/firewall.json') for path in publish.call_args.args[1])


def test_failed_query_rule_application_restores_old_rate_without_restart(state):
    data, sessions, publish, _, _ = state
    pool = data['pools']['dns']
    pool.update(slipstream_runtime_version=2, rate_limit=200)
    server = sessions[('server', '198.51.100.10')]
    applied = []
    def execute(command, **kwargs):
        if '/firewall.py apply ' in command:
            applied.append(command)
            return (1, '', 'insertion failed') if len(applied) == 1 else (0, '', '')
        return 0, '', ''
    server.execute.side_effect = execute
    assert not update.change('dns', {'rate_limit': 300})[0]
    assert pool['rate_limit'] == 200
    assert pool['gre_update']['status'] == 'failed'
    assert len(applied) == 2
    assert not any('systemctl restart' in call.args[0] for call in server.execute.call_args_list)
