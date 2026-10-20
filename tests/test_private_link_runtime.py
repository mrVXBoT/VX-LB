"""Standalone provisioning contracts; SSH and data probes mocked explicitly."""
import copy
from contextlib import nullcontext
from unittest.mock import MagicMock, patch
import pytest
from core import private_link_runtime as runtime


@pytest.fixture
def state():
    link = dict(link_id='link-aabbccdd', link_name='one', engine_id='wireguard', status='planned',
                interface='pl_aabbccdd', private_subnet='10.100.0.0/30', tunnel_port=51820, mtu=1400,
                reservation_owner='link_one', iran_server={'ip':'192.0.2.1','private_ip':'10.100.0.1'},
                kharej_server={'ip':'198.51.100.1','private_ip':'10.100.0.2'}, port_forwarding_rules=[])
    data = dict(custom_links={'one':link}, iran_servers=[{'ip':'192.0.2.1'}], kharej_servers=[{'ip':'198.51.100.1'}],
                resource_reservations={'link_one': {'interfaces':['pl_aabbccdd'],'ipv4_subnet':'10.100.0.0/30'}})
    peers = [MagicMock(), MagicMock()]
    for peer in peers:
        peer.execute.return_value=(0,'','')
        peer.write_file.return_value=True
    with patch.object(runtime,'load_data',side_effect=lambda:copy.deepcopy(data)), \
         patch.object(runtime,'atomic_update',side_effect=lambda function:function(data)), \
         patch.object(runtime,'mutation_lock',side_effect=lambda:nullcontext()), \
         patch.object(runtime,'busy',return_value=False), \
         patch.object(runtime,'connect',side_effect=peers), \
         patch.object(runtime,'probe_pair',return_value={'passed':True,'protocols':['tcp','udp'],'directions':['iran_to_kharej','kharej_to_iran'],'latency_ms':1}) as probe:
        yield data,peers,probe


def test_real_deployment_boundary_precedes_active_status(state):
    data,peers,probe=state
    def validate_writes(*args):
        assert data['custom_links']['one']['status']=='provisioning'
        return {'passed':True,'protocols':['tcp','udp'],'directions':['iran_to_kharej','kharej_to_iran'],'latency_ms':1}
    probe.side_effect=validate_writes
    assert runtime.provision('one')[0]
    assert data['custom_links']['one']['status']=='active'
    assert data['custom_links']['one']['runtime']['interface']=='pl_aabbccdd'
    for peer in peers:
        assert peer.write_file.call_count == 4
        commands=' '.join(call.args[0] for call in peer.execute.call_args_list)
        assert 'systemctl start wg-quick@pl_aabbccdd.service' in commands
        assert 'ip route replace default' not in commands
        peer.close.assert_called_once()
    assert 'PrivateKey' not in repr(data)
    assert 'PresharedKey' not in repr(data)


def test_failed_upload_keeps_durable_ownership_and_never_marks_active(state):
    data,peers,probe=state
    peers[1].write_file.return_value=False
    assert not runtime.provision('one')[0]
    assert data['custom_links']['one']['status']=='failed'
    assert data['custom_links']['one']['runtime']['endpoints']['iran']['state']=='started'
    probe.assert_not_called()


def test_invalid_probe_result_is_not_healthy(state):
    data,_,probe=state
    probe.return_value={'passed':True}
    assert not runtime.provision('one')[0]
    assert data['custom_links']['one']['status']=='failed'


def test_reservation_mismatch_never_touches_endpoints(state):
    data,peers,_=state
    data['resource_reservations']['link_one']['interfaces']=['other']
    assert not runtime.provision('one')[0]
    for peer in peers:peer.execute.assert_not_called()
    assert data['custom_links']['one']['status']=='planned'


def test_standalone_config_uses_reserved_interface_subnet_and_owned_firewall(state):
    data,_,_=state
    cfg=runtime.spec(data['custom_links']['one'])
    assert cfg['interface']=='pl_aabbccdd'
    assert 'Address = 10.100.0.1/30' in cfg['iran_config']
    assert 'AllowedIPs = 10.100.0.2/32' in cfg['iran_config']
    assert 'vxlb-pl:link-aabbccdd' in cfg['iran_config']
    assert 'MASQUERADE' not in cfg['iran_config']
    assert cfg['iran_config'].index('PostUp') < cfg['iran_config'].index('[Peer]')


def installed(data):
    link=data['custom_links']['one']
    link['status']='active'
    link['runtime']={'driver':'wireguard','interface':link['interface'],'endpoints':{
        role:{'path':'/etc/wireguard/pl_aabbccdd.conf','service':'wg-quick@pl_aabbccdd.service','sha256':'a'*64,'state':'started'}
        for role in ('iran','kharej')}}
    return link


def test_delete_releases_reservation_only_after_both_endpoints_clean(state):
    data,peers,_=state
    link=installed(data)
    def execute(command,**kwargs):
        return (0,'a'*64+'  /etc/wireguard/pl_aabbccdd.conf','') if 'sha256sum' in command else (0,'','')
    for peer in peers:peer.execute.side_effect=execute
    assert runtime.delete('one')[0]
    assert data['custom_links']=={}
    assert data['resource_reservations']=={}
    for peer in peers:
        commands=' '.join(call.args[0] for call in peer.execute.call_args_list)
        assert 'systemctl disable wg-quick@pl_aabbccdd.service' in commands
        assert 'rm -f -- /etc/wireguard/pl_aabbccdd.conf' in commands


def test_changed_foreign_configuration_is_never_removed(state):
    data,peers,_=state
    installed(data)
    peers[0].execute.return_value=(0,'b'*64+'  /etc/wireguard/pl_aabbccdd.conf','')
    assert not runtime.delete('one')[0]
    assert data['custom_links']['one']['status']=='cleanup_failed'
    assert 'link_one' in data['resource_reservations']
    assert not any('systemctl stop' in call.args[0] for call in peers[0].execute.call_args_list)


def test_deployment_error_explains_why_cleanup_is_required(state):
    data,peers,probe=state
    def execute(command,**kwargs):
        if 'systemctl start wg-quick@pl_aabbccdd.service' in command:
            return (1,'','wg-quick start failed')
        return (0,'','')
    peers[1].execute.side_effect=execute
    ok,message=runtime.provision('one')
    assert not ok
    assert 'wg-quick start failed' in message
    link=data['custom_links']['one']
    assert link['status']=='failed'
    assert 'wg-quick start failed' in link['error']
    assert 'owned remote resources must be cleaned before retry' in link['error']
    probe.assert_not_called()


def test_delete_tolerates_unloaded_wireguard_service_during_partial_cleanup(state):
    data,peers,_=state
    installed(data)
    def execute(command,**kwargs):
        if 'sha256sum' in command:
            return (0,'a'*64+'  /etc/wireguard/pl_aabbccdd.conf','')
        if 'systemctl stop wg-quick@pl_aabbccdd.service' in command:
            return (1,'','Unit wg-quick@pl_aabbccdd.service not loaded.')
        return (0,'','')
    peers[0].execute.side_effect=execute
    assert runtime.delete('one')[0]
    assert data['custom_links']=={}


def test_missing_wireguard_tools_trigger_install_before_config_write(state):
    data,peers,_=state
    calls={'n':0}
    def execute(command,**kwargs):
        if command.startswith('command -v wg'):
            calls['n']+=1
            return (1,'','not found') if calls['n']==1 else (0,'','')
        return (0,'','')
    peers[0].execute.side_effect=execute
    with patch.object(runtime.WireGuardAdapter,'install',return_value=(True,'installed')) as install:
        assert runtime.provision('one')[0]
    assert install.call_count==1
    commands=[call.args[0] for call in peers[0].execute.call_args_list]
    first_preflight=next(i for i,c in enumerate(commands) if c.startswith('command -v wg'))
    assert commands[first_preflight+1].startswith('command -v wg')


def test_planned_dependent_link_cannot_be_deleted(state):
    data,peers,_=state
    data['custom_links']['one']['dependents']=['active-relay']
    assert not runtime.delete('one')[0]
    assert 'one' in data['custom_links']
    for peer in peers:peer.execute.assert_not_called()
