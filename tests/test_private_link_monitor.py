import copy
import json
from unittest.mock import MagicMock,patch
import pytest
from core import private_link_monitor as monitor

LINK={'link_id':'link-aabbccdd','engine_id':'wireguard','status':'active','interface':'pl_test',
      'iran_server':{'ip':'192.0.2.1','private_ip':'10.100.0.1'},'kharej_server':{'ip':'198.51.100.1','private_ip':'10.100.0.2'},'runtime':{'owned':'same'}}
DATA={'custom_links':{'one':LINK},'iran_servers':[{'ip':'192.0.2.1'}],'kharej_servers':[{'ip':'198.51.100.1'}]}
PROBE={'passed':True,'protocols':['tcp','udp'],'directions':['iran_to_kharej','kharej_to_iran'],'latency_ms':2}


def peers():
    items=[MagicMock(),MagicMock()]
    for peer in items:peer.execute.return_value=(0,json.dumps({'interface_up':True,'service_active':True,'last_handshake':1,'rx_bytes':1,'tx_bytes':2}),'')
    return items


def test_active_interfaces_only_become_healthy_after_bidirectional_data():
    targets=peers()
    with patch.object(monitor,'connect',side_effect=targets),patch.object(monitor,'probe_pair',return_value=PROBE) as probe:
        result=monitor.inspect_link(DATA,LINK)
    assert result['status']=='HEALTHY'
    probe.assert_called_once()
    for peer in targets:peer.close.assert_called_once()


def test_running_services_and_handshake_without_data_are_degraded():
    with patch.object(monitor,'connect',side_effect=peers()),patch.object(monitor,'probe_pair',side_effect=RuntimeError('no echo')):
        assert monitor.inspect_link(DATA,LINK)['status']=='DEGRADED'


def test_missing_interface_is_down_without_fake_probe():
    targets=peers()
    targets[0].execute.return_value=(0,json.dumps({'interface_up':False,'service_active':True}),'')
    with patch.object(monitor,'connect',side_effect=targets),patch.object(monitor,'probe_pair') as probe:
        assert monitor.inspect_link(DATA,LINK)['status']=='DOWN'
    probe.assert_not_called()


def test_ssh_failure_is_unverified_not_proof_of_tunnel_filtering():
    with patch.object(monitor,'connect',side_effect=RuntimeError('SSH offline')):
        assert monitor.inspect_link(DATA,LINK)['status']=='UNVERIFIED'


def test_telemetry_racing_changed_runtime_identity_is_discarded():
    data=copy.deepcopy(DATA)
    def inspect(*args):
        data['custom_links']['one']['runtime']={'owned':'changed'}
        return {'status':'HEALTHY'}
    with patch.object(monitor,'load_data',side_effect=lambda:copy.deepcopy(data)),patch.object(monitor,'atomic_update',side_effect=lambda function:function(data)),patch.object(monitor,'inspect_link',side_effect=inspect):
        assert monitor.check_cycle()=={}
    assert 'telemetry' not in data['custom_links']['one']


def test_background_cycle_is_not_started_twice():
    with patch.object(monitor,'load_data',return_value=DATA),patch.object(monitor.threading,'Thread') as thread:
        assert monitor.schedule_cycle()
        assert not monitor.schedule_cycle()
        worker=thread.call_args.kwargs['target']
        with patch.object(monitor,'check_cycle'):worker()
    assert not monitor._cycle_lock.locked()


def test_missing_endpoint_fields_are_unverified_not_proof_of_outage():
    targets=peers()
    targets[0].execute.return_value=(0,'{}','')
    with patch.object(monitor,'connect',side_effect=targets),patch.object(monitor,'probe_pair') as probe:
        assert monitor.inspect_link(DATA,LINK)['status']=='UNVERIFIED'
    probe.assert_not_called()


def test_inspection_distinguishes_existing_admin_down_interface():
    import contextlib,io,subprocess,sys
    outputs=[MagicMock(returncode=0,stdout='[{"flags":["POINTOPOINT","NOARP"]}]'),MagicMock(returncode=0,stdout='active\n')]
    captured=io.StringIO()
    with patch.object(subprocess,'run',side_effect=outputs),patch.object(sys,'argv',['inspect','pl_test','wg-quick@pl_test.service']),contextlib.redirect_stdout(captured):
        exec(monitor.INSPECT,{})
    result=json.loads(captured.getvalue())
    assert result['interface_exists'] is True
    assert result['interface_up'] is False
    assert result['service_active'] is True
