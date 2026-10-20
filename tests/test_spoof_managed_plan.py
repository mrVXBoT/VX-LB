"""Real carrier selection, secret ownership and packet-engine dependency gates."""
import copy
import json
import pytest
from core import spoof_managed_plan as managed
from core import http_firewall_agent as firewall
from core.nfqws2_profiles import MODES


def inputs(mode):
    node=dict(engine='spoof',transport=mode,ip='192.0.2.1',spoof=dict(profile=mode,queue=45101,record_port=51004),
        http_connect=dict(id='a'*32,token='b'*64,public_port=443,relay_backend_port=51001,carrier_local_port=51002,probe_port=51003,
            security=dict(server_cert='SERVER CERT',server_key='SERVER KEY',client_cert='CLIENT CERT',client_key='CLIENT KEY')))
    pool=dict(name='packet',client_ports=['8080'],kharej_server={'ip':'192.0.2.2'})
    return node,pool


@pytest.mark.parametrize('mode',sorted(MODES))
def test_profiles_have_real_queue_gate_and_preserve_peer_key_ownership(mode):
    node,pool=inputs(mode);original=copy.deepcopy(node);plan=managed.plan(node,pool)
    assert node==original
    assert 'CLIENT KEY' not in plan['server_files'].values()
    assert 'SERVER KEY' not in plan['client_files'].values()
    queue=plan['queue_config'];assert queue['peer']=='192.0.2.2' and queue['carrier_port']==443
    base=plan['base'];client=json.loads(plan['client_files'][base+'/client-carrier.json'])
    server=json.loads(plan['server_files'][base+'/server-carrier.json'])
    assert client['tls'] is (mode!='l7-header-mutation') and server['tls']==client['tls']
    unit=plan['client_files']['/etc/systemd/system/vxlb-http-'+('a'*32)+'-client-carrier.service']
    assert plan['queue_rules_service'] in unit
    rules=plan['client_files']['/etc/systemd/system/'+plan['queue_rules_service']]
    assert 'ExecStopPost=' in rules and ' remove ' in rules
    assert plan['queue_service'] in rules
    assert '--queue-bypass' not in '\n'.join(plan['client_files'].values())


def test_tls_record_helper_is_loopback_only_required_and_firewall_scoped():
    node,pool=inputs('split-tls');plan=managed.plan(node,pool);base=plan['base'];directory=plan['queue_directory']
    carrier=json.loads(plan['client_files'][base+'/client-carrier.json'])
    helper=json.loads(plan['client_files'][directory+'/records.json'])
    assert (carrier['remote_host'],carrier['remote_port'])==('127.0.0.1',51004)
    assert helper['remote_host']=='192.0.2.2' and helper['remote_port']==443
    assert helper['listen_host']=='127.0.0.1'
    fw=json.loads(plan['client_files'][base+'/client-firewall.json'])
    rules=[r for r in firewall.rules(fw) if '51004' in r]
    assert len(rules)==1 and '-i' in rules[0] and 'lo' in rules[0] and '127.0.0.1' in rules[0]
    unit=plan['client_files']['/etc/systemd/system/vxlb-http-'+('a'*32)+'-client-carrier.service']
    assert 'vxlb-spoof-'+('a'*32)+'-records.service' in unit


@pytest.mark.parametrize('port',[443,51001,51002,51003,8080])
def test_conflicting_helper_port_is_rejected_before_deployment(port):
    node,pool=inputs('split-tls');node['spoof']['record_port']=port
    with pytest.raises(ValueError,match='overlaps'):managed.plan(node,pool)
