"""Durable packet-profile ownership and queue+wire+data acceptance boundaries."""
import copy
from contextlib import nullcontext
import json
from unittest.mock import MagicMock
import pytest
from core import spoof_transport as runtime
from core.load_balancer import LoadBalancerManager


def node():
    return dict(ip='192.0.2.1',node_name='spoof-'+('a'*32),engine='spoof',transport='fake-sni',provisioning=True,
        spoof=dict(profile='fake-sni',queue=45100,fake_sni='example.com',ttl_delta=3),
        http_connect=dict(id='a'*32,token='b'*64,public_port=443,relay_backend_port=51001,carrier_local_port=51002,probe_port=51003,
            security=dict(server_cert='SERVER CERT',server_key='SERVER KEY',client_cert='CLIENT CERT',client_key='CLIENT KEY')))


def proof():return dict(passed=True,latency_ms=5,protocols=['tcp','udp'],wire={'profile':'fake-sni','passed':True},queue={'owner_pid':12})


@pytest.fixture
def state(monkeypatch):
    data={'pools':{'qa':dict(name='qa',engine='spoof',transport='fake-sni',spoof_runtime_version=1,client_ports=['8080'],nodes=[],kharej_server={'ip':'192.0.2.2'},fake_sni='example.com',ttl_delta=3)}}
    monkeypatch.setattr(runtime,'get_pools',lambda:data['pools'])
    monkeypatch.setattr(runtime,'atomic_update',lambda fn:fn(data))
    monkeypatch.setattr(runtime,'mutation_lock',lambda:nullcontext())
    monkeypatch.setattr(runtime.time,'sleep',lambda value:None)
    monkeypatch.setattr(LoadBalancerManager,'check_port_conflicts',lambda *args,**kwargs:(True,''))
    monkeypatch.setattr(runtime,'install',lambda ssh:None)
    monkeypatch.setattr(runtime,'verify_listeners',lambda *args:None)
    return data


@pytest.mark.parametrize('failure',[False,True])
def test_node_published_only_after_real_verification_and_retained_if_cleanup_fails(state,monkeypatch,failure):
    server=MagicMock();monkeypatch.setattr(runtime,'connect',lambda info:server)
    monkeypatch.setattr(runtime,'allocate',lambda *args:node())
    def deploy(*args):assert state['pools']['qa']['nodes'][0]['provisioning'] is True
    monkeypatch.setattr(runtime,'deploy',deploy)
    def verify(*args):
        if failure:raise RuntimeError('wire transformation missing')
        return proof()
    monkeypatch.setattr(runtime,'verify',verify)
    def cleanup(*args):raise RuntimeError('owned rule removal failed')
    monkeypatch.setattr(runtime,'cleanup',cleanup)
    ok,message=runtime.add('qa',{'ip':'192.0.2.1'})
    saved=state['pools']['qa']['nodes'][0]
    assert ok is (not failure)
    assert saved['provisioning'] is failure
    if failure:assert saved['status']=='FAILED' and 'cleanup' in message
    else:assert saved['status']=='HEALTHY' and saved['spoof']['wire_evidence']['passed']


def test_port_update_rolls_back_both_attempted_endpoints_and_keeps_old_inventory(state,monkeypatch):
    saved=node();saved['provisioning']=False;state['pools']['qa']['nodes']=[saved]
    source,target=MagicMock(),MagicMock();sessions=iter([source,target]);calls=[]
    monkeypatch.setattr(runtime,'connect',lambda info:next(sessions));monkeypatch.setattr(runtime,'node_credentials',lambda value:value)
    def deploy(ssh,files,services):
        calls.append(ssh)
        if len(calls)==2:raise RuntimeError('client persistence failed')
    monkeypatch.setattr(runtime,'deploy',deploy);monkeypatch.setattr(runtime,'verify',lambda *args:proof())
    ok,message=runtime.change_ports('qa',['8081'])
    assert not ok and 'previous ports restored' in message
    assert calls==[target,source,source,target]
    assert state['pools']['qa']['client_ports']==['8080']


@pytest.mark.parametrize('issue',[None,'owner','no_packets','pid','drops','wire'])
def test_data_success_alone_never_accepts_missing_queue_or_packet_effect(monkeypatch,issue):
    iran,kharej=MagicMock(),MagicMock();echo_in,echo_out=MagicMock(),MagicMock();trace_in,trace_out=MagicMock(),MagicMock()
    echo_out.readline.return_value='51003\n';echo_out.channel.exit_status_ready.return_value=True
    trace_out.readline.side_effect=['READY\n',json.dumps({'profile':'fake-sni','passed':issue!='wire','observations':{}})+'\n']
    trace_out.channel.exit_status_ready.return_value=True
    monkeypatch.setattr(runtime.http,'open_echo',lambda *args:(echo_in,echo_out,MagicMock()))
    monkeypatch.setattr(runtime.http,'probe_lock',lambda *args:nullcontext())
    iran.client.exec_command.return_value=(trace_in,trace_out,MagicMock())
    before=dict(verified=True,owner_pid=12,seen=4,kernel_dropped=0,user_dropped=0)
    after=dict(before,seen=8)
    if issue=='owner':after['verified']=False
    if issue=='no_packets':after['seen']=4
    if issue=='pid':after['owner_pid']=13
    if issue=='drops':after['kernel_dropped']=1
    statuses=iter([before,after]);monkeypatch.setattr(runtime,'queue_status',lambda *args:next(statuses))
    monkeypatch.setattr(runtime,'execute',lambda *args,**kwargs:json.dumps(proof()))
    if issue:
        with pytest.raises(RuntimeError):runtime.verify(iran,kharej,node())
    else:assert runtime.verify(iran,kharej,node())['passed']
    echo_in.close.assert_called_once();trace_in.close.assert_called()
    echo_out.channel.close.assert_called_once();trace_out.channel.close.assert_called_once()


@pytest.mark.parametrize('method,operation,args,expected',[
    ('add_node','add',('qa',{'ip':'192.0.2.3'}),('qa',{'ip':'192.0.2.3'},None)),
    ('remove_node','remove',('qa','192.0.2.1'),('qa','192.0.2.1',None)),
    ('delete_entire_pool','remove_pool',('qa',),('qa',None)),
    ('add_client_ports','change_ports',('qa',['8082']),('qa',['8080','8081','8082'])),
    ('remove_client_port','change_ports',('qa','8081'),('qa',['8080'])),
])
def test_load_balancer_routes_each_managed_packet_operation_to_correct_lifecycle(monkeypatch,method,operation,args,expected):
    from core import load_balancer
    pool=dict(engine='spoof',transport='fake-sni',spoof_runtime_version=1,client_ports=['8080','8081'],nodes=[])
    monkeypatch.setattr(load_balancer,'get_pools',lambda:{'qa':pool})
    action=MagicMock(return_value=(True,'done'));monkeypatch.setattr(runtime,operation,action)
    assert getattr(LoadBalancerManager,method)(*args)[0]
    action.assert_called_once_with(*expected)
