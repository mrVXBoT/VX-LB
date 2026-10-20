"""Managed HTTP plans and readiness/rollback gates; VPS acceptance is separate."""
from contextlib import nullcontext
import copy
import json
from unittest.mock import MagicMock
import pytest
from core import http_transport as http
from core import http_firewall_agent as firewall


def node(mode='http'):
    return dict(ip='192.0.2.1',node_name='http-'+('1'*32),engine=mode,transport=mode,
                provisioning=True,http_connect=dict(id='1'*32,token='2'*64,public_port=51000,
                    relay_backend_port=51001,carrier_local_port=51002,probe_port=51003,
                    security=dict(server_cert='SERVER CERT',server_key='SERVER KEY',client_cert='CLIENT CERT',client_key='CLIENT KEY')))


def pool(mode='http'):
    return dict(name='qa',engine=mode,transport=mode,client_ports=['8080'],kharej_server={'ip':'192.0.2.2'},nodes=[node(mode)])


@pytest.mark.parametrize('mode',['http','https'])
def test_private_probe_and_peer_keys_have_correct_ownership(mode):
    saved=pool(mode);config=http.plan(saved['nodes'][0],saved)
    assert 'SERVER KEY' not in config['client_files'].values()
    assert 'CLIENT KEY' not in config['server_files'].values()
    base=config['base']
    client=json.loads(config['client_files'][base+'/client.json'])
    server=json.loads(config['server_files'][base+'/server.json'])
    assert client['ports']==[8080,51003] and client['loopback_ports']==[51003]
    assert server['ports']==[8080,51003] and server['target_host']=='127.0.0.1'
    for role in ['server','client']:
        carrier=json.loads(config[role+'_files'][base+'/'+role+'-carrier.json'])
        assert carrier['tls'] is (mode=='https')
        assert carrier['server_name']=='vxlb-http'
        assert len(config[role+'_services'])==3
    client_fw=json.loads(config['client_files'][base+'/client-firewall.json'])
    rules=list(firewall.rules(client_fw))
    public=[r for r in rules if '-i' not in r]
    assert len(public)==2 and all(r[r.index('--dport')+1]=='8080' for r in public)
    assert all('--comment' in rule for rule in rules)


@pytest.fixture
def state(monkeypatch):
    data={'pools':{}}
    monkeypatch.setattr(http,'get_pools',lambda:data['pools'])
    monkeypatch.setattr(http,'save_pool',lambda name,pool:data['pools'].__setitem__(name,copy.deepcopy(pool)))
    monkeypatch.setattr(http,'atomic_update',lambda update:update(data))
    monkeypatch.setattr(http,'mutation_lock',nullcontext)
    from core.load_balancer import LoadBalancerManager
    monkeypatch.setattr(LoadBalancerManager,'check_port_conflicts',lambda *a,**kw:(True,''))
    return data


@pytest.mark.parametrize('probe_pass,cleanup_fails',[(True,False),(False,False),(False,True)])
def test_creation_requires_large_tcp_udp_before_marking_healthy(state,monkeypatch,probe_pass,cleanup_fails):
    monkeypatch.setattr(http,'connect',lambda server:MagicMock())
    monkeypatch.setattr(http,'install',lambda ssh:None)
    monkeypatch.setattr(http,'allocate',lambda *args:node())
    def deploy(*args):assert state['pools']['qa']['nodes'][0]['provisioning'] is True
    monkeypatch.setattr(http,'deploy',deploy)
    monkeypatch.setattr(http,'verify_listeners',lambda *args:None)
    def verify(*args):
        if not probe_pass:raise RuntimeError('large TCP/UDP failed')
        return {'passed':True,'latency_ms':1}
    monkeypatch.setattr(http,'verify',verify)
    monkeypatch.setattr(http.time,'sleep',lambda _:None)
    def cleanup(*args):
        if cleanup_fails:raise RuntimeError('cleanup failed')
    monkeypatch.setattr(http,'cleanup',cleanup)
    ok,message,saved=http.create('qa',{'ip':'192.0.2.2'},[{'ip':'192.0.2.1'}],['8080'])
    assert ok is probe_pass
    if probe_pass:
        assert saved['nodes'][0]['status']=='HEALTHY' and saved['nodes'][0]['provisioning'] is False
    elif cleanup_fails:
        assert saved['nodes'][0]['status']=='FAILED' and saved['nodes'][0]['provisioning'] is True
        assert 'cleanup failed' in saved['nodes'][0]['cleanup_error']
    else:assert saved['nodes']==[]


def test_reserved_ports_rejected_before_remote_mutation(state,monkeypatch):
    state['pools']['qa']=pool();state['pools']['qa']['nodes'][0]['provisioning']=False
    connect=MagicMock();monkeypatch.setattr(http,'connect',connect)
    ok,message=http.change_ports('qa',['51003'])
    assert not ok and 'reserved' in message
    assert state['pools']['qa']['client_ports']==['8080']
    connect.assert_not_called()


def test_partial_port_change_restores_both_attempted_hosts(state,monkeypatch):
    state['pools']['qa']=pool();state['pools']['qa']['nodes'][0]['provisioning']=False
    source,target=MagicMock(),MagicMock();sessions=iter([source,target]);calls=[]
    monkeypatch.setattr(http,'connect',lambda server:next(sessions))
    monkeypatch.setattr(http,'node_credentials',lambda saved:saved)
    def deploy(ssh,files,services):
        calls.append((ssh,files))
        if len(calls)==2:raise RuntimeError('client persistence failed')
    monkeypatch.setattr(http,'deploy',deploy)
    monkeypatch.setattr(http,'verify',lambda *args:{'passed':True})
    ok,message=http.change_ports('qa',['8081'])
    assert not ok and 'previous ports restored' in message
    assert [ssh for ssh,_ in calls]==[target,source,source,target]
    assert state['pools']['qa']['client_ports']==['8080']
    for _,files in calls[2:]:
        configs=[json.loads(value) for path,value in files.items() if path.endswith('/client.json') or path.endswith('/server.json')]
        assert configs[0]['ports']==[8080,51003]


def test_cleanup_removes_only_exact_owned_firewall_rules(monkeypatch):
    calls=[]
    def run(*args,**kwargs):
        calls.append(args)
        rows='-A INPUT -m comment --comment vxlb-http:'+('1'*32)+' -j ACCEPT\n-A INPUT -m comment --comment other-owner -j ACCEPT\n' if '-S' in args else ''
        return MagicMock(stdout=rows,returncode=0)
    monkeypatch.setattr(firewall,'command',run)
    firewall.remove({'id':'1'*32})
    deleted=[args for args in calls if '-D' in args]
    assert len(deleted)==1 and 'other-owner' not in deleted[0]
    assert not any('-F' in args or 'iptables-restore' in args for args in calls)


@pytest.mark.parametrize('passed',[True,False])
def test_probe_releases_owned_echo_before_unlock(monkeypatch,passed):
    iran,kharej=MagicMock(),MagicMock()
    stdin,stdout=MagicMock(),MagicMock()
    channel=stdout.channel
    stdout.readline.return_value='51003\n'
    kharej.client.exec_command.return_value=(stdin,stdout,MagicMock())
    events=[]
    stdin.close.side_effect=lambda:events.append('eof')
    channel.exit_status_ready.side_effect=lambda:events.append('exit') or True
    channel.close.side_effect=lambda:events.append('close')
    monkeypatch.setattr(http,'probe_lock',lambda *_:nullcontext())
    monkeypatch.setattr(http,'execute',lambda *args,**kwargs:json.dumps({'passed':passed,'protocols':['tcp','udp']}))
    if passed:
        assert http.verify(iran,kharej,node())['passed'] is True
    else:
        with pytest.raises(RuntimeError,match='nonce challenge failed'):
            http.verify(iran,kharej,node())
    assert events==['eof','exit','close']
    kharej.connect.assert_not_called()


@pytest.mark.parametrize('failure',[False,True])
def test_http_https_mode_commits_only_after_data_check_and_restores_on_failure(state,monkeypatch,failure):
    state['pools']['qa']=pool();state['pools']['qa']['nodes'][0]['provisioning']=False
    source,target=MagicMock(),MagicMock();sessions=iter([source,target]);deployed=[];probes=[]
    monkeypatch.setattr(http,'connect',lambda server:next(sessions))
    monkeypatch.setattr(http,'node_credentials',lambda saved:saved)
    monkeypatch.setattr(http,'verify_listeners',lambda *args:None)
    def deploy(ssh,files,services):
        configs=[json.loads(text) for path,text in files.items() if path.endswith('-carrier.json')]
        deployed.append(configs[0]['tls'])
    def verify(*args):
        probes.append(True)
        assert state['pools']['qa']['transport']=='http'
        if failure and len(probes)==1:raise RuntimeError('HTTPS data check failed')
        return {'passed':True}
    monkeypatch.setattr(http,'deploy',deploy);monkeypatch.setattr(http,'verify',verify)
    ok,message=http.change_mode('qa','https')
    assert ok is (not failure)
    assert deployed==([True,True,False,False] if failure else [True,True])
    saved=state['pools']['qa'];expected='http' if failure else 'https'
    assert saved['transport']==saved['engine']==expected
    assert saved['nodes'][0]['transport']==saved['nodes'][0]['engine']==expected
    assert len(probes)==(2 if failure else 1)


def test_echo_channel_timeout_reconnects_before_any_data_probe(monkeypatch):
    import paramiko
    iran,kharej=MagicMock(),MagicMock();stdin,stdout=MagicMock(),MagicMock()
    stdout.readline.return_value='51003\n';stdout.channel.exit_status_ready.return_value=True
    kharej.client.exec_command.side_effect=[paramiko.SSHException('Timeout opening channel.'),(stdin,stdout,MagicMock())]
    kharej.connect.return_value=(True,'connected')
    monkeypatch.setattr(http,'probe_lock',lambda *_:nullcontext())
    execute=MagicMock(return_value=json.dumps({'passed':True,'protocols':['tcp','udp']}))
    monkeypatch.setattr(http,'execute',execute)
    assert http.verify(iran,kharej,node())['passed']
    kharej.close.assert_called_once();kharej.connect.assert_called_once()
    assert kharej.client.exec_command.call_count==2
    execute.assert_called_once()
    stdin.close.assert_called_once()


@pytest.mark.parametrize('failure',['authentication','channel_denied','repeated_timeout'])
def test_echo_reconnect_does_not_retry_permanent_or_repeated_failures(failure):
    import paramiko
    kharej=MagicMock();kharej.connect.return_value=(True,'connected')
    error={'authentication':paramiko.AuthenticationException('denied'),'channel_denied':paramiko.ChannelException(1,'administratively prohibited'),'repeated_timeout':paramiko.SSHException('Timeout opening channel.')}[failure]
    kharej.client.exec_command.side_effect=error
    with pytest.raises(type(error)):http.open_echo(kharej,'owned echo')
    assert kharej.client.exec_command.call_count==(2 if failure=='repeated_timeout' else 1)
    assert kharej.connect.call_count==(1 if failure=='repeated_timeout' else 0)


def test_extra_owned_cleanup_failure_prevents_file_deletion():
    ssh=MagicMock()
    def cleanup(session):raise RuntimeError('owned rule remains')
    with pytest.raises(RuntimeError,match='owned rule remains'):
        http.cleanup(ssh,{'/etc/vxlb/http/owned/config.json':'{}'},[],extra_cleanup=cleanup)
    ssh.execute.assert_not_called()
