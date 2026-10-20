import copy
from contextlib import nullcontext
from unittest.mock import patch
import pytest
from core import pool_creation as creation

ARGS={'pool_name':'p','transport':'wireguard','client_ports':['443'],'kharej_server':{'ip':'192.0.2.2','password':'secret-pass'},'iran_servers':[{'ip':'192.0.2.1','password':'secret-pass'}]}

@pytest.fixture
def store():
    data={'pools':{},'pool_creations':{}}
    with patch.object(creation,'load_data',side_effect=lambda:copy.deepcopy(data)),patch.object(creation,'atomic_update',side_effect=lambda fn:fn(data)),patch.object(creation,'mutation_lock',side_effect=lambda:nullcontext()):
        yield data

def test_admission_persists_card_without_deployment_or_credentials(store):
    with patch.object(creation.threading,'Thread') as thread:
        ok,job=creation.start(ARGS)
    assert ok and job['status']=='queued'
    assert 'secret-pass' not in repr(store)
    assert creation.project(store)['p']['nodes'][0]['creation_pending']
    assert store['pools']=={}
    assert creation.start(ARGS)[0] is False
    thread.return_value.start.assert_called_once()

@pytest.mark.parametrize('complete',[True,False])
def test_worker_detects_partial_creation_even_when_engine_returns_success(store,complete):
    with patch.object(creation.threading,'Thread'):creation.start(ARGS)
    def deploy(**kwargs):
        kwargs['callback']('Connecting with secret-pass')
        store['pools']['p']={'nodes':[{'ip':'192.0.2.1','provisioning':not complete}]}
        return True,'error secret-pass',{}
    with patch.object(creation.LoadBalancerManager,'create_pool',side_effect=deploy):creation.run(ARGS)
    job=store['pool_creations']['p']
    assert job['status']==('succeeded' if complete else 'failed')
    assert 'secret-pass' not in repr(job)
    assert creation.project(store)['p']['creation_job']['status']==job['status']

def test_restart_is_explicit_and_does_not_replay_deployment(store):
    with patch.object(creation.threading,'Thread'):creation.start(ARGS)
    with patch.object(creation.LoadBalancerManager,'create_pool') as deploy:
        creation.recover()
        deploy.assert_not_called()
    assert store['pool_creations']['p']['status']=='failed'

def test_start_failure_is_not_left_locked(store):
    with patch.object(creation.threading,'Thread',side_effect=RuntimeError('cannot start')):
        assert creation.start(ARGS)[0] is False
    assert store['pool_creations']['p']['status']=='failed'

def test_api_accepts_creation_without_waiting_for_engine():
    import io,json
    from unittest.mock import MagicMock
    from core import web_server as web
    handler=web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
    body=json.dumps({'name':'p','transport':'wireguard','kharej_ip':'192.0.2.2','iran_ips':['192.0.2.1'],'client_ports':['443']}).encode()
    handler.path='/api/pools/create';handler.headers={'Content-Length':str(len(body))};handler.rfile=io.BytesIO(body)
    handler._is_authenticated=MagicMock(return_value=True);handler._send_json=MagicMock()
    with patch.object(web,'get_servers',side_effect=lambda role:ARGS['iran_servers'] if role=='iran' else [ARGS['kharej_server']]),patch.object(creation,'start',return_value=(True,{'status':'queued'})) as start,patch.object(web.LoadBalancerManager,'create_pool') as deploy:
        handler._do_POST()
    deploy.assert_not_called()
    assert handler._send_json.call_args.args[1]==202
    assert handler._send_json.call_args.args[0]['accepted'] is True
    assert start.call_args.args[0]['transport']=='wireguard'

def test_delete_pool_clears_creation_card_record():
    from core import storage
    data={'pools':{'p':{}},'pool_creations':{'p':{'status':'succeeded'}}}
    with patch.object(storage,'atomic_update',side_effect=lambda fn:fn(data)):
        assert storage.delete_pool('p')
    assert 'p' not in data['pool_creations']


def test_slipstream_form_fields_reach_persistent_creation_job():
    import io, json
    from unittest.mock import MagicMock
    from core import web_server as web
    handler = web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
    payload = dict(name='dns', transport='slipstream', kharej_ip='192.0.2.2',
                   iran_ips=['192.0.2.1'], client_ports=['443'],
                   domain='tunnel.example.com', resolvers=['1.1.1.1:53'], dns_port='25053', rate_limit='120')
    body = json.dumps(payload).encode()
    handler.path = '/api/pools/create'
    handler.headers = {'Content-Length': str(len(body))}
    handler.rfile = io.BytesIO(body)
    handler._is_authenticated = MagicMock(return_value=True)
    handler._send_json = MagicMock()
    with patch.object(web, 'get_servers', side_effect=lambda role: ARGS['iran_servers'] if role == 'iran' else [ARGS['kharej_server']]), patch.object(creation, 'start', return_value=(True, {'status': 'queued'})) as start:
        handler._do_POST()
    assert handler._send_json.call_args.args[1] == 202
    admitted = start.call_args.args[0]
    assert admitted['domain'] == payload['domain']
    assert admitted['resolvers'] == payload['resolvers']
    assert admitted['dns_port'] == payload['dns_port']
    assert admitted['rate_limit'] == payload['rate_limit']
