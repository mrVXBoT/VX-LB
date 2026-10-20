import copy
from contextlib import nullcontext
from unittest.mock import MagicMock,patch
import pytest
from core import pool_tasks as tasks
from core.transport_change import busy

@pytest.fixture
def store():
    data={'pools':{'p':{'engine':'wireguard','client_ports':['443','8443'],'nodes':[]}},'pool_tasks':{}}
    with patch.object(tasks,'load_data',side_effect=lambda:copy.deepcopy(data)),patch.object(tasks,'atomic_update',side_effect=lambda fn:fn(data)),patch.object(tasks,'mutation_lock',side_effect=lambda:nullcontext()):
        yield data

@pytest.mark.parametrize('kind,values',[('delete',None),('ports_add',['9443']),('ports_remove','443')])
def test_job_admission_and_own_worker_busy_exclusion(store,kind,values):
    with patch.object(tasks.threading,'Thread'):
        ok,job=tasks.start('p',kind,values)
    assert ok and busy(store)
    with tasks.worker_job(job['id']):
        assert not busy(store)
    assert busy(store)

@pytest.mark.parametrize('ok',[True,False])
def test_port_worker_records_result_without_blocking_itself(store,ok):
    with patch.object(tasks.threading,'Thread'):
        _,job=tasks.start('p','ports_add',['9443'])
    def operation(*args):
        assert not busy(store)
        return ok,'result'
    with patch.object(tasks.LoadBalancerManager,'add_client_ports',side_effect=operation) as action:
        tasks.run('p',job['id'])
    action.assert_called_once_with('p',['9443'])
    assert store['pool_tasks']['p']['status']==('succeeded' if ok else 'failed')

def test_restart_fails_job_without_replaying_remote_delete(store):
    with patch.object(tasks.threading,'Thread'):tasks.start('p','delete')
    with patch.object(tasks.LoadBalancerManager,'delete_entire_pool') as action:
        tasks.recover();action.assert_not_called()
    assert store['pool_tasks']['p']['status']=='failed'
    assert 'p' in store['pools']

def test_delete_failure_keeps_pool_inventory():
    from core.load_balancer import LoadBalancerManager
    pool={'kharej_server':{'ip':'192.0.2.2'},'nodes':[{'ip':'192.0.2.1','node_name':'node'}]}
    ssh=MagicMock();ssh.connect.return_value=(True,'ok')
    with patch('core.load_balancer.get_pools',return_value={'p':pool}),patch('core.load_balancer.SSHManager',return_value=ssh),patch('core.load_balancer.stop_and_remove_tunnel',return_value=False),patch('core.load_balancer.storage_delete_pool') as remove:
        assert not LoadBalancerManager.delete_entire_pool('p')[0]
        remove.assert_not_called()

@pytest.mark.parametrize('path,body,kind',[('/api/pools/delete',{'pool':'p'},'delete'),('/api/ports',{'pool':'p','action':'add','ports':['9443']},'ports_add'),('/api/ports',{'pool':'p','action':'remove','port':'443'},'ports_remove')])
def test_api_returns_accepted_without_remote_work(path,body,kind):
    import io,json
    from core import web_server as web
    handler=web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
    raw=json.dumps(body).encode();handler.path=path;handler.headers={'Content-Length':str(len(raw))};handler.rfile=io.BytesIO(raw)
    handler._is_authenticated=MagicMock(return_value=True);handler._send_json=MagicMock()
    with patch.object(tasks,'start',return_value=(True,{'status':'queued'})) as start:
        handler._do_POST()
    assert start.call_args.args[1]==kind
    assert handler._send_json.call_args.args[1]==202
    assert handler._send_json.call_args.args[0]['accepted'] is True


def slipstream_pool():
    return dict(engine='slipstream', domain='tunnel.example.com', resolvers=['1.1.1.1:53'], dns_port=53,
                client_ports=['443'], nodes=[], rate_limit=1000, slipstream_runtime_version=3,
                slipstream_id='a'*16, slipstream_relay_port=25001, slipstream_dns_backend_port=25054)


def test_slipstream_settings_admission_normalizes_only_public_changed_fields(store):
    store['pools']['p'] = slipstream_pool()
    with patch.object(tasks.threading, 'Thread'):
        ok, job = tasks.start('p', 'slipstream_settings', {'rate_limit': '120'})
    assert ok
    assert job['values'] == {'rate_limit': 120}
    assert 'slipstream_security' not in repr(job)
    with tasks.worker_job(job['id']):
        assert not busy(store)


@pytest.mark.parametrize('values', [{'private_key': 'secret'}, {'rate_limit': 'invalid'}, {'rate_limit': 1000}, []])
def test_invalid_settings_do_not_admit_background_work(store, values):
    store['pools']['p'] = slipstream_pool()
    with patch.object(tasks.threading, 'Thread') as thread:
        assert not tasks.start('p', 'slipstream_settings', values)[0]
    thread.assert_not_called()
    assert store['pool_tasks'] == {}


@pytest.mark.parametrize('success', [True, False])
def test_settings_worker_records_real_transaction_result(store, success):
    store['pools']['p'] = slipstream_pool()
    with patch.object(tasks.threading, 'Thread'):
        _, job = tasks.start('p', 'slipstream_settings', {'rate_limit': 120})
    def change(name, values):
        assert not busy(store)
        assert values == {'rate_limit': 120}
        return success, 'runtime result'
    with patch('core.slipstream_update.change', side_effect=change):
        tasks.run('p', job['id'])
    assert store['pool_tasks']['p']['status'] == ('succeeded' if success else 'failed')


def test_settings_api_returns_accepted_without_running_remote_transaction():
    import io, json
    from core import web_server as web
    handler = web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
    raw = json.dumps({'pool': 'p', 'settings': {'rate_limit': 120}}).encode()
    handler.path = '/api/pools/slipstream-settings'
    handler.headers = {'Content-Length': str(len(raw))}
    handler.rfile = io.BytesIO(raw)
    handler._is_authenticated = MagicMock(return_value=True)
    handler._send_json = MagicMock()
    with patch.object(tasks, 'start', return_value=(True, {'status': 'queued'})) as start, patch('core.slipstream_update.change') as change:
        handler._do_POST()
    change.assert_not_called()
    start.assert_called_once_with('p', 'slipstream_settings', {'rate_limit': 120})
    assert handler._send_json.call_args.args[1] == 202


@pytest.mark.parametrize('success',[True,False])
def test_http_mode_worker_persists_real_result_and_excludes_its_own_lock(store,success):
    store['pools']['p'].update(engine='http',transport='http')
    with patch.object(tasks.threading,'Thread'):
        ok,job=tasks.start('p','http_transport','https')
    assert ok and busy(store)
    def change(name,mode):
        assert not busy(store)
        assert (name,mode)==('p','https')
        return success,'verified result'
    with patch('core.http_transport.change_mode',side_effect=change) as action:
        tasks.run('p',job['id'])
    action.assert_called_once_with('p','https')
    assert store['pool_tasks']['p']['status']==('succeeded' if success else 'failed')


@pytest.mark.parametrize('current,target',[('http','http'),('tcp','https'),('https','tcp')])
def test_http_mode_rejects_unchanged_or_cross_family_before_worker(store,current,target):
    store['pools']['p']['transport']=current
    with patch.object(tasks.threading,'Thread') as thread:
        assert not tasks.start('p','http_transport',target)[0]
    thread.assert_not_called()
    assert store['pool_tasks']=={}


@pytest.mark.parametrize('current,target,code',[('http','https',202),('tcp','https',409),('https','tcp',409)])
def test_http_mode_api_admits_only_family_switch_without_remote_work(current,target,code):
    import io,json
    from core import web_server as web
    handler=web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
    raw=json.dumps({'pool':'p','transport':target}).encode()
    handler.path='/api/pools/transport';handler.headers={'Content-Length':str(len(raw))};handler.rfile=io.BytesIO(raw)
    handler._is_authenticated=MagicMock(return_value=True);handler._send_json=MagicMock()
    with patch.object(web,'get_pools',return_value={'p':{'transport':current}}),patch.object(tasks,'start',return_value=(True,{'status':'queued'})) as start,patch('core.http_transport.change_mode') as remote:
        handler._do_POST()
    remote.assert_not_called()
    if code==202:start.assert_called_once_with('p','http_transport','https')
    else:start.assert_not_called()
    assert handler._send_json.call_args.args[1]==code
