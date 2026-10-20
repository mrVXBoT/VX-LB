import copy
from contextlib import nullcontext
from unittest.mock import MagicMock, patch
import pytest
from core import link_tasks as tasks
from core.transport_change import busy


@pytest.fixture
def state():
    data=dict(pools={},custom_links={},resource_reservations={},link_tasks={},
              iran_servers=[{'ip':'192.0.2.1','password':'secret-iran'}],kharej_servers=[{'ip':'198.51.100.1','password':'secret-outside'}])
    with patch.object(tasks,'load_data',side_effect=lambda:copy.deepcopy(data)),patch.object(tasks,'atomic_update',side_effect=lambda function:function(data)),patch.object(tasks,'mutation_lock',side_effect=lambda:nullcontext()),patch.object(tasks.threading,'Thread') as thread:
        yield data,thread


def test_explicit_pair_admission_is_atomic_and_keeps_credentials_out_of_job(state):
    data,thread=state
    ok,job=tasks.start_matrix([['192.0.2.1','198.51.100.1']])
    assert ok and job['status']=='queued'
    assert len(data['custom_links'])==1
    assert len(data['resource_reservations'])==1
    assert 'secret-' not in repr(job)
    thread.return_value.start.assert_called_once()
    assert busy(data)
    with tasks.worker_job(job['id']):assert not busy(data)


@pytest.mark.parametrize('pairs',[None,[],[['192.0.2.1']], [['192.0.2.1','198.51.100.1']]*2,[['192.0.2.99','198.51.100.1']],[['::1','198.51.100.1']]])
def test_invalid_or_unknown_pairs_leave_no_links_or_jobs(state,pairs):
    data,thread=state
    assert not tasks.start_matrix(pairs)[0]
    assert data['custom_links']=={}
    assert data['resource_reservations']=={}
    assert data['link_tasks']=={}
    thread.assert_not_called()


def test_worker_excludes_own_job_from_busy_and_tracks_link_results(state):
    data,_=state
    _,job=tasks.start_matrix([['192.0.2.1','198.51.100.1']])
    def provision(name):
        assert not busy(data)
        data['custom_links'][name]['status']='active'
        return True,'verified'
    with patch.object(tasks.private_link_runtime,'provision',side_effect=provision):tasks.run(job['id'])
    assert data['link_tasks'][job['id']]['status']=='succeeded'
    assert data['link_tasks'][job['id']]['completed']==1


def test_restart_preserves_partial_remote_ownership_without_replay(state):
    data,_=state
    _,job=tasks.start_matrix([['192.0.2.1','198.51.100.1']])
    name=job['links'][0]
    data['custom_links'][name].update(status='provisioning',runtime={'owned':'retained'})
    with patch.object(tasks.private_link_runtime,'provision') as action:tasks.recover()
    action.assert_not_called()
    assert data['link_tasks'][job['id']]['status']=='failed'
    assert data['custom_links'][name]['status']=='cleanup_failed'
    assert data['custom_links'][name]['runtime']=={'owned':'retained'}


def test_delete_admission_does_not_remove_record_before_runtime_cleanup(state):
    data,_=state
    data['custom_links']['one']={'status':'planned'}
    ok,job=tasks.start_delete('one')
    assert ok and 'one' in data['custom_links']
    with patch.object(tasks.private_link_runtime,'delete',return_value=(False,'cleanup failed')):tasks.run(job['id'])
    assert 'one' in data['custom_links']
    assert data['link_tasks'][job['id']]['status']=='failed'


@pytest.mark.parametrize('path,body,target',[('/api/links/matrix',{'pairs':[['192.0.2.1','198.51.100.1']],'port':51820,'mtu':1400},'start_matrix'),('/api/links/delete',{'link':'one'},'start_delete')])
def test_web_admits_jobs_without_waiting_for_ssh(path,body,target):
    import io,json
    from core import web_server as web
    handler=web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
    raw=json.dumps(body).encode()
    handler.path=path;handler.headers={'Content-Length':str(len(raw))};handler.rfile=io.BytesIO(raw)
    handler._is_authenticated=MagicMock(return_value=True);handler._send_json=MagicMock()
    with patch.object(tasks,target,return_value=(True,{'status':'queued'})) as start,patch.object(tasks.private_link_runtime,'provision') as provision:
        handler._do_POST()
    start.assert_called_once()
    provision.assert_not_called()
    assert handler._send_json.call_args.args[1]==202
