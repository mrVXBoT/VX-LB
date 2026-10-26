"""Authenticated event invalidation and status read amplification regressions."""
import io
from unittest.mock import MagicMock, patch

from core.ui_events import inventory_events
from core import web_server as web


def test_events_report_atomic_replacement_without_inventory_contents(tmp_path):
    inventory = tmp_path / 'inventory.json'
    inventory.write_text('private-password')
    ticks = [0]
    def pause(_):
        replacement = tmp_path / 'replacement'
        replacement.write_text('another-secret')
        replacement.replace(inventory)
        ticks[0] += 1
    stream = inventory_events(inventory, lambda: ticks[0] < 2, pause=pause)
    assert b'event: ready' in next(stream)
    event = next(stream)
    assert b'event: change' in event
    assert b'private-password' not in event and b'another-secret' not in event
    assert list(stream) == []


def test_heartbeat_and_revocation_do_not_require_inventory_reads(tmp_path):
    now = [0]
    authorized = [True]
    def pause(_):
        now[0] += 15
    stream = inventory_events(tmp_path / 'absent', lambda: authorized[0], pause=pause, clock=lambda: now[0])
    next(stream)
    assert next(stream) == b': heartbeat\n\n'
    authorized[0] = False
    assert list(stream) == []


def handler(path, authenticated=True):
    request = web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
    request.path = path
    request._is_authenticated = MagicMock(return_value=authenticated)
    request._send_json = MagicMock()
    return request


def test_stream_requires_authentication():
    request = handler('/api/events', False)
    with patch.object(web, 'inventory_events') as stream:
        request.do_GET()
    stream.assert_not_called()
    assert request._send_json.call_args.args[1] == 401


def test_stream_headers_flush_and_disconnect():
    request = handler('/api/events')
    request.send_response = MagicMock()
    request.send_header = MagicMock()
    request.end_headers = MagicMock()
    request.wfile = io.BytesIO()
    with patch.object(web, 'inventory_events', return_value=iter([b'event: ready\ndata: {}\n\n'])):
        request.do_GET()
    assert request.close_connection
    request.send_header.assert_any_call('Content-Type', 'text/event-stream; charset=utf-8')
    request.send_header.assert_any_call('X-Accel-Buffering', 'no')
    assert b'event: ready' in request.wfile.getvalue()


def test_status_reads_one_snapshot_for_many_nodes_and_redacts_job_errors():
    nodes = [{'ip': f'192.0.2.{i}', 'server_name': str(i)} for i in range(1, 101)]
    data = {'pools': {'p': {'nodes': nodes, 'node_removals': {
        '192.0.2.1': {'status': 'failed', 'ip': '192.0.2.1', 'error': 'SSH fixture-password', 'force': True}}}},
        'iran_servers': [{'password': 'fixture-password'}], 'kharej_servers': [{}],
        'node_telemetry': {'p:192.0.2.1': {'status': 'HEALTHY'}}}
    request = handler('/api/status')
    with patch.object(web, 'load_data', return_value=data) as load, \
         patch.object(web, 'get_dashboard_domain_config', return_value={}), \
         patch.object(web, 'TelemetryWatchdog') as watchdog, \
         patch.object(web, 'get_servers') as servers:
        watchdog.return_value.is_daemon_running.return_value = False
        watchdog.return_value.get_daemon_pid.return_value = None
        request.do_GET()
    load.assert_called_once()
    servers.assert_not_called()
    watchdog.return_value.get_node_telemetry.assert_not_called()
    payload = request._send_json.call_args.args[0]
    assert len(payload['pools'][0]['nodes']) == 100
    assert payload['pools'][0]['nodes'][0]['status'] == 'HEALTHY'
    assert payload['iran_count'] == payload['kharej_count'] == 1
    assert 'fixture-password' not in str(payload)
    assert 'force' not in payload['pools'][0]['node_removals']['192.0.2.1']


def test_busy_admission_does_not_wait_for_remote_worker_lock():
    from core import pool_creation, pool_tasks, node_removal
    busy_data = {'pool_tasks': {'other': {'id': 'active', 'status': 'running'}}}
    for module, arguments in ((pool_creation, ({'pool_name':'p','transport':'wireguard','client_ports':['443'], 'kharej_server':{'ip':'198.51.100.1'},'iran_servers':[{'ip':'192.0.2.1'}]},)), (pool_tasks, ('p', 'delete')),
                              (node_removal, ('p', '192.0.2.1'))):
        with patch.object(module, 'load_data', return_value=busy_data), \
             patch.object(module, 'mutation_lock') as lock:
            assert module.start(*arguments)[0] is False
        lock.assert_not_called()
