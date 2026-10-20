"""Exercise the standalone WireGuard data challenge, including TCP truncation."""
import socket
import subprocess
import sys

import pytest
from core.wireguard_tools import ECHO_RESPONDER_SCRIPT, NONCE_PROBE_SCRIPT


@pytest.mark.parametrize('truncate', [False, True])
def test_large_tcp_and_udp_nonce_challenge(truncate):
    with socket.socket() as allocation:
        allocation.bind(('127.0.0.1', 0))
        port = allocation.getsockname()[1]
    server_code = ECHO_RESPONDER_SCRIPT
    if truncate:
        server_code = server_code.replace('conn.sendall(data)', "conn.sendall(b'wrong'); return")
    server = subprocess.Popen([sys.executable, '-c', server_code, '127.0.0.1', str(port)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert server.stdout.readline().strip() == 'READY'
        probe = subprocess.run([sys.executable, '-c', NONCE_PROBE_SCRIPT,
                                '127.0.0.1', str(port), 'ab' * 16],
                               capture_output=True, text=True, timeout=12)
        if truncate:
            assert probe.returncode != 0
            # Closing with unread request bytes can produce TCP RST instead of
            # orderly EOF. Both reject the corrupted/truncated response.
            assert 'nonce mismatch' in probe.stderr or 'Connection reset by peer' in probe.stderr
            assert 'PASS:' not in probe.stdout
        else:
            assert probe.returncode == 0, probe.stderr
            assert 'PASS:' in probe.stdout
    finally:
        server.terminate()
        server.communicate(timeout=5)


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_creation_rejects_failed_large_data_probe_without_healthy_member(monkeypatch, cleanup_fails):
    from unittest.mock import MagicMock
    from core import wireguard_adapter as wg
    from core.load_balancer import LoadBalancerManager
    state = {'pools': {}}
    ssh = MagicMock()
    ssh.execute.side_effect = lambda command, **kw: (1, '', '') if command.startswith('ip link show dev ') and not cleanup_fails else (0, 'mock_output', '')
    ssh.write_file.return_value = True
    monkeypatch.setattr(wg, 'get_pools', lambda: state['pools'])
    monkeypatch.setattr(wg, 'save_pool', lambda name, pool: state['pools'].__setitem__(name, pool))
    monkeypatch.setattr(wg, 'atomic_update', lambda fn: fn(state))
    monkeypatch.setattr(wg, 'connect', lambda server: ssh)
    monkeypatch.setattr(LoadBalancerManager, 'check_port_conflicts', lambda *args: (True, ''))
    monkeypatch.setattr(wg, 'execute_active_wireguard_probe',
                        lambda **kwargs: {'passed': False, 'error': 'TCP 64KiB timed out'})
    ok, _, _ = wg.create('qa-mtu-failure', {'ip': '192.0.2.2'},
                         [{'ip': '192.0.2.1', 'name': 'Iran'}], ['8080'])
    assert not ok
    nodes = state['pools']['qa-mtu-failure']['nodes']
    if cleanup_fails:
        assert len(nodes) == 1
        assert nodes[0]['status'] == 'FAILED'
        assert nodes[0]['provisioning'] is True
    else:
        assert nodes == []
