"""A manager upgrade must read existing LD-BP monitors without redeploying tunnels."""
import shlex
import subprocess
import sys
import time
from unittest.mock import patch

import pytest

from core.watchdog import TelemetryWatchdog


@pytest.mark.parametrize('family', ['legacy', 'current', 'both', 'legacy-rotated', 'missing'])
def test_actual_remote_reader_selects_one_log_family(tmp_path, family):
    stamp = time.strftime('%Y-%m-%d %H:%M:%S')
    success = f'[{stamp}] USER_SESSION_ACTIVE | port=8443 | client=192.0.2.30:1000 | bytes_rx=10000 bytes_ack=10000\n'
    current = tmp_path / 'vxlb.log'
    legacy = tmp_path / 'bp.log'
    if family in ('legacy', 'both'):
        # When both exist, only current logs should provide evidence.
        legacy.write_text(success if family == 'legacy' else success.replace('USER_SESSION_ACTIVE', 'SESSION_CLOSED_STALLED').replace('192.0.2.30', '192.0.2.40'))
    if family in ('current', 'both'):
        current.write_text(success)
    if family == 'legacy-rotated':
        (tmp_path / 'bp.log.1').write_text(success)

    def execute(command):
        if command.startswith('ss '):
            return 0, '', ''
        script = shlex.split(command)[2]
        script = script.replace('/var/log/vxlb-user-connections.log', str(current))
        script = script.replace('/var/log/bp-user-connections.log', str(legacy))
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, check=True)
        return 0, result.stdout, result.stderr

    watchdog = TelemetryWatchdog()
    with patch('core.watchdog.SSHManager') as ssh, \
         patch.object(watchdog, 'get_node_telemetry', return_value={}), \
         patch.object(watchdog, 'save_node_telemetry'):
        ssh.return_value.connect.return_value = (True, '')
        ssh.return_value.execute.side_effect = execute
        result = watchdog.analyze_node_health('pool', {'ip': '192.0.2.1'}, ['8443'])
    assert result[0] == ('IDLE' if family == 'missing' else 'HEALTHY')
    assert result[3]['8443']['independent_clients'] == 0
