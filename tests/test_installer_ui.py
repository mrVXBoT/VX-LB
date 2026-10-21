"""Exercise installer UI with real subprocess failures, TTYs and redirected logs."""
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import subprocess
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / 'install.sh').read_text().split('\nui_banner\n', 1)[0]
BUNDLE = ROOT / 'scripts/installer-ui/renderer.bundle.mjs'


def run_ui(command, **kwargs):
    return subprocess.run(['bash', '-c', UI + '\n' + command],
                          capture_output=True, text=True, **kwargs)


def log_path(output):
    return Path(re.search(r'/[^\n]*vx-lb-install\.[^\s]+\.log', output)[0])


def test_redirected_output_keeps_command_noise_in_private_log():
    result = run_ui("run_step 'Install dependencies' bash -c 'echo noisy-pip-output'")
    assert result.returncode == 0, result.stderr
    assert '\x1b' not in result.stdout
    assert 'noisy-pip-output' not in result.stdout
    assert '[ done' in result.stdout
    log = log_path(result.stdout)
    assert 'noisy-pip-output' in log.read_text()
    assert log.stat().st_mode & 0o777 == 0o600
    log.unlink()


def test_failed_function_stops_and_preserves_exit_code():
    result = run_ui("broken() { echo checksum-mismatch; bash -c 'exit 37'; echo WRONG; }; run_step Verify broken")
    assert result.returncode == 37
    assert 'checksum-mismatch' in result.stderr
    assert 'WRONG' not in result.stderr
    assert 'failed' in result.stderr
    assert 'done' not in result.stdout
    log_path(result.stdout).unlink()


def test_no_color_disables_renderer_colors():
    if not shutil.which('node'):
        pytest.skip('Node unavailable')
    result = subprocess.run(['node', str(BUNDLE), 'success', '/opt/vx-lb', 'vx-lb', '/tmp/install.log'],
                            capture_output=True, text=True, env={**os.environ, 'NO_COLOR': '1'})
    assert result.returncode == 0, result.stderr
    assert '\x1b' not in result.stdout
    assert 'vx-lb --set-web-password' in result.stdout
    assert '/tmp/install.log' in result.stdout


@pytest.mark.parametrize('interrupt', [False, True])
def test_tty_animates_and_restores_cursor(interrupt):
    master, slave = pty.openpty()
    proc = subprocess.Popen(['bash', '-c', UI + "\nrun_step Download sleep " + ('30' if interrupt else '0.3')],
                            stdout=slave, stderr=slave, env={**os.environ, 'TERM': 'xterm-256color', 'NO_COLOR': '1'})
    os.close(slave)
    output = b''
    deadline = time.monotonic() + 5
    sent = False
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.1)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output += chunk
            if interrupt and not sent and b'\x1b[?25l' in output:
                proc.send_signal(signal.SIGTERM)
                sent = True
        proc.wait(timeout=2)
        assert proc.returncode == (143 if interrupt else 0)
        assert b'000000' in output
        assert b'\x1b[?25h' in output
        assert b'\x1b[36m' not in output
    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(master)
        match = re.search(rb'/[^\r\n]*vx-lb-install\.[^\s]+\.log', output)
        if match:
            Path(match[0].decode()).unlink(missing_ok=True)
