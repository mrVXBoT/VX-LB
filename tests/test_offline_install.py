"""Offline artifact integrity, safe update, and actual network-isolated install."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import patch
from types import SimpleNamespace

import pytest
from scripts.verify_offline_payload import verify

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def payload(tmp_path):
    (tmp_path / 'wheelhouse').mkdir()
    wheel = b'test wheel'
    (tmp_path / 'wheelhouse/example.whl').write_bytes(wheel)
    inputs = {}
    for name in ('requirements.txt', 'requirements-offline.lock'):
        (tmp_path / name).write_text('example==1\n')
        inputs[name] = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
    manifest = {'schema': 1, 'implementation': 'cpython', 'python': ['3.13'],
                'architectures': ['x86_64', 'aarch64'], 'glibc_min': '2.34',
                'inputs': inputs, 'wheels': {'example.whl': hashlib.sha256(wheel).hexdigest()}}
    (tmp_path / 'offline-manifest.json').write_text(json.dumps(manifest))
    return tmp_path


def test_payload_integrity(payload):
    assert verify(payload, check_host=False)['schema'] == 1


@pytest.mark.parametrize('change,match', [
    ('corrupt', 'checksum mismatch'), ('missing', 'differ from manifest'),
    ('extra', 'differ from manifest'), ('requirements', 'changed')])
def test_broken_payload_fails(payload, change, match):
    if change == 'corrupt':
        (payload / 'wheelhouse/example.whl').write_bytes(b'corrupt')
    elif change == 'missing':
        (payload / 'wheelhouse/example.whl').unlink()
    elif change == 'extra':
        (payload / 'wheelhouse/unexpected.whl').write_bytes(b'extra')
    else:
        (payload / 'requirements.txt').write_text('example==2\n')
    with pytest.raises(ValueError, match=match):
        verify(payload, check_host=False)


def test_unsupported_host_fails_before_install(payload):
    with patch('platform.machine', return_value='riscv64'):
        with pytest.raises(ValueError, match='Unsupported offline host'):
            verify(payload)


def test_musl_fails_with_actionable_message(payload):
    with patch('platform.machine', return_value='x86_64'), \
         patch('platform.libc_ver', return_value=('musl', '1.2')), \
         patch('sys.version_info', SimpleNamespace(major=3, minor=13)):
        with pytest.raises(ValueError, match='glibc >= 2.34'):
            verify(payload)


def installer(args, **kwargs):
    return subprocess.run(['bash', str(ROOT / 'install.sh'), *args],
                          text=True, capture_output=True, **kwargs)


@pytest.mark.parametrize('args', [['--offline', '--update'], ['--check', '--update'], ['--typo']])
def test_invalid_flags_do_not_mutate(args):
    result = installer(args)
    assert result.returncode == 2, result.stdout + result.stderr


def test_unknown_depot_architecture_fails():
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/verify_offline_depot.py'), 'riscv64'],
                            text=True, capture_output=True)
    assert result.returncode != 0
    assert 'Unsupported depot architectures' in result.stderr


def test_update_preserves_tracked_changes(tmp_path):
    shutil.copy2(ROOT / 'install.sh', tmp_path / 'install.sh')
    (tmp_path / 'main.py').write_text('# original\n')
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    subprocess.run(['git', '-C', str(tmp_path), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(tmp_path), '-c', 'user.name=Test', '-c',
                    'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
    (tmp_path / 'main.py').write_text('# precious local change\n')
    result = subprocess.run(['bash', str(tmp_path / 'install.sh'), '--update'],
                            text=True, capture_output=True)
    assert result.returncode != 0
    assert 'Nothing was reset' in result.stderr
    assert (tmp_path / 'main.py').read_text() == '# precious local change\n'


def test_bootstrap_offline_requires_local_files(tmp_path):
    env = {**os.environ, 'VX_LB_INSTALL_DIR': str(tmp_path / 'not-downloaded')}
    result = subprocess.run(['bash', '-s', '--', '--offline'],
                            input=(ROOT / 'install.sh').read_text(), env=env,
                            text=True, capture_output=True)
    assert result.returncode != 0
    assert 'Transfer and extract' in result.stderr
    assert not (tmp_path / 'not-downloaded').exists()


def test_real_install_without_network_or_system_pip(tmp_path):
    if not shutil.which('unshare'):
        pytest.skip('Linux network namespaces unavailable')
    probe = subprocess.run(['unshare', '-Urn', 'true'], capture_output=True)
    if probe.returncode:
        pytest.skip('Unprivileged network namespaces unavailable; CI uses Docker --network none')
    if sys.version_info[:2] not in [(3, v) for v in range(10, 15)]:
        pytest.skip('Host outside supported Python matrix')
    root = tmp_path / 'kit'
    root.mkdir()
    # Hardlinks keep the integration test small. Neither installer nor test edits
    # the input payload; runtime state is always created in the isolated copy.
    def link_or_copy(src, dst):
        try:
            return os.link(src, dst)
        except OSError:
            return shutil.copy2(src, dst)
    for name in ('core', 'scripts', 'bin', 'wheelhouse', 'systemd', 'web'):
        shutil.copytree(ROOT / name, root / name, copy_function=link_or_copy,
                        ignore=shutil.ignore_patterns('__pycache__'))
    for name in ('install.sh', 'main.py', 'daemon.py', 'run.sh', 'vx-lb',
                 'requirements.txt', 'requirements-offline.lock', 'offline-manifest.json'):
        shutil.copy2(ROOT / name, root / name)
    denied = tmp_path / 'no-network-commands'
    denied.mkdir()
    for command in ('git', 'curl', 'wget', 'apt-get', 'dnf', 'yum', 'pacman', 'pip3'):
        script = denied / command
        script.write_text('#!/bin/sh\necho "Unexpected download command" >&2\nexit 97\n')
        script.chmod(0o755)
    env = {**os.environ, 'PATH': f"{denied}:{os.environ['PATH']}",
           'VX_LB_BIN_DIR': str(tmp_path / 'commands'),
           'PIP_INDEX_URL': 'https://unreachable.invalid/simple'}
    def run(*args):
        result = subprocess.run(['unshare', '-Urn', 'bash', str(root / 'install.sh'), *args],
                                env=env, text=True, capture_output=True, timeout=180)
        assert result.returncode == 0, result.stdout + result.stderr
        return result
    run('--check')
    bootstrap = subprocess.run(['unshare', '-Urn', 'bash', '-s', '--', '--offline', '--check'],
                               input=(ROOT / 'install.sh').read_text(),
                               env={**env, 'VX_LB_INSTALL_DIR': str(root)},
                               text=True, capture_output=True, timeout=60)
    assert bootstrap.returncode == 0, bootstrap.stdout + bootstrap.stderr
    assert not list(root.rglob('__pycache__'))
    assert not (root / '.venv').exists()
    assert not (root / 'data').exists()
    assert not (tmp_path / 'commands').exists()
    run('--no-service')  # No --offline flag: automatic offline detection.
    run('--offline', '--no-service')  # Idempotent reinstall.
    result = subprocess.run(['unshare', '-Urn', str(tmp_path / 'commands/vx-lb'), '--list-capabilities'],
                            text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    result = subprocess.run([str(root / '.venv/bin/python'), '-m', 'pip', 'check'],
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_manifest_must_cover_requirement_inputs(payload):
    manifest_path = payload / 'offline-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    del manifest['inputs']['requirements.txt']
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='both requirements files'):
        verify(payload, check_host=False)


def test_update_fast_forwards_and_executes_new_installer(tmp_path):
    upstream = tmp_path / 'upstream'
    upstream.mkdir()
    subprocess.run(['git', 'init', '-q', '-b', 'main', str(upstream)], check=True)
    for key, value in [('user.name', 'Test'), ('user.email', 'test@example.invalid')]:
        subprocess.run(['git', '-C', str(upstream), 'config', key, value], check=True)
    shutil.copy2(ROOT / 'install.sh', upstream / 'install.sh')
    (upstream / 'main.py').write_text('# app\n')
    subprocess.run(['git', '-C', str(upstream), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(upstream), 'commit', '-qm', 'initial'], check=True)
    checkout = tmp_path / 'checkout'
    subprocess.run(['git', 'clone', '-q', str(upstream), str(checkout)], check=True)
    (checkout / 'data').mkdir()
    (checkout / 'data/inventory.json').write_text('precious runtime data')
    (upstream / 'install.sh').write_text('#!/bin/bash\necho updated-installer-executed\n')
    subprocess.run(['git', '-C', str(upstream), 'commit', '-qam', 'new installer'], check=True)
    result = subprocess.run(['bash', str(checkout / 'install.sh'), '--update'],
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'updated-installer-executed' in result.stdout
    assert (checkout / 'data/inventory.json').read_text() == 'precious runtime data'
