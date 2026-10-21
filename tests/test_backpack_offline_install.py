"""Every BackPack deployment path must work without the upstream repository."""
import hashlib
import shlex
import shutil
import subprocess
from dataclasses import replace

import pytest

from core.backpack_adapter import BackPackAdapter
from core.dependency_manifest import PLATFORM_DEPENDENCIES
from core.ssh_client import SSHManager

class Node:
    def __init__(self, arch='x86_64', installed=False, upload_ok=True, probe_ok=True, arch_ok=True):
        self.arch = arch
        self.installed = installed
        self.upload_ok = upload_ok
        self.probe_ok = probe_ok
        self.arch_ok = arch_ok
        self.commands = []
        self.uploads = []

    def execute(self, command):
        self.commands.append(command)
        # Fail immediately if either entry point ever attempts an upstream fetch.
        assert not any(word in command for word in ('curl', 'wget', 'http://', 'https://'))
        if command == 'uname -m':
            return (0, self.arch, '') if self.arch_ok else (1, '', 'architecture probe failed')
        assert '--help' in command, command
        return (0, 'installed\n', '') if self.installed else (1, '', 'not executable')

    def upload_binary(self, local, remote, mode):
        self.uploads.append((local, remote, mode))
        self.installed = self.upload_ok and self.probe_ok
        return self.upload_ok

    def install_backpack(self):
        raise AssertionError('Legacy online installer hook must never run')


@pytest.fixture(params=['legacy', 'adapter'])
def install(request):
    if request.param == 'adapter':
        return lambda node: BackPackAdapter().install(node, 'iran', {})
    return lambda node: SSHManager.ensure_backpack_installed(node)


@pytest.fixture
def depot(tmp_path, monkeypatch):
    import core.ssh_client as module
    monkeypatch.setattr(module, '__file__', str(tmp_path / 'core/ssh_client.py'))
    manifest = PLATFORM_DEPENDENCIES['backpack']
    payloads = {arch: f'verified backpack {arch}'.encode() for arch in ('x86_64', 'aarch64')}
    entries = {arch: {**manifest.architectures[arch], 'sha256': hashlib.sha256(data).hexdigest()}
               for arch, data in payloads.items()}
    monkeypatch.setitem(PLATFORM_DEPENDENCIES, 'backpack', replace(manifest, architectures=entries))
    def write(arch='x86_64', path=None, corrupt=False):
        path = tmp_path / (path or f'bin/{arch}/backpack')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'corrupt' if corrupt else payloads[arch])
        return path
    return write


def test_working_installed_binary_is_preserved_without_depot(install):
    node = Node(installed=True)
    assert install(node)[0]
    assert not node.uploads
    assert len(node.commands) == 1


@pytest.mark.parametrize('arch,canonical', [('x86_64','x86_64'), ('amd64','x86_64'),
                                          ('aarch64','aarch64'), ('arm64','aarch64')])
def test_verified_bundled_binary_is_uploaded_for_both_cpus(install, depot, arch, canonical):
    binary = depot(canonical)
    node = Node(arch=arch)
    ok, message = install(node)
    assert ok, message
    assert node.uploads == [(str(binary), '/usr/local/bin/backpack', 0o755)]


@pytest.mark.parametrize('path', ['bin/backpack', 'data/binaries/x86_64/backpack', 'data/binaries/backpack'])
def test_verified_local_cache_is_supported(install, depot, path):
    binary = depot(path=path)
    node = Node()
    assert install(node)[0]
    assert node.uploads[0][0] == str(binary)


def test_missing_depot_never_downloads_even_with_legacy_url_override(install, depot, monkeypatch):
    monkeypatch.setenv('VX_LB_BACKPACK_INSTALL_URL', 'https://upstream.invalid/install.sh')
    node = Node()
    ok, message = install(node)
    assert not ok
    assert 'Restore' in message and 'no external download' in message
    assert not node.uploads


def test_corrupt_binary_is_rejected_without_upload(install, depot):
    depot(corrupt=True)
    node = Node()
    ok, message = install(node)
    assert not ok and 'does not match pinned manifest' in message
    assert not node.uploads


def test_corrupt_primary_can_use_verified_cached_copy(install, depot):
    depot(corrupt=True)
    cached = depot(path='data/binaries/x86_64/backpack')
    node = Node()
    assert install(node)[0]
    assert node.uploads[0][0] == str(cached)


def test_wrong_architecture_payload_is_rejected(install, depot):
    depot('x86_64', path='bin/aarch64/backpack')
    node = Node(arch='aarch64')
    assert not install(node)[0]
    assert not node.uploads


def test_unverified_manifest_is_rejected(install, depot, monkeypatch):
    depot()
    manifest = PLATFORM_DEPENDENCIES['backpack']
    entries = {arch: {**info, 'is_verified': False} for arch, info in manifest.architectures.items()}
    monkeypatch.setitem(PLATFORM_DEPENDENCIES, 'backpack', replace(manifest, architectures=entries))
    node = Node()
    assert not install(node)[0]
    assert not node.uploads


@pytest.mark.parametrize('arch', ['riscv64', 'armv7l', 'not-x86_64'])
def test_unsupported_architecture_fails_without_download(install, depot, arch):
    depot()
    node = Node(arch=arch)
    ok, message = install(node)
    assert not ok and 'not supported' in message
    assert not node.uploads


def test_architecture_probe_failure_is_reported(install, depot):
    node = Node(arch_ok=False)
    ok, message = install(node)
    assert not ok and 'architecture probe failed' in message
    assert not node.uploads


def test_upload_failure_never_falls_back_online(install, depot):
    depot()
    node = Node(upload_ok=False)
    ok, message = install(node)
    assert not ok and 'upload failed' in message
    assert len(node.commands) == 2


def test_failed_execution_probe_never_falls_back_online(install, depot):
    depot()
    node = Node(probe_ok=False)
    ok, message = install(node)
    assert not ok and 'execution check' in message
    assert len(node.uploads) == 1


def test_real_bundled_backpack_is_deployed_and_runs_with_network_disabled(tmp_path):
    if not shutil.which('unshare') or subprocess.run(['unshare', '-Urn', 'true'], capture_output=True).returncode:
        pytest.skip('Unprivileged network namespaces unavailable')
    target = tmp_path / 'backpack'
    class Sandbox:
        def execute(self, command):
            command = command.replace('/usr/local/bin/backpack', shlex.quote(str(target)))
            result = subprocess.run(['unshare', '-Urn', 'sh', '-c', command],
                                    text=True, capture_output=True, timeout=30)
            return result.returncode, result.stdout, result.stderr

        def upload_binary(self, local, remote, mode):
            shutil.copy2(local, target)
            target.chmod(mode)
            return True
    ok, message = BackPackAdapter().install(Sandbox(), 'iran', {})
    assert ok, message
    assert target.exists()
    assert SSHManager.ensure_backpack_installed(Sandbox())[0]
