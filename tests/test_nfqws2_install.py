"""Pinned-package gates and atomic publication boundaries; no network by default."""
import hashlib
import io
import os
from pathlib import Path
import tarfile
from unittest.mock import MagicMock
import pytest
from core import nfqws2_install as installer


def test_corrupt_archive_is_rejected_before_tar_processing(tmp_path,monkeypatch):
    path=tmp_path/'bad.tar.gz';path.write_bytes(b'corrupt package')
    archive=MagicMock();monkeypatch.setattr(installer.tarfile,'open',archive)
    with pytest.raises(ValueError,match='archive SHA256 mismatch'):installer.archive_bundle(path)
    archive.assert_not_called()


@pytest.mark.parametrize('symlink',[False,True])
def test_unsafe_or_wrong_component_is_rejected_even_if_archive_hash_matches(tmp_path,monkeypatch,symlink):
    path=tmp_path/'package.tar.gz'
    with tarfile.open(path,'w:gz') as archive:
        info=tarfile.TarInfo('zapret2-'+installer.VERSION+'/binaries/linux-x86_64/nfqws2')
        if symlink:
            info.type=tarfile.SYMTYPE;info.linkname='/unexpected/target';archive.addfile(info)
        else:
            info.size=3;archive.addfile(info,io.BytesIO(b'bad'))
    monkeypatch.setattr(installer,'ARCHIVE_SHA256',hashlib.sha256(path.read_bytes()).hexdigest())
    with pytest.raises(ValueError,match='regular file' if symlink else 'component SHA256 mismatch'):
        installer.archive_bundle(path)


def ssh_commands():
    ssh=MagicMock();commands=[]
    def execute(command,**kwargs):
        commands.append(command)
        text={'uname -s':'Linux','uname -m':'x86_64','uname -r':'6.8.0-test'}.get(command,'')
        return 0,text,''
    ssh.execute.side_effect=execute
    return ssh,commands


def test_installed_verified_package_is_reused_and_lua_rechecked(monkeypatch):
    ssh,commands=ssh_commands();bundle=MagicMock()
    monkeypatch.setattr(installer,'check',lambda *args:True)
    monkeypatch.setattr(installer,'archive_bundle',bundle)
    result=installer.install(ssh)
    bundle.assert_not_called();ssh.upload_binary.assert_not_called();ssh.write_file.assert_not_called()
    assert result['version']==installer.VERSION
    assert any('--intercept=0' in command and 'type(rst)' in command for command in commands)


def test_failed_binary_upload_never_publishes_package_and_checks_stage_cleanup(monkeypatch):
    ssh,commands=ssh_commands();ssh.upload_binary.return_value=False
    monkeypatch.setattr(installer,'check',lambda *args:False)
    monkeypatch.setattr(installer,'archive_bundle',lambda *args:{'nfqws2':b'package'})
    with pytest.raises(RuntimeError,match='binary upload failed'):installer.install(ssh,archive_path='owned package')
    assert not any('os.rename' in command for command in commands)
    assert any('shutil.rmtree' in command and '.stage-' in command for command in commands)
    assert not any('--intercept=0' in command for command in commands)


def test_actual_official_archive_matches_all_component_pins():
    source=os.environ.get('VXLB_NFQWS2_QA_ARCHIVE')
    if not source:pytest.skip('Set explicit pinned release archive for package validation')
    bundle=installer.archive_bundle(source)
    assert set(bundle)=={'nfqws2','zapret-lib.lua','zapret-antidpi.lua','LICENSE.txt'}
    for name,digest in installer.COMPONENT_SHA256.items():
        assert hashlib.sha256(bundle[name]).hexdigest()==digest
