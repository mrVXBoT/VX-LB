#!/usr/bin/env python3
"""Exercise both BackPack installers with real binaries in a local sandbox.

CI runs this inside its --network none container. No real SSH host, installed
service or global executable is changed; remote operations target a temp folder.
"""
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.backpack_adapter import BackPackAdapter
from core.ssh_client import SSHManager


class Sandbox:
    def __init__(self, target):
        self.target = target
        self.uploads = 0

    def execute(self, command):
        command = command.replace('/usr/local/bin/backpack', shlex.quote(str(self.target)))
        result = subprocess.run(command, shell=True, text=True, capture_output=True, timeout=30)
        return result.returncode, result.stdout, result.stderr

    def upload_binary(self, local, remote, mode):
        assert remote == '/usr/local/bin/backpack'
        shutil.copy2(local, self.target)
        self.target.chmod(mode)
        self.uploads += 1
        return True


def main():
    for entry in ('adapter', 'legacy'):
        with tempfile.TemporaryDirectory(prefix='vxlb-backpack-check-') as folder:
            node = Sandbox(Path(folder) / 'backpack')
            for _ in range(2):
                if entry == 'adapter':
                    ok, message = BackPackAdapter().install(node, 'iran', {})
                else:
                    ok, message = SSHManager.ensure_backpack_installed(node)
                if not ok:
                    raise RuntimeError(f'{entry}: {message}')
            assert node.uploads == 1, 'A working binary must not be overwritten'
            print(f'PASS BackPack {entry}: verified local upload, execution, existing binary reuse')


if __name__ == '__main__':
    main()
