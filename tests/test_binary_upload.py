"""Interrupted uploads must never replace a working remote executable."""
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from core.ssh_client import SSHManager


class BinaryUploadTests(unittest.TestCase):
    def setUp(self):
        self.file = tempfile.NamedTemporaryFile(delete=False)
        self.file.write(b'complete binary')
        self.file.close()
        self.addCleanup(os.unlink, self.file.name)
        self.ssh = SSHManager('192.0.2.1')
        self.ssh.client = MagicMock()
        self.ftp = MagicMock()
        self.ftp.stat.return_value.st_size = os.path.getsize(self.file.name)
        self.commands = []
        self.ssh.execute = lambda command, **kwargs: self.commands.append(command) or (0, '', '')

    def upload(self):
        with patch('core.ssh_client.paramiko.SFTPClient.from_transport', return_value=self.ftp):
            return self.ssh.upload_binary(self.file.name, '/usr/local/bin/backpack')

    def test_complete_upload_is_published_after_size_and_mode_checks(self):
        self.assertTrue(self.upload())
        temporary_path = self.ftp.put.call_args.args[1]
        self.assertNotEqual(temporary_path, '/usr/local/bin/backpack')
        self.ftp.stat.assert_called_once_with(temporary_path)
        self.ftp.chmod.assert_called_once_with(temporary_path, 0o755)
        self.assertTrue(any(command.startswith('mv -f ') for command in self.commands))
        self.ftp.get_channel.return_value.settimeout.assert_called_once_with(60)
        self.ftp.close.assert_called_once()

    def test_interrupted_upload_keeps_existing_binary(self):
        self.ftp.put.side_effect = TimeoutError('interrupted')
        self.assertFalse(self.upload())
        self.assertFalse(any(command.startswith('mv ') for command in self.commands))
        self.assertTrue(self.commands[-1].startswith('rm -f '))

    def test_truncated_upload_is_not_published(self):
        self.ftp.stat.return_value.st_size = 1
        self.assertFalse(self.upload())
        self.assertFalse(any(command.startswith('mv ') for command in self.commands))

    def test_non_executable_file_is_not_considered_installed(self):
        self.ssh.execute = MagicMock(side_effect=[(1, '', ''), (0, 'x86_64', ''), (0, 'installed', '')])
        with patch.object(self.ssh, 'upload_binary', return_value=True):
            self.assertTrue(self.ssh.ensure_backpack_installed()[0])
        command = self.ssh.execute.call_args_list[0].args[0]
        self.assertIn('[ -x ', command)
        self.assertIn('--help', command)
