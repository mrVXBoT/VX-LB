import hashlib
import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from scripts import bundle_binaries as bundler


class BinaryBundlerTests(unittest.TestCase):
    def check_archive(self, kind):
        binary = b'verified executable' * 100
        stream = io.BytesIO()
        member = 'nested/Waterwall' if kind == 'zip' else 'paqet_linux_amd64'
        if kind == 'zip':
            with zipfile.ZipFile(stream, 'w') as archive:
                archive.writestr(member, binary)
        else:
            with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                info = tarfile.TarInfo(member)
                info.size = len(binary)
                archive.addfile(info, io.BytesIO(binary))
        data = stream.getvalue()
        item = {'name': 'fixture', 'arch': 'x86_64', 'url': 'https://example.invalid/fixture',
                'dest': 'engine', 'sha256': hashlib.sha256(binary).hexdigest(),
                'archive_sha256': hashlib.sha256(data).hexdigest(),
                'is_' + kind: True, kind + '_member': os.path.basename(member)}
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(bundler, 'BIN_DIR', folder), patch.object(bundler, 'TARGETS', [item]), patch.object(bundler.urllib.request, 'urlopen', return_value=io.BytesIO(data)):
                bundler.fetch_and_bundle()
            path = os.path.join(folder, 'x86_64', 'engine')
            with open(path, 'rb') as result:
                self.assertEqual(result.read(), binary)
            self.assertTrue(os.access(path, os.X_OK))

    def test_verified_zip_release(self):
        self.check_archive('zip')

    def test_verified_tar_release(self):
        self.check_archive('tar')

    def test_bad_archive_hash_is_rejected(self):
        item = {'name': 'fixture', 'arch': 'x86_64', 'url': 'https://example.invalid/fixture', 'dest': 'engine', 'archive_sha256': '0' * 64}
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(bundler, 'BIN_DIR', folder), patch.object(bundler, 'TARGETS', [item]), patch.object(bundler.urllib.request, 'urlopen', return_value=io.BytesIO(b'corrupt archive')):
                bundler.fetch_and_bundle()
            self.assertFalse(os.path.exists(os.path.join(folder, 'x86_64', 'engine')))
