import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import toolbox_backup as backups


class BackupTests(unittest.TestCase):
    def fixture(self, directory, tags=None, member=None):
        config = json.dumps({'os': 'linux', 'architecture': backups.toolbox.ARCH}).encode()
        digest = hashlib.sha256(config).hexdigest()
        archive = directory/'image.tar.gz'
        with tarfile.open(archive, 'w:gz') as out:
            files = {digest+'.json': config, 'manifest.json': json.dumps([{'Config': digest+'.json', 'RepoTags': tags, 'Layers': []}]).encode()}
            if member:
                files[member] = b'fixture'
            for name, content in files.items():
                item = tarfile.TarInfo(name); item.size = len(content)
                out.addfile(item, io.BytesIO(content))
        manifest = {'schema': 1, 'profile': backups.toolbox.PROFILE, 'platform': 'linux/'+backups.toolbox.ARCH,
                    'image_id': 'sha256:'+digest, 'runtime': {'fixture': 'measured'}, 'archive': archive.name,
                    'archive_bytes': archive.stat().st_size, 'archive_sha256': backups.checksum(archive)}
        (directory/'manifest.json').write_text(json.dumps(manifest))
        return manifest

    def test_checksums_and_profile_are_required_before_any_docker_call(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(backups.toolbox, 'preflight') as preflight:
            root = Path(temp); manifest = self.fixture(root)
            self.assertEqual(backups.inspect_backup(root)[0], manifest)
            (root/'image.tar.gz').write_bytes(b'corrupted')
            with self.assertRaisesRegex(RuntimeError, 'checksum'):
                backups.restore(root)
            preflight.assert_not_called()
            self.fixture(root)
            (root/'manifest.json').unlink()
            with self.assertRaises(FileNotFoundError): backups.restore(root)
            preflight.assert_not_called()
            manifest = self.fixture(root)
            manifest['profile'] = 'different-profile'
            (root/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(RuntimeError, 'profile or architecture'): backups.restore(root)
            preflight.assert_not_called()

    def test_tagged_or_path_escaping_archives_are_rejected_before_load(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.fixture(root, tags=['someone-elses-image:latest'])
            with self.assertRaisesRegex(RuntimeError, 'untagged'): backups.inspect_backup(root)
            self.fixture(root, member='../escape')
            with self.assertRaisesRegex(RuntimeError, 'Unsafe image'): backups.inspect_backup(root)
            self.assertFalse((root.parent/'escape').exists())

    def test_real_fixture_failure_preserves_the_active_runtime_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); manifest = self.fixture(root)
            with patch.object(backups.toolbox, 'preflight'), patch.object(backups.toolbox, 'monitored'), \
                 patch.object(backups.toolbox, 'image_bytes', return_value=100), \
                 patch.object(backups.toolbox, 'probe', return_value=manifest['runtime']), \
                 patch.object(backups.toolbox, 'save_pin') as save, \
                 patch('toolbox_validation.validate_image', side_effect=RuntimeError('actual fixture failed')):
                with self.assertRaisesRegex(RuntimeError, 'actual fixture failed'): backups.restore(root)
                save.assert_not_called()


if __name__ == '__main__': unittest.main()
