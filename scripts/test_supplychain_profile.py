import io
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import supplychain_profile


class DatasetTests(unittest.TestCase):
    def archive(self, target, complete=True):
        with tarfile.open(target, 'w:gz') as archive:
            entries = {'metadata.json': b'{}', '../../outside': b'never extract this'}
            if complete:
                entries['trivy.db'] = b'fixture database'
            for name, value in entries.items():
                info = tarfile.TarInfo(name); info.size = len(value)
                archive.addfile(info, io.BytesIO(value))

    def test_verified_dataset_is_reused_and_tampering_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(supplychain_profile.toolbox, 'STATE', Path(temp)), \
             patch.object(supplychain_profile.toolbox, 'preflight'), \
             patch.object(supplychain_profile.toolbox, 'download', side_effect=lambda asset, target: self.archive(target)) as download:
            asset = {'sha256': 'a'*64}
            supplychain_profile.prepare_dataset(asset)
            supplychain_profile.prepare_dataset(asset)
            self.assertEqual(download.call_count, 1)
            path = Path(temp)/'datasets'/('a'*64)/'trivy/db/trivy.db'
            path.write_bytes(b'modified')
            with self.assertRaisesRegex(RuntimeError, 'modified'):
                supplychain_profile.prepare_dataset(asset)
            self.assertEqual(path.read_bytes(), b'modified')
            self.assertFalse((Path(temp)/'outside').exists())

    def test_incomplete_archive_never_promotes_a_dataset(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(supplychain_profile.toolbox, 'STATE', Path(temp)), \
             patch.object(supplychain_profile.toolbox, 'preflight'), \
             patch.object(supplychain_profile.toolbox, 'download', side_effect=lambda asset, target: self.archive(target, complete=False)):
            with self.assertRaisesRegex(RuntimeError, 'Incomplete'):
                supplychain_profile.prepare_dataset({'sha256': 'a'*64})
            self.assertFalse((Path(temp)/'datasets'/('a'*64)).exists())
            self.assertFalse((Path(temp)/'outside').exists())

    def test_failed_grype_import_preserves_existing_datasets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root/'project'; state = root/'state'
            (source/'docker/toolbox').mkdir(parents=True)
            (state/'datasets/previous').mkdir(parents=True)
            marker = state/'datasets/previous/marker'; marker.write_text('keep')
            digest = hashlib.sha256(b'archive fixture').hexdigest()
            (state/'datasets'/(digest+'.tar.zst')).write_bytes(b'archive fixture')
            lock = {'data': {'grype-db': {'sha256': digest}}}
            (source/'docker/toolbox/supplychain.lock.json').write_text(json.dumps(lock))
            with patch.object(supplychain_profile.toolbox, 'ROOT', source), \
                 patch.object(supplychain_profile.toolbox, 'STATE', state), \
                 patch.object(supplychain_profile.toolbox, 'preflight'), \
                 patch.object(supplychain_profile.toolbox, 'run', side_effect=RuntimeError('import failed')):
                with self.assertRaisesRegex(RuntimeError, 'import failed'):
                    supplychain_profile.finalize_dataset('candidate')
            self.assertFalse((state/'datasets'/digest).exists())
            self.assertEqual(marker.read_text(), 'keep')

    def test_grype_metadata_comes_from_the_pinned_importer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root/'project'; state = root/'state'
            (source/'docker/toolbox').mkdir(parents=True)
            (state/'datasets').mkdir(parents=True)
            digest = hashlib.sha256(b'archive fixture').hexdigest()
            (state/'datasets'/(digest+'.tar.zst')).write_bytes(b'archive fixture')
            (source/'docker/toolbox/supplychain.lock.json').write_text(json.dumps({'data': {'grype-db': {'sha256': digest}}}))
            imported = b'{"digest":"fixture-generated-by-importer","client_version":"fixture"}'
            def importer(*args, **kwargs):
                self.assertEqual(kwargs['network'], 'none')
                destination = kwargs['writable_mounts'][0][0]/'grype/6'
                destination.mkdir(parents=True)
                (destination/'vulnerability.db').write_bytes(b'hydrated database')
                (destination/'import.json').write_bytes(imported)
            with patch.object(supplychain_profile.toolbox, 'ROOT', source), \
                 patch.object(supplychain_profile.toolbox, 'STATE', state), \
                 patch.object(supplychain_profile.toolbox, 'preflight'), \
                 patch.object(supplychain_profile.toolbox, 'run', side_effect=importer) as run:
                supplychain_profile.finalize_dataset('candidate')
                supplychain_profile.finalize_dataset('candidate')
                self.assertEqual(run.call_count, 1)
            self.assertEqual((state/'datasets'/digest/'grype/6/import.json').read_bytes(), imported)


if __name__ == '__main__':
    unittest.main()
