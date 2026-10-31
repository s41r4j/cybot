import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('testssl_metadata',Path(__file__).resolve().parents[1]/'docker/toolbox/testssl_metadata.py')
metadata=importlib.util.module_from_spec(spec);spec.loader.exec_module(metadata)


class TestSSLMetadataTests(unittest.TestCase):
    def fixture(self,root):
        rows=[]
        for name,data in [('usr/bin/testssl',b'checked engine'),('etc/testssl/cipher-mapping.txt',b'checked cipher data')]:
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            rows.append({'path':'/'+name,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        return {'schema':1,'version':'3.2.1','runtime_files':rows}

    def test_installed_source_changes_and_extra_data_fail_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);lock=self.fixture(root)
            self.assertEqual(len(metadata.verify(lock,root)),64)
            (root/'usr/bin/testssl').write_bytes(b'changed engine')
            with self.assertRaisesRegex(RuntimeError,'bytes differ'):metadata.verify(lock,root)
            lock=self.fixture(root)
            (root/'etc/testssl/untracked').write_bytes(b'untracked')
            with self.assertRaisesRegex(RuntimeError,'file set'):metadata.verify(lock,root)

    def test_manifest_escape_and_runtime_symlinks_fail_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);lock=self.fixture(root)
            lock['runtime_files'][0]['path']='/usr/bin/../testssl'
            with self.assertRaisesRegex(RuntimeError,'source path'):metadata.verify(lock,root)
            lock=self.fixture(root)
            path=root/'etc/testssl/cipher-mapping.txt';path.unlink();path.symlink_to(root/'usr/bin/testssl')
            with self.assertRaisesRegex(RuntimeError,'symlink'):metadata.verify(lock,root)


if __name__=='__main__':unittest.main()
