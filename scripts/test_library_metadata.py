import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import library_metadata as package


class LibraryMetadataTests(unittest.TestCase):
    def fixture(self,root):
        (root/'library.py').write_text('value = 1\n');(root/'adapter.py').write_text('pass\n');(root/'LICENSE').write_text('fixture notice')
        digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
        source={'url':'https://example.invalid/checked-source.tar.gz','sha256':'a'*64}
        lock={'source':source,'files':{'library.py':digest(root/'library.py'),'LICENSE':digest(root/'LICENSE')}}
        (root/'source.lock.json').write_text(json.dumps(lock))
        package.install(root,'fixture','1.0.0',source,{'requests':'2.34.2'},root/'LICENSE')
        return digest(root/'source.lock.json'),digest(root/'adapter.py')

    def test_canonical_identity_requires_source_and_installed_record_integrity(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);lock,adapter=self.fixture(root)
            self.assertEqual(package.verify(root,'fixture','1.0.0',lock,adapter),'1.0.0')
            (root/'library.py').write_text('value = 2\n')
            with self.assertRaisesRegex(RuntimeError,'checked source'):package.verify(root,'fixture','1.0.0',lock,adapter)

    def test_unrecorded_files_and_metadata_changes_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);lock,adapter=self.fixture(root)
            extra=root/'unexpected.py';extra.write_text('pass\n')
            with self.assertRaisesRegex(RuntimeError,'Unrecorded'):package.verify(root,'fixture','1.0.0',lock,adapter)
            extra.unlink();(root/'fixture-1.0.0.dist-info/INSTALLER').write_text('changed\n')
            with self.assertRaisesRegex(RuntimeError,'file changed'):package.verify(root,'fixture','1.0.0',lock,adapter)

    def test_source_symlinks_are_rejected_before_reading(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);lock,adapter=self.fixture(root)
            (root/'library.py').unlink();(root/'library.py').symlink_to(root/'adapter.py')
            with self.assertRaisesRegex(RuntimeError,'regular library source'):package.verify(root,'fixture','1.0.0',lock,adapter)
