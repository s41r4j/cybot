import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

import web_profile
from patched_go_tools import patch_source


class WebProfileTests(unittest.TestCase):
    def test_source_extraction_rejects_escape_links_and_duplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, kind in [('root/../escape', tarfile.REGTYPE), ('../escape', tarfile.REGTYPE), ('root/link', tarfile.SYMTYPE)]:
                archive = root/'input.tar'
                with tarfile.open(archive, 'w') as output:
                    member = tarfile.TarInfo(name); member.type = kind
                    output.addfile(member)
                with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                    web_profile.extract_source(archive, root/'output')
            with tarfile.open(archive, 'w') as output:
                for _ in range(2):
                    member = tarfile.TarInfo('root/fixture'); member.size = 4
                    output.addfile(member, io.BytesIO(b'test'))
            with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
                web_profile.extract_source(archive, root/'output')
            self.assertFalse((root/'escape').exists())

    def test_both_tls_contexts_must_be_patched_exactly(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root/'transport.rb'
            original = b'verify_none\nverify_none\n'
            spec = {'sha256': hashlib.sha256(original).hexdigest(), 'replacements': [['verify_none', 'verify_peer', 2]]}
            source.write_bytes(original)
            records = patch_source(root, {'transport.rb': spec})
            self.assertEqual(source.read_bytes(), b'verify_peer\nverify_peer\n')
            self.assertEqual(records[0]['after_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            with self.assertRaisesRegex(RuntimeError, 'input changed'):
                patch_source(root, {'transport.rb': spec})
            source.write_bytes(original)
            spec['replacements'][0][2] = 1
            with self.assertRaisesRegex(RuntimeError, 'insertion point'):
                patch_source(root, {'transport.rb': spec})
            self.assertEqual(source.read_bytes(), original)


if __name__ == '__main__': unittest.main()
