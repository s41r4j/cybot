import hashlib
from pathlib import Path
import tempfile
import unittest

import patched_go_tools


class PatchedGoToolTests(unittest.TestCase):
    def test_exact_patch_input_is_required_and_provenance_matches_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root/'fixture.go'
            original = b'package fixture\nimport "golang.org/x/crypto/openpgp"\n'
            source.write_bytes(original)
            with self.assertRaisesRegex(RuntimeError, 'input changed'):
                patched_go_tools.patch_imports(root, {'fixture.go': '0'*64})
            self.assertEqual(source.read_bytes(), original)
            records = patched_go_tools.patch_imports(root, {'fixture.go': hashlib.sha256(original).hexdigest()})
            self.assertIn(b'github.com/ProtonMail/go-crypto/openpgp', source.read_bytes())
            self.assertEqual(records[0]['after_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())

    def test_compatibility_patches_require_exact_source_and_insertion_points(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = root/'fixture.go'
            source.write_bytes(b'if schema.ExclusiveMin {')
            spec = {'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                    'replacements': [['if schema.ExclusiveMin {', 'if schema.ExclusiveMin.Bool != nil && *schema.ExclusiveMin.Bool {']]}
            result = patched_go_tools.patch_source(root, {'fixture.go': spec})
            self.assertEqual(result[0]['after_sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
            with self.assertRaisesRegex(RuntimeError, 'input changed'):
                patched_go_tools.patch_source(root, {'fixture.go': spec})
            spec['sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
            with self.assertRaisesRegex(RuntimeError, 'insertion point changed'):
                patched_go_tools.patch_source(root, {'fixture.go': spec})


if __name__ == '__main__': unittest.main()
