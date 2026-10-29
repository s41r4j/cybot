from pathlib import Path
import tempfile
import unittest
import zipfile

import javascript_profile


class JavaScriptProfileTests(unittest.TestCase):
    def test_wheel_extraction_rejects_path_escape_and_preserves_notices(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); archive = root/'input.whl'
            with zipfile.ZipFile(archive, 'w') as source: source.writestr('../escape.py', 'unsafe')
            with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                javascript_profile.unpack_wheel(archive, root/'site', root/'notices')
            self.assertFalse((root/'escape.py').exists())
            with zipfile.ZipFile(archive, 'w') as source:
                source.writestr('fixture.py', 'value = 42')
                source.writestr('fixture.dist-info/LICENSE', 'fixture notice')
            javascript_profile.unpack_wheel(archive, root/'site', root/'notices')
            self.assertEqual((root/'site/fixture.py').read_text(), 'value = 42')
            self.assertEqual((root/'notices/fixture.dist-info/LICENSE').read_text(), 'fixture notice')

    def test_syntax_guard_refuses_unrecognized_patch_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root/'tree.go').write_text('package fixture')
            with self.assertRaisesRegex(RuntimeError, 'input changed'):
                javascript_profile.patch_jsluice(root, {'tree.go': '0'*64})
            self.assertEqual((root/'tree.go').read_text(), 'package fixture')


if __name__ == '__main__': unittest.main()
