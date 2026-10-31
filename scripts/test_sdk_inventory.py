import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('sdk_inventory',Path(__file__).resolve().parents[1]/'docker/toolbox/sdk_inventory.py')
sdk=importlib.util.module_from_spec(spec);spec.loader.exec_module(sdk)


class SDKInventoryTests(unittest.TestCase):
    def fixture(self,root):
        for name in ('bin/go','bin/gofmt','pkg/tool/linux_amd64/compile'):
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture SDK binary');path.chmod(0o755)
        return sdk.source_manifest(root,'1.26.10','amd64','a'*64)

    def test_inventory_rejects_changed_added_and_symlinked_sdk_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);manifest=self.fixture(root)
            (root/'bin/gofmt').write_bytes(b'changed')
            with patch.object(sdk.subprocess,'run') as run:
                # Hash mismatch must fail before running even the SDK inspector.
                manifest['files']['bin/go']='0'*64
                with self.assertRaisesRegex(RuntimeError,'verified source'): sdk.measure(root,manifest)
                run.assert_not_called()
            (root/'pkg/tool/linux_amd64/extra').write_bytes(b'extra');(root/'pkg/tool/linux_amd64/extra').chmod(0o755)
            with self.assertRaisesRegex(RuntimeError,'set changed'): sdk.measure(root,manifest)
            (root/'bin/gofmt').unlink();(root/'bin/gofmt').symlink_to(root/'bin/go')
            with self.assertRaisesRegex(RuntimeError,'symlink'): sdk.sdk_files(root)

    def test_metadata_from_every_tool_is_checked_without_executing_that_tool(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);manifest=self.fixture(root)
            def output(args,**kwargs):
                self.assertEqual(args[:3],[str(root/'bin/go'),'version','-m'])
                return type('Output',(),{'stdout':args[3]+': go1.26.10\n\tbuild\tGOOS=linux\n\tbuild\tGOARCH=amd64\n'})()
            with patch.object(sdk.subprocess,'run',side_effect=output) as run:
                measured=sdk.measure(root,manifest)
                self.assertEqual(run.call_count,3)
                self.assertEqual({row['path'] for row in measured.values()},{str(root/name) for name in manifest['files']})
            with patch.object(sdk.subprocess,'run',return_value=type('Output',(),{'stdout':str(root/'bin/go')+': go1.25.0\n'})()):
                with self.assertRaisesRegex(RuntimeError,'different compiler'): sdk.measure(root,manifest)
