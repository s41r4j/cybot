import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).parent))
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('toolbox', Path(__file__).with_name('toolbox.py'))
toolbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(toolbox)

class BudgetTests(unittest.TestCase):
    def test_failed_process_stderr_can_be_captured_with_stdout(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'log'
            with path.open('w') as output, patch.object(toolbox.time, 'sleep'), \
                 patch.object(toolbox, 'disk_usage', return_value={'accounted_bytes':0,'host_free_bytes':100*toolbox.GB}):
                with self.assertRaisesRegex(RuntimeError, 'exit 1'):
                    toolbox.monitored([sys.executable, '-c', 'import sys; print("archive error", file=sys.stderr); sys.exit(1)'],
                                      stdout=output, stderr=toolbox.subprocess.STDOUT)
            self.assertIn('archive error', path.read_text())

    def test_pull_rejects_mutable_or_local_only_references(self):
        with patch.object(toolbox, 'docker') as docker, patch.object(toolbox, 'monitored') as monitored:
            for ref in ('cybotainer:latest', 'sha256:'+'a'*64, 'ghcr.io/s41r4j/cybot:stable'):
                with self.assertRaisesRegex(RuntimeError, 'registry image pinned'):
                    toolbox.pull(ref)
            docker.assert_not_called()
            monitored.assert_not_called()

    def test_failed_downloaded_image_validation_does_not_change_pin(self):
        with patch.object(toolbox, 'preflight'), patch.object(toolbox, 'monitored'), \
             patch.object(toolbox, 'probe', return_value={}), patch.object(toolbox, 'save_pin') as save_pin, \
             patch('toolbox_validation.validate_image', side_effect=RuntimeError('fixture failure')):
            with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
                toolbox.pull('ghcr.io/s41r4j/cybot@sha256:'+'a'*64)
            save_pin.assert_not_called()

    def test_failed_integration_validation_never_promotes_candidate(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(toolbox, 'STATE', Path(temp)), \
             patch.object(toolbox, 'preflight'), patch.object(toolbox, 'prepare'), \
             patch.object(toolbox, 'monitored'), patch.object(toolbox, 'run'), \
             patch.object(toolbox, 'probe', return_value={}), \
             patch.object(toolbox, 'image_bytes', return_value=100), \
             patch.object(toolbox, 'docker', return_value='') as docker, \
             patch.object(toolbox, 'save_pin') as save_pin, \
             patch.object(toolbox.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout='sha256:old')), \
             patch('toolbox_validation.validate_image', side_effect=RuntimeError('fixture integration failed')):
            with self.assertRaisesRegex(RuntimeError, 'integration failed'):
                toolbox.build()
            save_pin.assert_not_called()
            self.assertFalse(any(call.args[0] == 'tag' for call in docker.call_args_list))

    def test_units(self):
        self.assertEqual(toolbox.size_bytes('1.5GiB'), int(1.5 * 1024**3))
        self.assertEqual(toolbox.size_bytes('12.4GB'), 12_400_000_000)
        with self.assertRaises(RuntimeError): toolbox.size_bytes('unavailable')

    def test_image_budget_uses_unpacked_storage(self):
        with patch.object(toolbox, 'docker', side_effect=['[{"Id":"sha256:fixture","Size":164000000}]', '{"ID":"sha256:fixture","Size":"717MB"}']):
            self.assertEqual(toolbox.image_bytes('sha256:fixture'), 718_000_000)

    def test_operation_lock_blocks_second_invocation(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(toolbox.tempfile, 'gettempdir', return_value=temp):
            with toolbox.operation_lock():
                with self.assertRaisesRegex(RuntimeError, 'Another CYBOT'):
                    with toolbox.operation_lock():
                        self.fail('overlapping operation admitted')
            with toolbox.operation_lock():
                pass

    def test_storage_rejected_before_memory_or_mutation(self):
        with patch.object(toolbox, 'docker', return_value=json.dumps([{'Endpoints':{'docker':{'Host':'unix:///docker.sock'}}}])) as docker, \
             patch.object(toolbox, 'disk_usage', return_value={'accounted_bytes':19*toolbox.GB,'host_free_bytes':80*toolbox.GB}), \
             patch.dict(toolbox.os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'Storage admission refused'): toolbox.preflight()
            self.assertEqual(docker.call_count, 1)

    def test_checksum_failure_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(toolbox.urllib.request, 'urlopen', return_value=io.BytesIO(b'bad')):
            asset={'url':'https://example.invalid/file','size':3,'sha256':hashlib.sha256(b'yes').hexdigest()}
            with self.assertRaisesRegex(RuntimeError,'integrity mismatch'): toolbox.download(asset, Path(temp)/'out')

    def test_extract_only_selected_binary_and_notice(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); archive=root/'a.zip'
            with zipfile.ZipFile(archive,'w') as z:
                z.writestr('../../outside',b'no')
                z.writestr('scanner',b'bin')
                z.writestr('LICENSE',b'notice')
            toolbox.unpack_binary(archive,'scanner',root)
            self.assertEqual((root/'bin/scanner').read_bytes(),b'bin')
            self.assertEqual((root/'share/licenses/scanner/LICENSE').read_bytes(),b'notice')
            self.assertFalse((root/'outside').exists())

    def test_conflicting_container_is_never_removed(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(toolbox,'ROOT',Path(temp)), \
             patch.object(toolbox,'preflight'), patch.object(toolbox,'current_image', return_value='fixture'), patch.object(toolbox,'image_bytes', return_value=100), patch.object(toolbox,'docker') as docker:
            docker.side_effect=RuntimeError('name in use')
            with self.assertRaisesRegex(RuntimeError,'name in use'): toolbox.run(['health'])
            self.assertFalse(any(call.args[0] in ('rm','stop') for call in docker.call_args_list))

    def test_runtime_mounts_isolate_private_state_and_bound_writable_reports(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root/'.cybot/toolbox/analysis'
            reports = state/'validation'
            reports.mkdir(parents=True)
            private = root/'.cybot/private-assessments'
            private.mkdir()
            with patch.object(toolbox, 'ROOT', root), patch.object(toolbox, 'STATE', state), \
                 patch.object(toolbox, 'PROFILE', 'analysis'), patch.object(toolbox, 'preflight'), \
                 patch.object(toolbox, 'image_bytes', return_value=100), \
                 patch.object(toolbox, 'docker', side_effect=RuntimeError('fixture stop')) as docker:
                with self.assertRaisesRegex(RuntimeError, 'fixture stop'):
                    toolbox.run(['health'], image='fixture', writable_mounts=[(reports, '/validation/reports')])
                args = docker.call_args.args
                self.assertEqual(args[args.index('--network')+1], 'none')
                self.assertIn(f'type=bind,src={root}/.cybot/runtimes/analysis,dst=/workspace/.cybot', args)
                self.assertIn(f'type=bind,src={reports.resolve()},dst=/validation/reports', args)
                self.assertFalse(any(f'src={root}/.cybot,' in str(arg) for arg in args))
                docker.reset_mock()
                with self.assertRaisesRegex(RuntimeError, 'inside this profile state'):
                    toolbox.run(['health'], image='fixture', writable_mounts=[(private, '/validation/reports')])
                docker.assert_not_called()

if __name__ == '__main__': unittest.main()
