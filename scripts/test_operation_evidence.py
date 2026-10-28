import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import operation_evidence


class OperationEvidenceTests(unittest.TestCase):
    def fixture(self, root):
        report = {'kind': 'tool', 'id': 'fixture', 'tool': 'fixture', 'source_sha256': 'a'*64,
                  'platform': 'linux/amd64', 'binary_sha256': 'b'*64,
                  'cases': [{'type': kind, 'status': 'passed', 'mode': 'real-operation'} for kind in ('positive', 'negative', 'failure')]}
        (root/'tool-fixture.json').write_text(json.dumps(report))
        return {'binaries': {'fixture': {'sha256': 'b'*64, 'reported_version': '1.0.0'}}}

    def test_rejects_different_binary_and_stale_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runtime = self.fixture(root)
            with self.assertRaisesRegex(RuntimeError, 'source/platform'):
                operation_evidence.collect(root, runtime, 'c'*64, 'amd64')
            runtime['binaries']['fixture']['sha256'] = 'c'*64
            with self.assertRaisesRegex(RuntimeError, 'binary differs'):
                operation_evidence.collect(root, runtime, 'a'*64, 'amd64')

    def test_merge_rejects_tampered_reports_and_duplicate_records(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); incoming = root/'incoming'; incoming.mkdir()
            runtime = self.fixture(incoming)
            records = operation_evidence.collect(incoming, runtime, 'a'*64, 'amd64')
            self.assertEqual(len(records), 1)
            evidence = incoming/'evidence.json'
            with self.assertRaisesRegex(RuntimeError, 'duplicate'):
                operation_evidence.merge([evidence, evidence], root/'duplicate', 'a'*64)
            (incoming/'tool-fixture.json').write_text('{}')
            with self.assertRaisesRegex(RuntimeError, 'modified'):
                operation_evidence.merge([evidence], root/'tampered', 'a'*64)

    def test_help_or_missing_negative_case_is_not_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); runtime = self.fixture(root)
            path = root/'tool-fixture.json'; report = json.loads(path.read_text())
            report['cases'][1]['mode'] = 'help'
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(RuntimeError, 'missing passing cases'):
                operation_evidence.collect(root, runtime, 'a'*64, 'amd64')


if __name__ == '__main__':
    unittest.main()
