import io
import json
import unittest

import artifact_audit


class ArtifactAuditTests(unittest.TestCase):
    def header(self):
        return [{'config': {'scanner_name': 'govulncheck', 'scanner_version': 'v1.9.0',
                            'scan_mode': 'binary', 'scan_level': 'symbol'}},
                {'SBOM': {'go_version': 'go1.26.10', 'modules': [{'path': 'fixture', 'version': 'v1.0.0'}]}}]

    def test_compiled_advisory_blocks_even_when_json_scanner_exits_zero(self):
        objects = self.header()
        for frame in [{'module': 'fixture'}, {'module': 'fixture', 'package': 'fixture/pkg'},
                      {'module': 'fixture', 'package': 'fixture/pkg', 'function': 'Vulnerable'}]:
            objects.append({'finding': {'osv': 'GO-FIXTURE', 'trace': [frame]}})
        report = artifact_audit.summarize(objects)
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(len(report['advisories']), 1)
        self.assertEqual(report['advisories'][0]['level'], 2)

    def test_no_affected_compiled_code_passes_but_module_observation_is_retained(self):
        objects = self.header() + [{'finding': {'osv': 'GO-FIXTURE', 'trace': [{'module': 'unused-dependency'}]}}]
        report = artifact_audit.summarize(objects)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(len(report['advisories']), 1)

    def test_missing_inventory_wrong_mode_and_truncated_stream_fail_closed(self):
        for objects in [[], self.header()[:1], [{'config': {'scan_mode': 'source'}}, self.header()[1]]]:
            with self.assertRaises(RuntimeError): artifact_audit.summarize(objects)
        with self.assertRaisesRegex(RuntimeError, 'Truncated'):
            list(artifact_audit.messages(io.StringIO('{"config":')))
        content = '\n'.join(json.dumps(item, indent=2) for item in self.header())
        self.assertEqual(len(list(artifact_audit.messages(io.StringIO(content)))), 2)

    def test_stripped_binary_fallback_is_explicit_and_remains_blocked(self):
        objects = self.header() + [{'finding': {'osv': 'GO-FIXTURE', 'trace': [
            {'module': 'fixture', 'package': 'fixture/pkg', 'function': 'fixture/pkg/*'}]}}]
        report = artifact_audit.summarize(objects)
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['advisories'][0]['precision'], 'conservative-module')

    def test_older_or_unrecognized_compiler_cannot_pass_a_clean_module_scan(self):
        for version in ['go1.26.4-X:jsonv2', 'go1.25.5', 'devel go1.27']:
            objects = self.header(); objects[1]['SBOM']['go_version'] = version
            report = artifact_audit.summarize(objects)
            self.assertEqual(report['status'], 'blocked')
            self.assertEqual(report['toolchain']['status'], 'blocked')


if __name__ == '__main__': unittest.main()
