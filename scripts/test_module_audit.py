import unittest
from unittest.mock import patch

import module_audit


class ModuleAuditTests(unittest.TestCase):
    def test_local_development_versions_cannot_hide_an_upstream_advisory(self):
        spec = {'module': 'fixture.invalid/scanner@v1.2.3', 'sum': 'h1:fixture'}
        result = module_audit.assess(spec, {'vulns': [{'id': 'GO-fixture', 'summary': 'known affected upstream code'}]}, True)
        self.assertEqual(result['status'], 'blocked')
        with patch.object(module_audit, 'query') as query:
            with self.assertRaisesRegex(RuntimeError, 'provenance differs'):
                module_audit.audit_build(spec, {}, 'a'*64, [], {}, {})
            query.assert_not_called()

    def test_provenance_binds_binary_locks_and_local_replacement_before_query(self):
        spec = {'module': 'fixture.invalid/scanner@v1.2.3', 'sum': 'h1:fixture'}
        locks = {'go.mod': 'b'*64, 'go.sum': 'c'*64}
        replacement = {'module': 'fixture.invalid/dependency@v2.0.0', 'sum': 'h1:dependency'}
        provenance = {'kind': 'cybot-patched-upstream', 'binary_sha256': 'a'*64,
                      'upstream_module': spec['module'], 'upstream_sum': spec['sum'], 'dependency_locks': locks,
                      'patch_module': replacement['module'], 'patch_module_sum': replacement['sum']}
        modules = [{'path': 'fixture.invalid/scanner', 'version': '(devel)'},
                   {'path': './.cybot-patches/go-github', 'version': '(devel)'}]
        with patch.object(module_audit, 'query', return_value={}) as query:
            self.assertEqual(len(module_audit.audit_build(spec, provenance, 'a'*64, modules, locks, replacement)), 2)
            self.assertEqual(query.call_count, 2)
            query.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'provenance differs'):
                module_audit.audit_build(spec, provenance, 'd'*64, modules, locks, replacement)
            with self.assertRaisesRegex(RuntimeError, 'provenance differs'):
                module_audit.audit_build(spec, provenance, 'a'*64, modules, {}, replacement)
            with self.assertRaisesRegex(RuntimeError, 'compiled inventory'):
                module_audit.audit_build(spec, provenance, 'a'*64, [], locks, replacement)
            query.assert_not_called()

    def test_incident_review_requires_exact_verified_source_and_known_record(self):
        spec = {'module': 'github.com/aquasecurity/trivy@v0.72.0', 'sum': 'h1:W3v+NE94olOzk3nSwwha59DTBsbcgLRXa4QNSJpRQQM='}
        advisory = {'vulns': [{'id': 'GO-2026-4919'}]}
        self.assertEqual(module_audit.assess(spec, advisory, True)['findings'][0]['status'], 'not-affected')
        self.assertEqual(module_audit.assess(spec, advisory, False)['status'], 'blocked')
        self.assertEqual(module_audit.assess(dict(spec, sum='different-source'), advisory, True)['status'], 'blocked')
        self.assertEqual(module_audit.assess(dict(spec, module='github.com/aquasecurity/trivy@v0.69.4'), advisory, True)['status'], 'blocked')
        self.assertEqual(module_audit.assess(spec, {'vulns': [{'id': 'GO-new-unreviewed'}]}, True)['status'], 'blocked')

    def test_versioned_source_requires_the_exact_compiled_module_and_build_mode(self):
        spec={'module':'fixture.invalid/tool@v1.2.3','sum':'h1:fixture','build_mode':'versioned-module'}
        provenance={'kind':'cybot-patched-upstream','binary_sha256':'a'*64,'upstream_module':spec['module'],
                    'upstream_sum':spec['sum'],'dependency_locks':{},'build_mode':'versioned-module',
                    'compiled_identity':{'module':'fixture.invalid/tool','version':'v1.2.3','sum':spec['sum']}}
        with patch.object(module_audit,'query',return_value={}) as query:
            rows=module_audit.audit_build(spec,provenance,'a'*64,[{'path':'fixture.invalid/tool','version':'v1.2.3'}],{},{})
            self.assertEqual(rows[0]['status'],'passed')
            query.reset_mock()
            for version in ('(devel)','v1.2.4'):
                with self.assertRaisesRegex(RuntimeError,'compiled inventory'):
                    module_audit.audit_build(spec,provenance,'a'*64,[{'path':'fixture.invalid/tool','version':version}],{},{})
            with self.assertRaisesRegex(RuntimeError,'build mode'):
                module_audit.audit_build(spec,dict(provenance,build_mode='copied-module'),'a'*64,[],{},{})
            with self.assertRaisesRegex(RuntimeError,'checksum identity'):
                module_audit.audit_build(spec,dict(provenance,compiled_identity={}), 'a'*64,[],{},{})
            query.assert_not_called()


if __name__ == '__main__': unittest.main()
