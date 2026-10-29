import hashlib
import json
import tempfile
from pathlib import Path
import unittest

import public_source
import release_gate

class PublicationTests(unittest.TestCase):
    def test_export_never_copies_private_state_or_history(self):
        with tempfile.TemporaryDirectory() as source, tempfile.TemporaryDirectory() as output:
            root = Path(source)
            for name in ('README.md', '.git/config', '.cybot/token', 'nasa-recon/findings.txt', 'videos/private.txt', 'internal/app/main.go'):
                path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text('fixture')
            public_source.export(Path(output), root)
            copied = {str(path.relative_to(output)) for path in Path(output).rglob('*') if path.is_file()}
            self.assertEqual(copied, {'README.md', 'internal/app/main.go'})

    def test_missing_evidence_and_inventory_deletions_fail_closed(self):
        coverage = {'tools': [{'id':'fixture','implementation':'adapter','normalization':'tool-specific','capabilities':['fixture.run'],'platforms':['linux'],'version':'1'}], 'capabilities':[]}
        baseline = {'tools':['fixture','missing-tool'], 'capabilities':['missing-capability']}
        report = release_gate.evaluate(coverage, baseline, {}, 'a'*64, Path(tempfile.gettempdir()))
        self.assertFalse(report['release_ready'])
        self.assertEqual(report['validated_items'], 0)
        self.assertTrue(any('baseline' in reason for reason in report['blockers']))

    def test_presence_or_help_is_not_operation_validation(self):
        with tempfile.TemporaryDirectory() as output:
            root=Path(output)
            report_data={'kind':'tool','id':'fixture','source_sha256':'a'*64,'binary_sha256':'b'*64,'platform':'linux/amd64','cases':[{'type':kind,'status':'passed','mode':'real-operation'} for kind in ('positive','negative','failure')]}
            data=json.dumps(report_data).encode(); (root/'report.json').write_bytes(data)
            coverage={'tools':[{'id':'fixture','implementation':'adapter','normalization':'tool-specific','capabilities':['fixture.run'],'platforms':['linux'],'version':'1'}],'capabilities':[]}
            baseline={'tools':['fixture'],'capabilities':[]}
            record={'kind':'tool','id':'fixture','status':'passed','mode':'binary-presence','platform':'linux/amd64','version':'1','binary_sha256':'b'*64,'cases':['positive','negative','failure'],'report':'report.json','report_sha256':hashlib.sha256(data).hexdigest()}
            evidence={'source_sha256':'a'*64,'records':[record]}
            report=release_gate.evaluate(coverage,baseline,evidence,'a'*64,root)
            self.assertFalse(report['release_ready'])
            record['mode']='real-operation'
            self.assertTrue(release_gate.evaluate(coverage,baseline,evidence,'a'*64,root)['release_ready'])
            record['report']='../outside.json'
            self.assertFalse(release_gate.evaluate(coverage,baseline,evidence,'a'*64,root)['release_ready'])

    def test_go_audit_cannot_clear_missing_os_audit_or_tampered_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            coverage = {'tools': [], 'capabilities': []}
            required = {'profile': 'core', 'platform': 'linux/amd64'}
            baseline = dict(coverage, required_artifact_audits=[required])
            evidence = {'source_sha256': 'a'*64, 'records': []}
            self.assertFalse(release_gate.evaluate(coverage, baseline, evidence, 'a'*64, root)['release_ready'])
            report = dict(required, source_sha256='a'*64, status='passed', image_id='sha256:'+'b'*64,
                          final_security_ready=False, os_packages={'status': 'not-audited'},
                          binaries={'cybot': {'status': 'passed', 'binary_sha256': 'c'*64}})
            def save():
                data = json.dumps(report).encode(); (root/'audit.json').write_bytes(data)
                evidence['artifact_audits'] = [dict(required, report='audit.json', report_sha256=hashlib.sha256(data).hexdigest())]
            save()
            self.assertFalse(release_gate.evaluate(coverage, baseline, evidence, 'a'*64, root)['release_ready'])
            report.update(final_security_ready=True, os_packages={'status': 'passed'}); save()
            self.assertTrue(release_gate.evaluate(coverage, baseline, evidence, 'a'*64, root)['release_ready'])
            proof = {'runtime': {'profile': 'core', 'image_id': 'sha256:'+'d'*64}}
            def save_proof():
                data = json.dumps(proof).encode(); (root/'case.json').write_bytes(data)
                evidence['records'] = [{'kind': 'capability', 'id': 'fixture', 'platform': 'linux/amd64',
                                        'report': 'case.json', 'report_sha256': hashlib.sha256(data).hexdigest()}]
            save_proof()
            self.assertFalse(release_gate.evaluate(coverage, baseline, evidence, 'a'*64, root)['release_ready'])
            proof['runtime']['image_id'] = report['image_id']; save_proof()
            self.assertTrue(release_gate.evaluate(coverage, baseline, evidence, 'a'*64, root)['release_ready'])
            (root/'audit.json').write_text('{}')
            self.assertFalse(release_gate.evaluate(coverage, baseline, evidence, 'a'*64, root)['release_ready'])

if __name__ == '__main__': unittest.main()
