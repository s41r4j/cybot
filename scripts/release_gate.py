#!/usr/bin/env python3
"""Require artifact-bound operation evidence for the entire CYBOT catalog."""
import argparse
import hashlib
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import re
import sys
from public_source import ROOT, source_digest

def evaluate(coverage, baseline, evidence, digest, evidence_root):
    blockers = []
    items = []
    for family in ('tools', 'capabilities'):
        ids = [row['id'] for row in coverage[family]]
        if len(ids) != len(set(ids)) or set(ids) != set(baseline[family]):
            blockers.append(f'{family}: inventory differs from the complete catalog baseline; entries cannot silently disappear')
    records = evidence.get('records', [])
    if evidence.get('source_sha256') != digest:
        blockers.append('Missing or stale validation: evidence must match the current product source digest')
    for required in baseline.get('required_artifact_audits', []):
        label = required['profile']+'/'+required['platform']
        matching = [row for row in evidence.get('artifact_audits', []) if all(row.get(key) == required[key] for key in ('profile', 'platform'))]
        if len(matching) != 1:
            blockers.append(label+': exactly one source-matching final artifact security audit is required')
            continue
        record = matching[0]
        try:
            path = evidence_root/record['report']
            path.resolve().relative_to(evidence_root.resolve())
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != record.get('report_sha256'):
                raise ValueError('artifact audit checksum differs')
            audit = json.loads(data)
            if hours := baseline.get('max_artifact_audit_age_hours'):
                checked_at = datetime.fromisoformat(audit.get('checked_at', ''))
                now = datetime.now(timezone.utc)
                if checked_at.tzinfo is None or checked_at > now + timedelta(minutes=5) or checked_at < now - timedelta(hours=hours):
                    raise ValueError('artifact security audit is stale or has an invalid timestamp')
            if audit.get('source_sha256') != digest or any(audit.get(key) != required[key] for key in ('profile', 'platform')):
                raise ValueError('artifact audit source/platform differs')
            if not re.fullmatch('sha256:[a-f0-9]{64}', audit.get('image_id', '')):
                raise ValueError('audited image identity is missing')
            if audit.get('status') != 'passed' or audit.get('final_security_ready') is not True or audit.get('os_packages', {}).get('status') != 'passed':
                raise ValueError('final artifact security audit is incomplete or has blocking findings')
            if package_policy := baseline.get('package_audit'):
                from package_audit_report import validate_clear_report
                validate_clear_report(audit.get('package_audit',{}),package_policy,audit['image_id'],required['profile'])
                if audit['package_audit'].get('source_sha256')!=digest or any(audit['package_audit'].get(key)!=required[key] for key in ('profile','platform')):
                    raise ValueError('package audit source/profile/platform differs')
            binaries = audit.get('binaries', {})
            if not binaries or 'cybot' not in binaries or any(row.get('status') != 'passed' or not re.fullmatch('[a-f0-9]{64}', row.get('binary_sha256', '')) for row in binaries.values()):
                raise ValueError('compiled executable security evidence is incomplete')
            for name, binary in binaries.items():
                local_modules = [row['path'] for row in binary.get('modules', []) if row.get('version') == '(devel)']
                if name == 'cybot' or not local_modules:
                    continue
                reviewed = binary.get('source_modules', [])
                if not reviewed or any(row.get('status') != 'passed' for row in reviewed) or not re.fullmatch('[a-f0-9]{64}', binary.get('source_provenance_sha256', '')):
                    raise ValueError('locally rebuilt upstream modules lack source-bound advisory review: '+name)
                names = {row.get('module') for row in reviewed}
                local_modules = ['github.com/google/go-github/v30' if path == './.cybot-patches/go-github' else path for path in local_modules]
                if not set(local_modules).issubset(names):
                    raise ValueError('source advisory review omits a development/replacement module: '+name)
            bound = False
            for operation in records:
                if operation.get('platform') != required['platform']:
                    continue
                proof_path = evidence_root/operation['report']
                proof_path.resolve().relative_to(evidence_root.resolve())
                proof = proof_path.read_bytes()
                if hashlib.sha256(proof).hexdigest() != operation.get('report_sha256'):
                    raise ValueError('operation report checksum differs')
                runtime = json.loads(proof).get('runtime', {})
                if runtime.get('profile') == required['profile']:
                    bound = True
                    if runtime.get('image_id') != audit['image_id']:
                        raise ValueError('audited image differs from operation-tested image')
                    if baseline.get('package_audit'):
                        components={row['component']:row for row in audit['package_audit']['components']}
                        for name in baseline['package_audit']['native_components'][required['profile']]:
                            if components[name].get('binary_sha256')!=runtime.get('binaries',{}).get(name,{}).get('sha256'):
                                raise ValueError('native-package coverage differs from the operation-tested executable: '+name)
                if operation.get('kind') == 'tool' and operation.get('id') in binaries and binaries[operation['id']]['binary_sha256'] != operation.get('binary_sha256'):
                    raise ValueError('audited executable differs from operation-tested executable')
            if records and not bound:
                raise ValueError('no operation-tested image identity is bound to this artifact audit')
        except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
            blockers.append(label+': '+str(error))
    for family in ('tools', 'capabilities'):
        for row in coverage[family]:
            kind = 'tool' if family == 'tools' else 'capability'
            reasons = []
            if row['implementation'] in ('not-implemented', 'partial'):
                reasons.append('operation implementation is incomplete')
            if row.get('normalization') == 'observations-only':
                reasons.append('operation-specific normalization is not validated')
            if family == 'tools' and not row.get('capabilities'):
                reasons.append('no executable capability mapping')
            if family == 'tools' and not row.get('platforms'):
                reasons.append('supported operating systems have not been explicitly declared')
            if family == 'tools' and row.get('version') in ('', 'unresolved', 'latest', 'stable'):
                reasons.append('a fixed tool version is required')
            matching = [record for record in records if record.get('kind') == kind and record.get('id') == row['id']]
            # Tool installations may be platform-specific; require at least one
            # real supported environment, never a help/version/presence probe.
            if not matching:
                reasons.append('no real-operation validation evidence')
            for record in matching:
                if record.get('status') != 'passed' or record.get('mode') != 'real-operation':
                    reasons.append('evidence is not a passed real-operation test')
                if not {'positive', 'negative', 'failure'}.issubset(record.get('cases', [])):
                    reasons.append('positive, negative and failure behavior must all be exercised')
                if not re.fullmatch(r'(linux|darwin|windows)/(amd64|arm64)', record.get('platform', '')):
                    reasons.append('validation platform is missing or invalid')
                if family == 'tools' and record.get('platform', '').split('/')[0] not in row.get('platforms', []):
                    reasons.append('evidence uses an unsupported platform')
                if family == 'tools' and record.get('version') != row.get('version'):
                    reasons.append('tested tool version differs from the catalog')
                if not re.fullmatch('[a-f0-9]{64}', record.get('binary_sha256', '')):
                    reasons.append('tested executable SHA-256 is missing')
                name = record.get('report', '')
                report_path = evidence_root / name
                try:
                    rel = report_path.resolve().relative_to(evidence_root.resolve())
                    if not name or not rel.parts or not report_path.is_file():
                        raise ValueError('missing report')
                    report_bytes = report_path.read_bytes()
                    if hashlib.sha256(report_bytes).hexdigest() != record.get('report_sha256'):
                        reasons.append('validation report checksum differs')
                    report = json.loads(report_bytes)
                    for key, expected in (('kind', kind), ('id', row['id']), ('source_sha256', digest), ('binary_sha256', record.get('binary_sha256')), ('platform', record.get('platform'))):
                        if report.get(key) != expected:
                            reasons.append('validation report metadata differs: '+key)
                    passed = {case.get('type') for case in report.get('cases', []) if case.get('status') == 'passed' and case.get('mode') == 'real-operation'}
                    if not {'positive', 'negative', 'failure'}.issubset(passed):
                        reasons.append('report does not prove all required real-operation cases passed')
                except (ValueError, OSError):
                    reasons.append('validation report is absent or outside the evidence directory')
            if family == 'tools':
                required = {platform for os_name in row.get('platforms', []) for platform in baseline.get('required_tool_platforms', {}).get(os_name, [])}
                tested = {record.get('platform') for record in matching}
                for platform in sorted(required - tested):
                    reasons.append('missing required platform evidence: '+platform)
            items.append({'kind': kind, 'id': row['id'], 'ready': not reasons, 'blockers': sorted(set(reasons))})
    if not (ROOT / 'LICENSE').is_file() or not (ROOT / 'SECURITY.md').is_file():
        blockers.append('project license and security policy are required')
    return {'schema_version': 1, 'source_sha256': digest,
            'release_ready': not blockers and all(item['ready'] for item in items),
            'counts': {family: len(coverage[family]) for family in ('tools', 'capabilities')},
            'validated_items': sum(item['ready'] for item in items),
            'blockers': blockers, 'items': items}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--coverage', type=Path, default=ROOT/'release/catalog-coverage.json')
    parser.add_argument('--baseline', type=Path, default=ROOT/'release/catalog-baseline.json')
    parser.add_argument('--evidence', type=Path, default=ROOT/'release/validation/evidence.json')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    coverage = json.loads(args.coverage.read_text())
    baseline = json.loads(args.baseline.read_text())
    evidence = json.loads(args.evidence.read_text()) if args.evidence.exists() else {}
    report = evaluate(coverage, baseline, evidence, source_digest(), args.evidence.parent)
    rendered = json.dumps(report, indent=2)+'\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(json.dumps({key: report[key] for key in ('release_ready', 'counts', 'validated_items', 'blockers')}, indent=2))
    return 0 if report['release_ready'] else 1

if __name__ == '__main__':
    sys.exit(main())
