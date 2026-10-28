#!/usr/bin/env python3
"""Require artifact-bound operation evidence for the entire CYBOT catalog."""
import argparse
import hashlib
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
