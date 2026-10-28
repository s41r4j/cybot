"""Bind executed operation reports to independent runtime measurements."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from public_source import source_digest


def collect(directory, runtime, source, arch):
    records = []
    for path in sorted(directory.glob('*.json')):
        if path.name == 'evidence.json':
            continue
        report = json.loads(path.read_text())
        tool = report['tool']
        measured = runtime['binaries'][tool]
        if report['source_sha256'] != source or report['platform'] != 'linux/'+arch:
            raise RuntimeError('Report source/platform differs from validation host: '+str(path))
        if report['binary_sha256'] != measured['sha256']:
            raise RuntimeError('Executed binary differs from runtime probe: '+tool)
        cases = report.get('cases', [])
        if {case['type'] for case in cases if case['status'] == 'passed' and case['mode'] == 'real-operation'} != {'positive', 'negative', 'failure'}:
            raise RuntimeError('Operation report is missing passing cases: '+tool)
        # Retain engine/runtime hashes (Semgrep's launcher alone is insufficient
        # to identify the engine); the whole measured image inventory is bound.
        report['runtime'] = runtime
        path.write_text(json.dumps(report, indent=2)+'\n')
        records.append({'kind': report['kind'], 'id': report['id'], 'status': 'passed',
                        'mode': 'real-operation', 'platform': report['platform'],
                        'version': measured['reported_version'], 'binary_sha256': measured['sha256'],
                        'cases': sorted(case['type'] for case in cases), 'report': path.name,
                        'report_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    (directory/'evidence.json').write_text(json.dumps({'source_sha256': source, 'records': records}, indent=2)+'\n')
    return records


def merge(inputs, destination, source):
    destination.mkdir(parents=True, exist_ok=True)
    records = []
    seen = {}
    for index, path in enumerate(sorted(inputs)):
        evidence = json.loads(path.read_text())
        if evidence.get('source_sha256') != source:
            raise RuntimeError('Refusing stale validation artifact: '+str(path))
        for record in evidence['records']:
            key = (record['kind'], record['id'], record['platform'])
            original = path.parent / record['report']
            original.resolve().relative_to(path.parent.resolve())
            if hashlib.sha256(original.read_bytes()).hexdigest() != record['report_sha256']:
                raise RuntimeError('Operation report was modified: '+str(original))
            if key in seen:
                previous = seen[key]
                if any(previous[field] != record[field] for field in ('binary_sha256', 'version', 'status', 'mode', 'cases')):
                    raise RuntimeError('Conflicting duplicate validation record: '+str(key))
                # Profiles can independently test the same pinned executable.
                # Retain one checked report; never count the item twice.
                continue
            seen[key] = record
            name = f'{index}-{original.name}'
            shutil.copy2(original, destination/name)
            records.append(dict(record, report=name))
    result = {'source_sha256': source, 'records': records}
    (destination/'evidence.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', type=Path, help='Directory containing downloaded CI evidence artifacts')
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    merge(options.inputs.rglob('evidence.json'), options.output, source_digest())
