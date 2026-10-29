#!/usr/bin/env python3
"""Audit compiled Go executables; JSON output never implies a clean exit by itself."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

from public_source import source_digest


def messages(stream):
    """Decode concatenated pretty-printed objects without quadratic whole-file copies."""
    decoder = json.JSONDecoder()
    pending = ''
    while True:
        chunk = stream.read(65536)
        pending += chunk
        while pending.strip():
            pending = pending.lstrip()
            try:
                value, end = decoder.raw_decode(pending)
            except json.JSONDecodeError:
                if not chunk:
                    raise RuntimeError('Truncated or malformed govulncheck JSON')
                break
            if not isinstance(value, dict):
                raise RuntimeError('Unexpected govulncheck message')
            yield value
            pending = pending[end:]
        if len(pending) > 8 * 1024**2:
            raise RuntimeError('Oversized govulncheck message')
        if not chunk:
            return


def summarize(objects):
    config = None
    sbom = None
    advisories = {}
    for message in objects:
        if 'config' in message:
            if config is not None:
                raise RuntimeError('Duplicate scanner configuration')
            config = message['config']
        if 'SBOM' in message:
            sbom = message['SBOM']
        if 'finding' not in message:
            continue
        finding = message['finding']
        trace = finding.get('trace', [])
        if not finding.get('osv') or not trace or not trace[0].get('module'):
            raise RuntimeError('Incomplete vulnerability finding')
        frame = trace[0]
        level = 2 if frame.get('function') else (1 if frame.get('package') else 0)
        precision = 'conservative-module' if frame.get('function', '').endswith('/*') else ('symbol' if level == 2 else ('package' if level == 1 else 'module'))
        key = (finding['osv'], frame['module'])
        previous = advisories.get(key)
        if previous is None or previous['level'] < level:
            advisories[key] = {'id': finding['osv'], 'module': frame['module'],
                               'version': frame.get('version'), 'fixed_version': finding.get('fixed_version'),
                               'level': level, 'precision': precision, 'package': frame.get('package'),
                               'symbol': frame.get('function')}
    if config is None or config.get('scan_mode') != 'binary' or config.get('scan_level') != 'symbol':
        raise RuntimeError('Missing binary/symbol scanner configuration')
    if config.get('scanner_name') != 'govulncheck' or config.get('scanner_version') != 'v1.9.0':
        raise RuntimeError('Unexpected vulnerability scanner version')
    if not sbom or not sbom.get('go_version') or not sbom.get('modules'):
        raise RuntimeError('Scanner did not identify a compiled Go module inventory')
    rows = sorted(advisories.values(), key=lambda row: (row['id'], row['module']))
    # Preserve conservative fallback findings from stripped executables as
    # blockers too. They do not prove a vulnerable package is linked, and they
    # cannot establish its absence. Never waive them as a clean artifact.
    return {'status': 'blocked' if any(row['level'] > 0 for row in rows) else 'passed',
            'scanner': config, 'go_version': sbom['go_version'],
            'modules': sbom['modules'], 'advisories': rows}


def audit(binary, scanner, timeout=180):
    binary = binary.resolve(strict=True)
    scanner = scanner.resolve(strict=True)
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryFile(mode='w+') as diagnostics:
        process = subprocess.Popen([str(scanner), '-json', '-mode=binary', str(binary)],
                                   stdout=subprocess.PIPE, stderr=diagnostics, text=True,
                                   env=dict(os.environ, GOMAXPROCS='1', GOMEMLIMIT='512MiB'))
        expired = threading.Event()
        def stop():
            expired.set()
            process.kill()
        timer = threading.Timer(timeout, stop)
        timer.start()
        try:
            report = summarize(messages(process.stdout))
            status = process.wait()
            if expired.is_set() or status != 0:
                raise RuntimeError('Vulnerability scanner failed or timed out')
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
    if hashlib.sha256(binary.read_bytes()).hexdigest() != before:
        raise RuntimeError('Executable changed during vulnerability analysis')
    return dict(report, binary_sha256=before, scanner_sha256=hashlib.sha256(scanner.read_bytes()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--scanner', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    options = parser.parse_args()
    report = audit(options.binary, options.scanner)
    report.update(schema_version=1, source_sha256=source_digest(),
                  checked_at=datetime.now(timezone.utc).isoformat())
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'binary': options.binary.name, 'status': report['status'],
                      'blocking_advisories': sum(row['level'] > 0 for row in report['advisories'])}))
    raise SystemExit(0 if report['status'] == 'passed' else 1)
