"""Audit exact installed Go executables without running them on the host."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import uuid

import artifact_audit
from public_source import source_digest
import toolbox


def audit_image():
    toolbox.preflight(3 * toolbox.GB)
    image = toolbox.current_image()
    measured = toolbox.probe(image)
    output = toolbox.STATE/'security'
    output.mkdir(parents=True, exist_ok=True)
    excluded = {'core': {'nmap'}, 'analysis': {'semgrep', 'semgrep-core'}, 'supplychain': set()}[toolbox.PROFILE]
    names = set(measured['binaries']) - excluded
    report = {'schema_version': 1, 'source_sha256': source_digest(),
              'profile': toolbox.PROFILE, 'platform': 'linux/'+toolbox.ARCH,
              'scope': 'compiled-go-executables', 'status': 'failed',
              'final_security_ready': False, 'os_packages': {'status': 'not-audited'},
              'unscanned_native_components': sorted(excluded), 'binaries': {}}
    try:
        with tempfile.TemporaryDirectory(prefix='artifact-audit-', dir=toolbox.STATE) as temp:
            work = Path(temp)
            env = dict(os.environ, GOOS='', GOARCH='', GOBIN=str(work/'tools'),
                       GOPATH=str(work/'gopath'), GOMODCACHE=str(work/'modules'),
                       GOCACHE=str(work/'cache'), GOTOOLCHAIN=toolbox.GO_TOOLCHAIN,
                       GOMAXPROCS='1', GOMEMLIMIT='512MiB', GOFLAGS='', GOWORK='off')
            cid = None
            try:
                toolbox.monitored(['go', 'install', '-p', '1', 'golang.org/x/vuln/cmd/govulncheck@v1.9.0'], env=env, timeout_seconds=600)
                # Never started. Remove only the container created here.
                cid = toolbox.docker('create', '--pull', 'never', '--name', 'cybot-audit-'+uuid.uuid4().hex,
                                     '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                                     '--memory', '2g', '--memory-swap', '2g', '--cpus', '1',
                                     '--pids-limit', '256', image, 'health').strip()
                report['image_id'] = json.loads(toolbox.docker('inspect', cid))[0]['Image']
                for name in sorted(names):
                    path = work/name
                    toolbox.docker('cp', cid+':'+measured['binaries'][name]['path'], str(path))
                    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != measured['binaries'][name]['sha256']:
                        raise RuntimeError('Copied executable differs from measured image: '+name)
                    result = artifact_audit.audit(path, work/'tools/govulncheck')
                    report['binaries'][name] = result
                    print(name, result['status'], 'blocking advisories:', sum(row['level'] > 0 for row in result['advisories']), flush=True)
                    path.unlink()
            finally:
                if cid is not None:
                    toolbox.docker('rm', cid)
                toolbox.monitored(['go', 'clean', '-modcache'], env=env, timeout_seconds=180)
            report['status'] = 'passed' if report['binaries'] and all(row['status'] == 'passed' for row in report['binaries'].values()) else 'blocked'
    finally:
        (output/'audit.json').write_text(json.dumps(report, indent=2)+'\n')
    if report['status'] != 'passed':
        raise RuntimeError('Installed Go executables have blocking audit findings; see '+str(output/'audit.json'))
    print('Go executable audit passed; OS/native-language artifact audit is still required.')
