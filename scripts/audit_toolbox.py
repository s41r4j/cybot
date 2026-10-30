"""Audit exact installed Go executables without running them on the host."""
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
import uuid

import artifact_audit
import module_audit
from public_source import source_digest
import toolbox


def audit_image():
    toolbox.preflight(3 * toolbox.GB)
    image = toolbox.current_image()
    measured = toolbox.probe(image)
    output = toolbox.STATE/'security'
    output.mkdir(parents=True, exist_ok=True)
    excluded = {'core': {'nmap'}, 'analysis': {'semgrep', 'semgrep-core', 'linkfinder', 'linkfinder-engine'}, 'supplychain': set()}[toolbox.PROFILE]
    names = set(measured['binaries']) - excluded
    lock_root = toolbox.ROOT/'docker/toolbox/patched-go'
    source_lock = json.loads((lock_root/'manifest.json').read_text())
    report = {'schema_version': 1, 'source_sha256': source_digest(),
              'checked_at': datetime.now(timezone.utc).isoformat(),
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
                    result = None
                    try:
                        result = artifact_audit.audit(path, work/'tools/govulncheck')
                        if name in source_lock['tools']:
                            provenance_path = work/(name+'-build.json')
                            toolbox.docker('cp', cid+':/opt/cybot/share/builds/'+name+'.json', str(provenance_path))
                            if provenance_path.is_symlink() or provenance_path.stat().st_size > 1024**2:
                                raise RuntimeError('Invalid measured source-build provenance')
                            expected_locks = {file: hashlib.sha256((lock_root/name/file).read_bytes()).hexdigest() for file in ('go.mod', 'go.sum')}
                            result['source_modules'] = module_audit.audit_build(source_lock['tools'][name], json.loads(provenance_path.read_text()),
                                result['binary_sha256'], result['modules'], expected_locks, source_lock['go-github'])
                            if any(row['status'] != 'passed' for row in result['source_modules']):
                                result['status'] = 'blocked'
                            result['source_provenance_sha256'] = hashlib.sha256(provenance_path.read_bytes()).hexdigest()
                        elif name == 'jsluice':
                            spec = json.loads((toolbox.ROOT/'docker/toolbox/javascript.lock.json').read_text())['jsluice']
                            provenance_path = work/'jsluice-build.json'
                            toolbox.docker('cp', cid+':/opt/cybot/share/builds/jsluice.json', str(provenance_path))
                            if provenance_path.is_symlink() or provenance_path.stat().st_size > 1024**2:
                                raise RuntimeError('Invalid JavaScript parser source provenance')
                            provenance = json.loads(provenance_path.read_text())
                            expected = {file: hashlib.sha256((toolbox.ROOT/'docker/toolbox/javascript/jsluice'/file).read_bytes()).hexdigest() for file in ('go.mod', 'go.sum')}
                            if provenance.get('source') != spec or provenance.get('dependency_locks') != expected \
                                    or {'path': spec['module_path'], 'version': '(devel)'} not in result['modules']:
                                raise RuntimeError('JavaScript parser source differs from the compiled inventory or source lock')
                            module, version = spec['module'].rsplit('@', 1)
                            result['source_modules'] = [module_audit.assess(spec, module_audit.query(module, version), source_build=True)]
                            result['source_provenance_sha256'] = hashlib.sha256(provenance_path.read_bytes()).hexdigest()
                            if any(row['status'] != 'passed' for row in result['source_modules']):
                                result['status'] = 'blocked'
                    except (RuntimeError, OSError, ValueError) as error:
                        # Missing/stripped build metadata is an audit failure,
                        # never a clean binary. Keep auditing independent tools.
                        if result is None:
                            result = {'binary_sha256': measured['binaries'][name]['sha256'],
                                      'go_version': 'unverified', 'advisories': []}
                        result.update(status='failed', error=str(error))
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
