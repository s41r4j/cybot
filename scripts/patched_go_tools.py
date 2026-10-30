"""Rebuild selected upstream releases from verified modules and committed dependency locks."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

import toolbox


def writable_copy(source, destination):
    shutil.copytree(source, destination)
    for path in [destination, *destination.rglob('*')]:
        if path.is_symlink():
            raise RuntimeError('Unexpected symlink in verified Go module')
        path.chmod(0o755 if path.is_dir() else 0o644)


def verified_module(spec, env):
    result = json.loads(subprocess.check_output(['go', 'mod', 'download', '-json', spec['module']],
                                              env=env, text=True, timeout=180))
    if result.get('Sum') != spec['sum'] or not result.get('Dir'):
        raise RuntimeError('Upstream Go module checksum mismatch: '+spec['module'])
    return Path(result['Dir'])


def patch_imports(root, files):
    applied = []
    for name, expected in files.items():
        path = root/name
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError('OpenPGP patch input changed: '+name)
        before = b'"golang.org/x/crypto/openpgp"'
        after = b'"github.com/ProtonMail/go-crypto/openpgp"'
        if data.count(before) != 1:
            raise RuntimeError('Expected exactly one OpenPGP import in '+name)
        updated = data.replace(before, after)
        path.write_bytes(updated)
        applied.append({'file': name, 'before_sha256': expected,
                        'after_sha256': hashlib.sha256(updated).hexdigest()})
    return applied


def patch_source(root, files):
    applied = []
    for name, spec in files.items():
        path = root/name
        path.resolve().relative_to(root.resolve())
        original = path.read_bytes()
        if hashlib.sha256(original).hexdigest() != spec['sha256']:
            raise RuntimeError('Upstream compatibility patch input changed: '+name)
        data = original
        for change in spec['replacements']:
            if len(change) not in (2, 3):
                raise RuntimeError("Invalid compatibility patch instruction: "+name)
            before, after = change[:2]
            expected_count = change[2] if len(change) == 3 else 1
            before, after = before.encode(), after.encode()
            if not before or not 1 <= expected_count <= 10 or data.count(before) != expected_count:
                raise RuntimeError('Compatibility patch insertion point changed: '+name)
            data = data.replace(before, after)
        path.write_bytes(data)
        applied.append({'file': name, 'before_sha256': spec['sha256'], 'after_sha256': hashlib.sha256(data).hexdigest()})
    return applied


def prepare(dest, names=None):
    lock_root = toolbox.ROOT/'docker/toolbox/patched-go'
    lock = json.loads((lock_root/'manifest.json').read_text())
    if lock['go_toolchain'] != toolbox.GO_TOOLCHAIN:
        raise RuntimeError('Patched tool compiler differs from the source lock')
    names = set(lock['tools']) if names is None else set(names)
    if not names.issubset(lock['tools']):
        raise RuntimeError('Requested patched tool has no committed source/dependency lock')
    cache = dest/'.patched-build'
    env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=toolbox.ARCH,
               GOMAXPROCS='1', GOMEMLIMIT='512MiB', GOTOOLCHAIN=toolbox.GO_TOOLCHAIN,
               GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org',
               GONOSUMDB='', GOPRIVATE='', GOFLAGS='', GOWORK='off',
               GOPATH=str(cache/'gopath'), GOMODCACHE=str(cache/'modules'),
               GOCACHE=str(cache/'build'), GOBIN='', GOEXPERIMENT='')
    try:
        source = verified_module(lock['go-github'], env)
        provenance = dest/'share/builds'
        provenance.mkdir(parents=True, exist_ok=True)
        for name, spec in lock['tools'].items():
            if name not in names:
                continue
            print('Rebuilding patched upstream release', name, spec['module'], flush=True)
            root = cache/name
            writable_copy(verified_module(spec, env), root)
            patched = root/'.cybot-patches/go-github'
            patched.parent.mkdir()
            writable_copy(source, patched)
            applied = patch_imports(patched, lock['go-github']['files'])
            source_patches = patch_source(root, spec.get('source_patches', {}))
            tool_env = dict(env, GOEXPERIMENT=spec.get('go_experiment', ''))
            for file in ('go.mod', 'go.sum'):
                shutil.copyfile(lock_root/name/file, root/file)
            test_files = {}
            for file in spec.get('test_files', []):
                target = root/file
                target.resolve().relative_to(root.resolve())
                shutil.copyfile(lock_root/name/file, target)
                test_files[file] = hashlib.sha256(target.read_bytes()).hexdigest()
            if spec.get('tests'):
                toolbox.monitored(['go', '-C', str(root), 'test', '-mod=readonly', '-p', '1', *spec['tests']], env=tool_env, timeout_seconds=600)
            # Keep symbols: stripped binaries force govulncheck into conservative
            # module-level fallback and cannot establish absence of affected code.
            args = ['go', '-C', str(root), 'build', '-mod=readonly', '-p', '1', '-trimpath', '-buildvcs=false']
            if spec.get('tags'):
                args.append('-tags='+','.join(spec['tags']))
            if spec.get('ldflags'):
                args.append('-ldflags='+spec['ldflags'])
            toolbox.monitored([*args, '-o', str(dest/'bin'/name), spec.get('package', './cmd/'+name)],
                              env=tool_env, timeout_seconds=1200)
            notices = dest/'share/licenses'/name/'modules'
            notices.mkdir(parents=True, exist_ok=True)
            for notice in (cache/'modules').rglob('*'):
                if notice.is_file() and notice.name.upper().startswith(('LICENSE', 'NOTICE', 'COPYING')):
                    target = notices/notice.relative_to(cache/'modules')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(notice, target)
            data = {'kind': 'cybot-patched-upstream', 'upstream_module': spec['module'],
                    'upstream_sum': spec['sum'], 'go_toolchain': toolbox.GO_TOOLCHAIN,
                    'platform': 'linux/'+toolbox.ARCH, 'patch_module': lock['go-github']['module'],
                    'go_experiment': spec.get('go_experiment', ''),
                    'patch_module_sum': lock['go-github']['sum'], 'patches': applied,
                    'source_patches': source_patches, 'compatibility_tests': test_files,
                    'binary_sha256': hashlib.sha256((dest/'bin'/name).read_bytes()).hexdigest(),
                    'dependency_locks': {file: hashlib.sha256((root/file).read_bytes()).hexdigest() for file in ('go.mod', 'go.sum')}}
            (provenance/(name+'.json')).write_text(json.dumps(data, indent=2)+'\n')
            shutil.rmtree(root)
    finally:
        toolbox.monitored(['go', 'clean', '-modcache'], env=env, timeout_seconds=180)
        if cache.exists():
            shutil.rmtree(cache)
