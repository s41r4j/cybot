"""Prepare pinned local JavaScript extraction engines for the analysis image."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import zipfile

from patched_go_tools import verified_module, writable_copy
import toolbox


def patch_jsluice(root, expected):
    records = []
    for name, digest in expected.items():
        path = root/name
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('JavaScript parser patch input changed: '+name)
        if name == 'tree.go':
            data += b'\n// HasError reports incomplete or invalid JavaScript syntax.\nfunc (n *Node) HasError() bool { return n == nil || n.node == nil || n.node.HasError() }\n'
        elif name == 'cmd/jsluice/urls.go':
            before = b'analzyer := jsluice.NewAnalyzer(source)'
            if data.count(before) != 1:
                raise RuntimeError('JavaScript parser syntax guard insertion point changed')
            data = data.replace(before, before+b'\n\tif analzyer.RootNode().HasError() {\n\t\terrs <- fmt.Errorf("JavaScript parse failed; extracted coverage is incomplete")\n\t\treturn\n\t}')
        else:
            raise RuntimeError('Unknown JavaScript parser patch file')
        path.write_bytes(data)
        records.append({'file': name, 'before_sha256': digest, 'after_sha256': hashlib.sha256(data).hexdigest()})
    return records


def unpack_wheel(archive, target, notices):
    total = 0
    with zipfile.ZipFile(archive) as source:
        for entry in source.infolist():
            parts = Path(entry.filename).parts
            if not parts or entry.is_dir():
                continue
            if '..' in parts or '\\' in entry.filename or ':' in parts[0] or Path(entry.filename).is_absolute() or ((entry.external_attr >> 16) & 0o170000) == 0o120000:
                raise RuntimeError('Unsafe Python wheel entry')
            total += entry.file_size
            if total > 2 * 1024**2:
                raise RuntimeError('Python wheel exceeds extraction limit')
            path = target.joinpath(*parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source.read(entry))
            if path.name.upper().startswith(('LICENSE', 'NOTICE', 'COPYING')):
                copy = notices.joinpath(*parts)
                copy.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, copy)


def prepare(dest):
    lock = json.loads((toolbox.ROOT/'docker/toolbox/javascript.lock.json').read_text())
    cache = dest/'.javascript-cache'
    env = dict(os.environ, GOTOOLCHAIN=toolbox.GO_TOOLCHAIN, CGO_ENABLED='1',
               GOOS='linux', GOARCH=toolbox.ARCH, GOMAXPROCS='1', GOMEMLIMIT='512MiB',
               GOMODCACHE=str(cache/'modules'), GOCACHE=str(cache/'build'), GOPATH=str(cache/'gopath'),
               GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org', GOPRIVATE='', GONOSUMDB='', GOFLAGS='', GOWORK='off')
    root = dest/'jsluice-source'
    try:
        writable_copy(verified_module(lock['jsluice'], env), root)
        patches = patch_jsluice(root, lock['jsluice']['patch_inputs'])
        for name in ('go.mod', 'go.sum'):
            shutil.copyfile(toolbox.ROOT/'docker/toolbox/javascript/jsluice'/name, root/name)
        toolbox.monitored(['go', '-C', str(root), 'mod', 'vendor'], env=env, timeout_seconds=300)
        notices = dest/'share/licenses/jsluice'
        for notice in root.rglob('*'):
            if notice.is_file() and notice.name.upper().startswith(('LICENSE', 'NOTICE', 'COPYING')):
                target = notices/notice.relative_to(root)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(notice, target)
        builds = dest/'share/builds'
        builds.mkdir(parents=True, exist_ok=True)
        (builds/'jsluice.json').write_text(json.dumps({'source': lock['jsluice'], 'patches': patches,
            'compiler_packages': lock['compiler'], 'go_toolchain': toolbox.GO_TOOLCHAIN,
            'dependency_locks': {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ('go.mod', 'go.sum')}}, indent=2)+'\n')
    finally:
        toolbox.monitored(['go', 'clean', '-modcache'], env=env, timeout_seconds=180)
        if cache.exists():
            shutil.rmtree(cache)
    for name, spec in lock['native_notices'].items():
        target = dest/'share/licenses/jsluice/native'/name
        target.parent.mkdir(parents=True, exist_ok=True)
        toolbox.download(spec, target)
    engine = dest/'lib/linkfinder'
    engine.mkdir(parents=True)
    for name, spec in lock['linkfinder']['assets'].items():
        toolbox.download(spec, engine/name)
    notices = dest/'share/licenses/linkfinder'
    notices.mkdir(parents=True)
    shutil.copy2(engine/'LICENSE', notices/'LICENSE')
    for name, spec in lock['linkfinder']['wheels'].items():
        archive = dest/'python-wheel'
        toolbox.download(spec, archive)
        unpack_wheel(archive, engine/'site-packages', notices/name)
        archive.unlink()
    launcher = dest/'bin/linkfinder'
    launcher.write_text('#!/bin/sh\nset -eu\nif [ "${1:-}" = "--version" ]; then\n  printf "%s\\n" "LinkFinder '+lock['linkfinder']['version']+'"\n  exit 0\nfi\nexport PYTHONDONTWRITEBYTECODE=1\nexport PYTHONPATH=/opt/cybot/lib/linkfinder/site-packages\nexec python3 /opt/cybot/lib/linkfinder/linkfinder.py "$@"\n')
    launcher.chmod(0o755)
    shutil.copy2(toolbox.ROOT/'docker/toolbox/javascript.lock.json', dest/'javascript.lock.json')
