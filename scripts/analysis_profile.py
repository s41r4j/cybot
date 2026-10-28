"""Pinned, offline static analysis profile using the shared toolbox limits."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile

import toolbox


def prepare(dest):
    lock = json.loads((toolbox.ROOT / 'docker/toolbox/analysis.lock.json').read_text())
    archive = dest / 'go.tar.gz'
    toolbox.download(lock['go']['assets'][toolbox.ARCH], archive)
    total = 0
    with tarfile.open(archive) as source:
        for member in source:
            parts = Path(member.name).parts
            if not member.isfile() or not parts or parts[0] != 'go' or '..' in parts:
                continue
            total += member.size
            if total > 512 * 1024**2:
                raise RuntimeError('Go SDK exceeds the analysis profile limit')
            target = dest.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as src, target.open('wb') as out:
                shutil.copyfileobj(src, out)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    archive.unlink()
    (dest / 'bin').mkdir(exist_ok=True)
    # Isolate downloads and compiler state from both the host and final image.
    cache = dest / '.build-cache'
    env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=toolbox.ARCH,
               GOMAXPROCS='1', GOMEMLIMIT='512MiB', GOTOOLCHAIN=toolbox.GO_TOOLCHAIN,
               GOBIN='', GOPATH=str(cache / 'gopath'), GOCACHE=str(cache / 'build'),
               GOMODCACHE=str(cache / 'modules'))
    toolbox.monitored(['go', 'install', '-p', '1', '-trimpath',
                       '-ldflags=-s -w -X main.Version='+lock['gosec']['version'],
                       'github.com/securego/gosec/v2/cmd/gosec@v'+lock['gosec']['version']],
                      env=env, timeout_seconds=900)
    installed = list((cache / 'gopath/bin').rglob('gosec'))
    if len(installed) != 1:
        raise RuntimeError('Expected exactly one built Gosec executable')
    shutil.copy2(installed[0], dest / 'bin/gosec')
    # Preserve upstream licenses for every fetched module, not just the scanner.
    notices = dest / 'share/licenses/gosec'
    for notice in (cache / 'modules').rglob('*'):
        if notice.is_file() and notice.name.upper().startswith(('LICENSE', 'NOTICE', 'COPYING')):
            target = notices / notice.relative_to(cache / 'modules')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(notice, target)
    shutil.rmtree(cache)
    shutil.copytree(toolbox.ROOT / 'rules', dest / 'rules')
    shutil.copy(toolbox.ROOT / 'docker/toolbox/analysis.Dockerfile', dest / 'Dockerfile')
    shutil.copy(toolbox.ROOT / 'docker/toolbox/analysis.lock.json', dest / 'analysis.lock.json')
    shutil.copy(toolbox.ROOT / 'scripts/toolbox-analysis-entrypoint.sh', dest / 'entrypoint.sh')
    (dest / 'entrypoint.sh').chmod(0o755)
    toolbox.prepare_cli(dest)


def probe(image):
    toolbox.STATE.mkdir(parents=True, exist_ok=True)
    commands = {
        'cybot': ('/opt/cybot/bin/cybot', '--version'),
        'gosec': ('/opt/cybot/bin/gosec', '-version'),
        'semgrep': ('/usr/local/bin/semgrep', '--version'),
        'semgrep-core': ('/usr/local/bin/semgrep-core', '-version'),
        'go': ('/opt/go/bin/go', 'version'),
    }
    # Locate the core engine through the CLI's installed package rather than
    # assume its wheel layout. Hash both the launcher and real native engine.
    lines = ['set -eu', "core=$(python3 -c 'import semgrep, pathlib; print(pathlib.Path(semgrep.__file__).parent / \"bin/semgrep-core\")')"]
    for name, (path, flag) in commands.items():
        if name == 'semgrep-core':
            path = '"$core"'
        lines += [f"printf '\\nCYBOT_HASH {name} '", f'sha256sum {path}',
                  f"printf 'CYBOT_VERSION {name}\\n'", f'{path} {flag} 2>&1', "printf '\\nCYBOT_END\\n'"]
    with tempfile.TemporaryDirectory(prefix='probe-', dir=toolbox.STATE) as temp:
        output = Path(temp) / 'result.txt'
        try:
            toolbox.run(['exec', 'sh', '-c', '\n'.join(lines)], image=image,
                        network='none', output=output, timeout_seconds=120)
        except RuntimeError:
            if output.exists():
                (toolbox.STATE / 'probe-error.txt').write_bytes(output.read_bytes()[-65536:])
            raise
        text = output.read_text()
    lock = json.loads((toolbox.ROOT / 'docker/toolbox/analysis.lock.json').read_text())
    report = {'binaries': {}, 'packages': {}}
    for name, (path, _) in commands.items():
        digest = re.search(r'CYBOT_HASH '+name+r' ([a-f0-9]{64})\s+(\S+)', text)
        output = re.search(r'CYBOT_VERSION '+name+r'\n(.*?)\nCYBOT_END', text, re.S)
        version = re.search(r'(?<!\d)(\d+\.\d+\.\d+)(?!\d)', output[1]) if output else None
        if not digest or not version:
            raise RuntimeError('Incomplete analysis runtime measurement: '+name+'\n'+text[-4000:])
        expected = lock['semgrep']['version'] if name in ('semgrep', 'semgrep-core') else lock.get(name, {}).get('version')
        if expected and version[1] != expected:
            raise RuntimeError('Analysis runtime version mismatch: '+name)
        report['binaries'][name] = {'path': digest[2], 'sha256': digest[1], 'reported_version': version[1]}
    return report
