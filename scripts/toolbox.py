#!/usr/bin/env python3
"""Budgeted local Docker toolbox. No global prune, daemon edits or host installs."""
import argparse
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import uuid
import zipfile

import toolbox_probe

ROOT = Path(__file__).resolve().parents[1]
GB = 1_000_000_000
BUDGET = 20 * GB
IMAGE_LIMIT = 3 * GB
ACTIVE_NAME = 'cybot-toolbox-active'
ARCH = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64', 'AMD64': 'amd64'}.get(platform.machine())
IMAGE = f'cybotainer:core-2026.10.22-{ARCH}'
STATE = ROOT / '.cybot' / 'toolbox'
GO_TOOLCHAIN = 'go1.26.10'
PROFILE = 'core'


def configure_profile(profile):
    global PROFILE, IMAGE, STATE
    PROFILE = profile
    IMAGE = f'cybotainer:{profile}-2026.10.28-{ARCH}'
    STATE = ROOT / '.cybot' / 'toolbox'
    if profile != 'core':
        STATE = STATE / profile


def command(*args, capture=True, **kwargs):
    return subprocess.run(args, check=True, text=True, timeout=30, stdout=subprocess.PIPE if capture else None, **kwargs).stdout


def docker(*args):
    return command('docker', *args)


def size_bytes(text):
    match = re.fullmatch(r'([\d.]+)\s*(B|kB|KB|MB|GB|TB|KiB|MiB|GiB)', text)
    if not match:
        raise RuntimeError(f'Cannot measure Docker size: {text!r}')
    unit = {'B': 1, 'kB': 1000, 'KB': 1000, 'MB': 10**6, 'GB': 10**9,
            'TB': 10**12, 'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3}[match[2]]
    return int(float(match[1]) * unit)



def image_bytes(image):
    # `image ls REFERENCE` does not accept image IDs as reference filters. Match
    # the immutable inspected ID against the complete, untruncated inventory.
    inspected = json.loads(docker('image', 'inspect', image))[0]
    rows = [json.loads(line) for line in docker('image', 'ls', '--no-trunc', '--format', '{{json .}}').splitlines()]
    matching = [row for row in rows if row['ID'] == inspected['Id']]
    if not matching:
        raise RuntimeError('Cannot measure installed image: ' + image)
    return max(inspected['Size'], *(size_bytes(row['Size']) + 1_000_000 for row in matching))


def directory_bytes(path):
    if not path.exists():
        return 0
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
        for file in files:
            p = Path(root) / file
            try:
                if not p.is_symlink():
                    total += p.stat().st_size
            except FileNotFoundError:
                pass
    return total


def disk_usage():
    # Conservative: includes other projects instead of claiming their free space.
    rows = [json.loads(line) for line in docker('system', 'df', '--format', '{{json .}}').splitlines()]
    docker_bytes = sum(size_bytes(r['Size']) for r in rows)
    raw = Path.home() / 'Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw'
    if platform.system() == 'Darwin' and raw.exists():
        docker_bytes = max(docker_bytes, raw.stat().st_blocks * 512)
    local_bytes = sum(directory_bytes(ROOT / p) for p in ('.cybot', 'reports', 'backups'))
    return {'docker_bytes': docker_bytes, 'local_state_bytes': local_bytes,
            'accounted_bytes': docker_bytes + local_bytes,
            'host_free_bytes': shutil.disk_usage(ROOT).free, 'budget_bytes': BUDGET}


def preflight(reserve=2 * GB):
    context = json.loads(docker('context', 'inspect'))[0]
    if not context['Endpoints']['docker']['Host'].startswith('unix://'):
        raise RuntimeError('This budgeted helper supports a local Unix Docker engine only.')
    if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT'):
        raise RuntimeError('Unset Docker endpoint overrides so disk accounting uses the inspected local engine.')
    usage = disk_usage()
    if usage['accounted_bytes'] + reserve > BUDGET:
        raise RuntimeError(f'Storage admission refused: {usage["accounted_bytes"]/GB:.2f} GB used + {reserve/GB:.1f} GB reserve > 20 GB. No data was deleted.')
    if usage['host_free_bytes'] < 10 * GB + reserve:
        raise RuntimeError('Storage admission refused: preserve 10 GB host free space plus operation reserve.')
    info = json.loads(docker('info', '--format', '{{json .}}'))
    # Existing containers can grow. This is an admission check, not a reservation
    # of shared VM memory. CYBOT itself always has a hard cgroup limit.
    stats = docker('stats', '--no-stream', '--format', '{{json .}}')
    used = sum(size_bytes(json.loads(line)['MemUsage'].split('/')[0].strip()) for line in stats.splitlines())
    if info['MemTotal'] - used < 3 * 1024**3:
        raise RuntimeError('Memory admission refused: less than 3 GiB VM headroom; other workloads take priority.')
    print(json.dumps(usage), file=sys.stderr)
    return usage


def download(asset, target):
    digest = hashlib.sha256()
    size = 0
    request = urllib.request.Request(asset['url'], headers={'User-Agent': asset.get('user_agent', 'CYBOT/0.1.0')})
    if repository := asset.get('oci_repository'):
        if not re.fullmatch(r'[a-z0-9_-]+/[a-z0-9_-]+', repository) or not asset['url'].startswith('https://ghcr.io/v2/'+repository+'/blobs/sha256:'):
            raise RuntimeError('Unsupported OCI database source')
        token_url = 'https://ghcr.io/token?service=ghcr.io&scope=repository:'+repository+':pull'
        with urllib.request.urlopen(token_url, timeout=30) as response:
            token = json.load(response)['token']
        request = urllib.request.Request(asset['url'], headers={'Authorization': 'Bearer '+token, 'User-Agent': 'CYBOT/0.1.0'})
    with urllib.request.urlopen(request, timeout=60) as source, target.open('wb') as dest:
        while block := source.read(1024 * 1024):
            size += len(block)
            if size > asset['size']:
                raise RuntimeError('Download exceeds locked size: ' + asset['url'])
            digest.update(block)
            dest.write(block)
    if size != asset['size'] or digest.hexdigest() != asset['sha256']:
        raise RuntimeError('Download integrity mismatch: ' + asset['url'])


def unpack_binary(archive, name, dest):
    (dest / 'bin').mkdir(exist_ok=True)
    notices = dest / 'share' / 'licenses' / name
    notices.mkdir(parents=True, exist_ok=True)
    found = False
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            entries = [(i.filename, i.file_size, lambda i=i: z.open(i)) for i in z.infolist() if not i.is_dir()]
            for filename, size, opener in entries:
                base = Path(filename).name
                if base != name and not base.lower().startswith(('license', 'notice', 'copying')):
                    continue
                if size > 200 * 1024**2:
                    raise RuntimeError('Oversized binary archive member')
                path = dest / 'bin' / name if base == name else notices / base
                with opener() as src, path.open('wb') as out:
                    shutil.copyfileobj(src, out)
                found |= base == name
    else:
        with tarfile.open(archive) as t:
            for member in t:
                base = Path(member.name).name
                if not member.isfile() or (base != name and not base.lower().startswith(('license', 'notice', 'copying'))):
                    continue
                if member.size > 200 * 1024**2:
                    raise RuntimeError('Oversized binary archive member')
                path = dest / 'bin' / name if base == name else notices / base
                with t.extractfile(member) as src, path.open('wb') as out:
                    shutil.copyfileobj(src, out)
                found |= base == name
    if not found:
        raise RuntimeError('Binary missing from archive: ' + name)
    (dest / 'bin' / name).chmod(0o755)


def prepare(dest):
    if PROFILE == 'analysis':
        from analysis_profile import prepare as prepare_analysis
        prepare_analysis(dest)
        return
    if PROFILE == 'supplychain':
        from supplychain_profile import prepare as prepare_supplychain
        prepare_supplychain(dest)
        return
    lock = json.loads((ROOT / 'docker/toolbox/core.lock.json').read_text())
    for name, spec in lock['tools'].items():
        if spec.get('build') == 'cybot-patched-go':
            continue
        print('Preparing', name, spec['version'], flush=True)
        usage = disk_usage()
        if usage['accounted_bytes'] + 3 * GB > BUDGET:
            raise RuntimeError('Storage reserve reached while preparing assets')
        archive = dest / 'download'
        download(spec['assets'][ARCH], archive)
        unpack_binary(archive, name, dest)
        archive.unlink()
    from patched_go_tools import prepare as prepare_patched_tools
    prepare_patched_tools(dest, {name for name, spec in lock['tools'].items() if spec.get('build') == 'cybot-patched-go'})
    archive = dest / 'templates.tar.gz'
    download(lock['data']['nuclei-templates'], archive)
    templates = dest / 'share/nuclei-templates'
    total = 0
    with tarfile.open(archive) as t:
        for member in t:
            parts = Path(member.name).parts[1:]
            if not member.isfile() or not parts or any(p in ('..', '/', '.git', '.github') for p in parts):
                continue
            total += member.size
            if total > 512 * 1024**2:
                raise RuntimeError('Template contents exceed 512 MiB')
            target = templates.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with t.extractfile(member) as src, target.open('wb') as out:
                shutil.copyfileobj(src, out)
    archive.unlink()
    wordlist = dest / 'share/seclists/Discovery/Web-Content/common.txt'
    wordlist.parent.mkdir(parents=True)
    download(lock['data']['common-wordlist'], wordlist)
    download(lock['data']['wordlist-license'], dest / 'share/seclists/LICENSE')
    shutil.copy(ROOT / 'docker/toolbox/core.lock.json', dest / 'core.lock.json')
    shutil.copytree(ROOT / 'rules', dest / 'rules')
    shutil.copy(ROOT / 'docker/toolbox/Dockerfile', dest / 'Dockerfile')
    shutil.copy(ROOT / 'scripts/toolbox-core-entrypoint.sh', dest / 'entrypoint.sh')
    for notice in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
        notices = dest / 'share/licenses/cybot'
        notices.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / notice, notices / notice)
    (dest / 'entrypoint.sh').chmod(0o755)
    prepare_cli(dest)


def prepare_cli(dest):
    # CLI compilation and its third-party notices are shared by all profiles.
    # Keep the build cache private and remove it with the temporary context.
    cache = dest / '.go-cache'
    version = os.environ.get('CYBOT_VERSION', '0.1.0-dev')
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?', version):
        raise RuntimeError('CYBOT_VERSION must be a semantic version')
    env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=ARCH,
               GOMAXPROCS='1', GOMEMLIMIT='512MiB', GOCACHE=str(cache), GOTOOLCHAIN=GO_TOOLCHAIN)
    monitored(['go', 'build', '-p', '1', '-trimpath', f'-ldflags=-s -w -X main.version={version}', '-o', str(dest / 'bin/cybot'),
               './cmd/cybot'], env=env)
    notices = dest / 'share/licenses/cybot'
    notices.mkdir(parents=True, exist_ok=True)
    for name in ('LICENSE', 'THIRD_PARTY_NOTICES.md'):
        shutil.copy(ROOT / name, notices / name)
    monitored([sys.executable, 'scripts/dependency_notices.py', '--output', str(notices / 'dependencies')], env=env, timeout_seconds=180)
    shutil.rmtree(cache)
    if directory_bytes(dest) > 2 * GB:
        raise RuntimeError('Prepared context exceeds 2 GB')


def monitored(args, reserve=GB, stop=None, env=None, stdout=None, timeout_seconds=None):
    process = subprocess.Popen(args, cwd=ROOT, env=env, stdout=stdout)
    started = time.monotonic()
    try:
        while process.poll() is None:
            time.sleep(3)
            if process.poll() is not None:
                break
            if timeout_seconds and time.monotonic() - started > timeout_seconds:
                raise RuntimeError('CYBOT operation exceeded its time limit')
            if stdout and os.fstat(stdout.fileno()).st_size > 16 * 1024**2:
                raise RuntimeError('Captured validation output exceeded 16 MiB')
            usage = disk_usage()
            if usage['accounted_bytes'] + reserve > BUDGET or usage['host_free_bytes'] < 10 * GB:
                raise RuntimeError('Storage reserve reached; stopping only this CYBOT operation.')
        if process.returncode:
            raise RuntimeError(f'Command failed with exit {process.returncode}: {args[0]}')
    finally:
        if process.poll() is None:
            if stop:
                try:
                    stop()
                except (OSError, subprocess.SubprocessError) as error:
                    print(f'Cleanup could not stop this operation: {error}', file=sys.stderr)
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def build():
    if not ARCH:
        raise RuntimeError('Unsupported architecture')
    preflight(4 * GB)
    STATE.mkdir(parents=True, exist_ok=True)
    builder = 'cybot-core-build-' + uuid.uuid4().hex[:10]
    candidate = 'cybotainer:core-candidate-' + uuid.uuid4().hex[:10]
    old = subprocess.run(['docker', 'image', 'inspect', IMAGE, '--format', '{{.Id}}'], capture_output=True, text=True)
    previous = subprocess.run(['docker', 'image', 'inspect', IMAGE + '-previous', '--format', '{{.Id}}'], capture_output=True, text=True)
    created = False
    builder_image_existed = subprocess.run(['docker', 'image', 'inspect', 'moby/buildkit:buildx-stable-1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    try:
        with tempfile.TemporaryDirectory(prefix='build-', dir=STATE) as work:
            dest = Path(work)
            prepare(dest)
            preflight(3 * GB)
            docker('buildx', 'create', '--name', builder, '--driver', 'docker-container',
                   '--driver-opt', 'memory=1g,memory-swap=1g,cpu-period=100000,cpu-quota=100000',
                   '--buildkitd-config', str(ROOT / 'docker/toolbox/buildkitd.toml'))
            created = True
            monitored(['docker', 'buildx', 'build', '--builder', builder, '--platform', f'linux/{ARCH}',
                       '--load', '--provenance=false', '--tag', candidate, str(dest)],
                      stop=lambda: docker('buildx', 'stop', builder))
            # The loaded image is self-contained. Release the idle builder/cache
            # and prepared files before compiling/running the validation harness.
            docker('buildx', 'rm', builder)
            created = False
            shutil.rmtree(dest)
            size = image_bytes(candidate)
            if size > IMAGE_LIMIT:
                raise RuntimeError(f'Image {size} exceeds 3 GB acceptance limit')
            if PROFILE == 'supplychain':
                from supplychain_profile import finalize_dataset
                finalize_dataset(candidate)
            run(['health'], image=candidate, network='none')
            measured = probe(candidate)
            # Keep the active/previous image untouched if any local behavior test fails.
            from toolbox_validation import validate_image
            validate_image(candidate)
            if old.returncode == 0:
                docker('tag', old.stdout.strip(), IMAGE + '-previous')
            docker('tag', candidate, IMAGE)
            save_pin(candidate, measured)
            if previous.returncode == 0 and previous.stdout.strip() != old.stdout.strip():
                # Never force: preserve retired images still referenced by another
                # tag or container. Otherwise keep exactly one previous version.
                subprocess.run(['docker', 'image', 'rm', previous.stdout.strip()], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(json.dumps({'image': IMAGE, 'size_bytes': size, 'previous_retained': old.returncode == 0}))
    finally:
        if created:
            subprocess.run(['docker', 'buildx', 'rm', builder], check=False)
        subprocess.run(['docker', 'image', 'rm', candidate], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not builder_image_existed:
            # No force: Docker refuses deletion if another builder now uses it.
            subprocess.run(['docker', 'image', 'rm', 'moby/buildkit:buildx-stable-1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run(args, image=None, network=None, mounts=(), writable_mounts=(), output=None, timeout_seconds=1800, file_size_limit=67108864, extra_hosts=()):
    if network is None:
        network = 'bridge' if PROFILE == 'core' else 'none'
    if image is None:
        image = current_image()
    preflight()
    size = image_bytes(image)
    if size > IMAGE_LIMIT:
        raise RuntimeError('Image exceeds the 3 GB compact-profile limit')
    for folder in ('reports', 'data', '.cybot'):
        (ROOT / folder).mkdir(exist_ok=True)
    runtime_state = ROOT/'.cybot/runtimes'/PROFILE
    runtime_state.mkdir(parents=True, exist_ok=True, mode=0o700)
    # An engine-wide name is the cross-process lock. Do not remove a conflicting
    # name: it may be someone else's active CYBOT run.
    extra = ['--network', network]
    for host, address in extra_hosts:
        extra += ['--add-host', host+':'+address]
    if PROFILE == 'supplychain':
        datasets = STATE/'datasets'
        if not datasets.is_dir():
            raise RuntimeError('Supply-chain profile requires its verified immutable dataset; build the profile first')
        extra += ['--mount', f'type=bind,src={datasets.resolve()},dst=/opt/cybot/datasets,readonly']
    for source, target in mounts:
        extra += ['--mount', f'type=bind,src={Path(source).resolve()},dst={target},readonly']
    for source, target in writable_mounts:
        if not Path(source).resolve().is_relative_to(STATE.resolve()):
            raise RuntimeError('Writable validation mounts must stay inside this profile state')
        extra += ['--mount', f'type=bind,src={Path(source).resolve()},dst={target}']
    uid = os.getuid() if hasattr(os, 'getuid') else 10001
    gid = os.getgid() if hasattr(os, 'getgid') else 10001
    cache_size = '512m' if PROFILE == 'analysis' else '128m'
    cid = docker('create', *extra, '--pull', 'never', '--name', ACTIVE_NAME, '--label', 'io.cybot.managed=true', '--user', f'{uid}:{gid}',
                 '--memory', '2g', '--memory-swap', '2g', '--cpus', '1', '--pids-limit', '256',
                 '--ulimit', f'fsize={file_size_limit}:{file_size_limit}', '--log-driver', 'none', '--init', '--read-only',
                 '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                 '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m',
                 '--tmpfs', f'/home/cybot/.cache:rw,noexec,nosuid,size={cache_size},uid={uid},gid={gid}',
                 '--tmpfs', f'/home/cybot/.config:rw,noexec,nosuid,size=16m,uid={uid},gid={gid}',
                 '--mount', f'type=bind,src={ROOT / "data"},dst=/data,readonly',
                 '--mount', f'type=bind,src={ROOT / "reports"},dst=/reports',
                 '--mount', f'type=bind,src={runtime_state},dst=/workspace/.cybot', image, *args).strip()
    try:
        with output.open('w') if output else nullcontext(None) as destination:
            monitored(['docker', 'start', '-a', cid], stop=lambda: docker('stop', '--time', '2', cid), stdout=destination, timeout_seconds=timeout_seconds)
        status = json.loads(docker('inspect', cid))[0]['State']
        if status['OOMKilled'] or status['ExitCode']:
            raise RuntimeError(f'CYBOT container exited: {status["ExitCode"]}; memory limit reached: {status["OOMKilled"]}')
    finally:
        docker('rm', '-f', cid)




def runtime_lock_path():
    return STATE / 'runtime.lock.json'


def current_image():
    path = runtime_lock_path()
    if not path.exists():
        raise RuntimeError('No validated runtime pin; build and validate the core image first.')
    entry = json.loads(path.read_text()).get('platforms', {}).get(ARCH)
    if not entry:
        raise RuntimeError(f'No validated {ARCH} image pin; build and validate on that architecture first.')
    return entry.get('reference', entry['image_id'])


def probe(image):
    report = _probe(image)
    report['image_id'] = json.loads(docker('image', 'inspect', image))[0]['Id']
    report['profile'] = PROFILE
    return report


def _probe(image):
    if PROFILE == 'analysis':
        from analysis_profile import probe as probe_analysis
        return probe_analysis(image)
    if PROFILE == 'supplychain':
        from supplychain_profile import probe as probe_supplychain
        return probe_supplychain(image)
    STATE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='probe-', dir=STATE) as temp:
        output = Path(temp) / 'result.txt'
        try:
            run(['exec', 'sh', '-c', toolbox_probe.script()], image=image, network='none', output=output, timeout_seconds=120)
        except (RuntimeError, subprocess.SubprocessError):
            if output.exists():
                diagnostic = STATE / 'probe-error.txt'
                diagnostic.write_bytes(output.read_bytes()[-65536:])
                raise RuntimeError('Runtime version probe failed; diagnostic retained at '+str(diagnostic)) from None
            raise
        measured = toolbox_probe.parse(output.read_text())
    toolbox_probe.validate_source(measured, json.loads((ROOT / 'docker/toolbox/core.lock.json').read_text()))
    return measured


def save_pin(image, measured, reference=None):
    path = runtime_lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = json.loads(path.read_text()) if path.exists() else {'schema': 1, 'platforms': {}}
    inspected = json.loads(docker('image', 'inspect', image))[0]
    lock['platforms'][ARCH] = {'image_id': inspected['Id'], 'tag': IMAGE, 'runtime': measured}
    if reference:
        lock['platforms'][ARCH]['reference'] = reference
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(lock, indent=2) + '\n')
    temporary.replace(path)


def pull(reference):
    # A registry digest is portable and immutable; a local image ID is neither
    # a download address nor sufficient provenance for another machine.
    if not re.fullmatch(r'[a-z0-9][a-z0-9._:/-]+/[a-z0-9._/-]+@sha256:[a-f0-9]{64}', reference):
        raise RuntimeError('Provide a registry image pinned by @sha256:<64 hex digits>')
    preflight(4 * GB)
    monitored(['docker', 'pull', '--platform', f'linux/{ARCH}', reference], timeout_seconds=900)
    if PROFILE == 'supplychain':
        from supplychain_profile import prepare_runtime_data, finalize_dataset
        prepare_runtime_data()
        finalize_dataset(reference)
    measured = probe(reference)
    from toolbox_validation import validate_image
    validate_image(reference)
    save_pin(reference, measured, reference=reference)
    print(json.dumps({'status': 'validated', 'reference': reference, 'platform': f'linux/{ARCH}'}))


def verify():
    image = current_image()
    measured = probe(image)
    entry = json.loads(runtime_lock_path().read_text())['platforms'][ARCH]
    toolbox_probe.validate_runtime(measured, entry['runtime'])
    print(json.dumps({'status': 'verified', 'image_id': image, **measured}, indent=2))


@contextmanager
def operation_lock():
    # Kernel lock automatically releases on process exit. Serializes supported
    # builds and runs across checkouts without changing Docker's global settings.
    path = Path(tempfile.gettempdir()) / 'cybot-toolbox-operation.lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        try:
            if os.name == 'nt':
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b'0')
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, PermissionError):
            raise RuntimeError('Another CYBOT build or run is active; wait for it to finish.') from None
        yield
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['core', 'analysis', 'supplychain'], default='core')
    parser.add_argument('--network', choices=['none', 'bridge'], help='Explicit network choice for run; local analysis profiles default to none')
    parser.add_argument('action', choices=['status', 'build', 'pull', 'run', 'verify', 'image', 'audit'])
    parser.add_argument('args', nargs=argparse.REMAINDER)
    options = parser.parse_args()
    if options.network is not None and options.action != 'run':
        parser.error('--network applies only to run; validation always uses an isolated network')
    configure_profile(options.profile)
    if options.action == 'image':
        print(current_image())
    elif options.action == 'status':
        print(json.dumps(disk_usage(), indent=2))
    else:
        with operation_lock():
            if options.action == 'verify':
                verify()
            elif options.action == 'build':
                build()
            elif options.action == 'audit':
                from audit_toolbox import audit_image
                audit_image()
            elif options.action == 'pull':
                if len(options.args) != 1:
                    raise RuntimeError('usage: toolbox.py pull REGISTRY/IMAGE@sha256:DIGEST')
                pull(options.args[0])
            else:
                run(options.args or ['help'], network=options.network)


if __name__ == '__main__':
    # Profile modules and the validation harness import `toolbox`. Reuse this
    # command's configured module instead of loading a second default-core copy.
    sys.modules['toolbox'] = sys.modules[__name__]
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError, OSError, KeyboardInterrupt) as error:
        print(f'CYBOT toolbox: {error}', file=sys.stderr)
        sys.exit(1)
