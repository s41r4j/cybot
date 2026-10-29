"""Pinned offline vulnerability and infrastructure configuration scanning."""
import json
import hashlib
from pathlib import Path
import re
import shutil
import tarfile
import tempfile

import toolbox
import toolbox_probe


def prepare(dest):
    lock = json.loads((toolbox.ROOT/'docker/toolbox/supplychain.lock.json').read_text())
    for name, spec in lock['tools'].items():
        archive = dest/'tool-download'
        toolbox.download(spec['assets'][toolbox.ARCH], archive)
        toolbox.unpack_binary(archive, name, dest)
        archive.unlink()
    prepare_runtime_data()
    shutil.copy(toolbox.ROOT/'docker/toolbox/supplychain.Dockerfile', dest/'Dockerfile')
    # Bind the exact data version into the image's environment, while keeping
    # the large database outside image layers and build contexts.
    dockerfile = dest/'Dockerfile'
    dockerfile.write_text(dockerfile.read_text().replace('@DATABASE_SHA256@', lock['data']['trivy-db']['sha256']).replace('@GRYPE_DATABASE_SHA256@', lock['data']['grype-db']['sha256']))
    shutil.copy(toolbox.ROOT/'docker/toolbox/supplychain.lock.json', dest/'supplychain.lock.json')
    shutil.copy(toolbox.ROOT/'scripts/toolbox-supplychain-entrypoint.sh', dest/'entrypoint.sh')
    (dest/'entrypoint.sh').chmod(0o755)
    toolbox.prepare_cli(dest)


def prepare_runtime_data():
    lock = json.loads((toolbox.ROOT/'docker/toolbox/supplychain.lock.json').read_text())
    toolbox.STATE.mkdir(parents=True, exist_ok=True)
    prepare_dataset(lock['data']['trivy-db'])
    asset = lock['data']['grype-db']
    root = toolbox.STATE/'datasets'
    archive = root/(asset['sha256']+'.tar.zst')
    if archive.exists():
        if file_hash(archive) != asset['sha256']:
            raise RuntimeError('Cached Grype archive was modified')
    else:
        temporary = archive.with_suffix('.download')
        try:
            toolbox.download(asset, temporary)
            temporary.rename(archive)
        finally:
            temporary.unlink(missing_ok=True)


def finalize_dataset(image):
    lock = json.loads((toolbox.ROOT/'docker/toolbox/supplychain.lock.json').read_text())
    asset = lock['data']['grype-db']
    root = toolbox.STATE/'datasets'; final = root/asset['sha256']
    expected = {'grype/6/vulnerability.db', 'grype/6/import.json'}
    if (final/'dataset.json').is_file():
        saved = json.loads((final/'dataset.json').read_text())
        if saved.get('archive_sha256') == asset['sha256'] and set(saved.get('files', {})) == expected and all(file_hash(final/name) == digest for name, digest in saved['files'].items()):
            return
        raise RuntimeError('Installed Grype dataset was modified; refusing to replace it')
    archive = root/(asset['sha256']+'.tar.zst')
    if not archive.is_file() or file_hash(archive) != asset['sha256']:
        raise RuntimeError('Verified Grype database archive is missing')
    toolbox.preflight(6 * toolbox.GB)
    # Let the pinned native CLI hydrate/import its own database format inside
    # the bounded container, rather than fabricate its integrity metadata.
    with tempfile.TemporaryDirectory(prefix='hydrate-', dir=root) as temp:
        temp = Path(temp); content = temp/'content'; content.mkdir()
        (content/'tmp').mkdir()
        toolbox.run(['exec', 'env', 'GRYPE_DB_CACHE_DIR=/validation/import/grype',
                     'GRYPE_DB_AUTO_UPDATE=false', 'GRYPE_CHECK_FOR_APP_UPDATE=false',
                     'TMPDIR=/validation/import/tmp', 'SQLITE_TMPDIR=/validation/import/tmp',
                     'grype', 'db', 'import', '/validation/db.tar.zst'],
                    image=image, network='none', mounts=[(archive, '/validation/db.tar.zst')],
                    writable_mounts=[(content, '/validation/import')],
                    file_size_limit=6 * 1024**3, timeout_seconds=1200)
        if not all((content/name).is_file() for name in expected):
            raise RuntimeError('Grype did not produce a complete imported database')
        shutil.rmtree(content/'tmp')
        files = {name: file_hash(content/name) for name in sorted(expected)}
        (content/'dataset.json').write_text(json.dumps({'archive_sha256': asset['sha256'], 'files': files}, indent=2)+'\n')
        content.rename(final)


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(1024*1024):
            digest.update(block)
    return digest.hexdigest()


def prepare_dataset(asset):
    if not re.fullmatch('[a-f0-9]{64}', asset['sha256']):
        raise RuntimeError('Dataset identifier must be a SHA-256 digest')
    root = toolbox.STATE/'datasets'; root.mkdir(parents=True, exist_ok=True)
    final = root/asset['sha256']
    if (final/'dataset.json').is_file():
        saved = json.loads((final/'dataset.json').read_text())
        expected_files = {'trivy/db/trivy.db', 'trivy/db/metadata.json'}
        if saved.get('archive_sha256') == asset['sha256'] and set(saved.get('files', {})) == expected_files and all(file_hash(final/name) == digest for name, digest in saved['files'].items()):
            return
        raise RuntimeError('Installed immutable dataset was modified; refusing to overwrite it')
    with tempfile.TemporaryDirectory(prefix='download-', dir=root) as temp:
        temp = Path(temp); archive = temp/'db.tar.gz'
        toolbox.download(asset, archive)
        target = temp/'content/trivy/db'; target.mkdir(parents=True)
        total, found = 0, set()
        with tarfile.open(archive) as source:
            for member in source:
                if not member.isfile() or member.name not in ('trivy.db', 'metadata.json'):
                    continue
                total += member.size
                if total > 4 * 1024**3:
                    raise RuntimeError(f'Trivy dataset exceeds 4 GiB: {total} bytes')
                toolbox.preflight(member.size + toolbox.GB)
                with source.extractfile(member) as src, (target/member.name).open('wb') as out:
                    shutil.copyfileobj(src, out)
                found.add(member.name)
        if found != {'trivy.db', 'metadata.json'}:
            raise RuntimeError('Incomplete vulnerability database archive')
        content = temp/'content'
        files = {'trivy/db/'+name: file_hash(target/name) for name in sorted(found)}
        (content/'dataset.json').write_text(json.dumps({'archive_sha256': asset['sha256'], 'files': files}, indent=2)+'\n')
        content.rename(final)


def probe(image):
    binaries = {'cybot': ('/opt/cybot/bin/cybot', '--version'),
                'trivy': ('/opt/cybot/bin/trivy', '--version'),
                'grype': ('/opt/cybot/bin/grype', 'version'),
                'syft': ('/opt/cybot/bin/syft', 'version')}
    script = toolbox_probe.script(binaries, packages=False)
    script += '\nprintf \'CYBOT_DATABASE \'\nsha256sum "$CYBOT_TRIVY_CACHE_DIR/db/trivy.db"\n'
    script += '\nprintf \'CYBOT_GRYPE_DATABASE \'\nsha256sum "$GRYPE_DB_CACHE_DIR/6/vulnerability.db"\n'
    with tempfile.TemporaryDirectory(prefix='probe-', dir=toolbox.STATE) as temp:
        output = Path(temp)/'result.txt'
        toolbox.run(['exec', 'sh', '-c', script], image=image, network='none', output=output, timeout_seconds=120)
        text = output.read_text()
    report = toolbox_probe.parse(text, binaries, packages=False)
    source = json.loads((toolbox.ROOT/'docker/toolbox/supplychain.lock.json').read_text())
    toolbox_probe.validate_source(report, source)
    digest = re.search(r'CYBOT_DATABASE ([a-f0-9]{64})\s', text)
    if not digest:
        raise RuntimeError('Missing installed vulnerability database measurement')
    report['data'] = {'trivy-db': {'sha256': digest[1], 'source': source['data']['trivy-db']}}
    grype = re.search(r'CYBOT_GRYPE_DATABASE ([a-f0-9]{64})\s', text)
    if not grype:
        raise RuntimeError('Missing imported Grype database measurement')
    report['data']['grype-db'] = {'sha256': grype[1], 'source': source['data']['grype-db']}
    return report
