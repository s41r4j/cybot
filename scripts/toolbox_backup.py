"""Checksummed image-only backups bound to validated runtime pins."""
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import threading

import toolbox
import toolbox_probe


def checksum(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def backup(destination=None):
    toolbox.preflight(4 * toolbox.GB)
    entry = json.loads(toolbox.runtime_lock_path().read_text())['platforms'][toolbox.ARCH]
    image = entry['image_id']
    if toolbox.image_bytes(image) > toolbox.IMAGE_LIMIT:
        raise RuntimeError('Backup image exceeds the profile size limit')
    measured = toolbox.probe(image)
    toolbox_probe.validate_runtime(measured, entry['runtime'])
    parent = toolbox.ROOT/'backups'
    parent.mkdir(exist_ok=True)
    destination = (Path(destination) if destination else parent/('cybot-'+toolbox.PROFILE+'-'+toolbox.ARCH+'-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))).resolve()
    if not destination.is_relative_to(parent.resolve()) or destination == parent.resolve():
        raise RuntimeError('Backup directory must be inside this workspace backups directory for storage accounting')
    if destination.exists():
        raise RuntimeError('Backup destination already exists; existing backups are preserved')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.backup-', dir=destination.parent) as temp:
        stage = Path(temp)
        archive = stage/'image.tar.gz'
        process = subprocess.Popen(['docker', 'save', image], stdout=subprocess.PIPE)
        expired = threading.Event()
        def stop():
            expired.set()
            process.kill()
        timer = threading.Timer(900, stop)
        timer.start()
        try:
            expanded = 0
            with gzip.open(archive, 'wb', compresslevel=6) as output:
                while block := process.stdout.read(1024 * 1024):
                    expanded += len(block)
                    if expanded > 4 * toolbox.GB or archive.stat().st_size > toolbox.IMAGE_LIMIT:
                        raise RuntimeError('Image backup exceeds its bounded archive limit')
                    output.write(block)
                    if expanded % (16 * 1024**2) == 0:
                        usage = toolbox.disk_usage()
                        if usage['accounted_bytes'] + toolbox.GB > toolbox.BUDGET or usage['host_free_bytes'] < 10 * toolbox.GB:
                            raise RuntimeError('Storage reserve reached while backing up this image')
            if process.wait() != 0 or expired.is_set():
                raise RuntimeError('Image backup failed or timed out')
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
        manifest = {'schema': 1, 'profile': toolbox.PROFILE, 'platform': 'linux/'+toolbox.ARCH,
                    'image_id': image, 'runtime': measured, 'archive': 'image.tar.gz',
                    'archive_sha256': checksum(archive), 'archive_bytes': archive.stat().st_size,
                    'scope': 'image-only; excludes workspace state and external datasets'}
        (stage/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        inspect_backup(stage)
        # Publish the archive and required manifest in a single directory rename.
        stage.rename(destination)
    print(json.dumps({'backup': str(destination), 'image_id': image, 'scope': manifest['scope']}))


def inspect_backup(directory):
    directory = Path(directory).resolve(strict=True)
    manifest_path = directory/'manifest.json'
    archive = directory/'image.tar.gz'
    if manifest_path.is_symlink() or archive.is_symlink() or manifest_path.stat().st_size > 1024 * 1024:
        raise RuntimeError('Unsafe backup manifest or archive')
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('schema') != 1 or manifest.get('profile') != toolbox.PROFILE or manifest.get('platform') != 'linux/'+toolbox.ARCH:
        raise RuntimeError('Backup profile or architecture does not match the selected runtime')
    image = manifest.get('image_id', '')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image) or manifest.get('archive') != archive.name:
        raise RuntimeError('Invalid immutable backup image identity')
    if archive.stat().st_size > toolbox.IMAGE_LIMIT or archive.stat().st_size != manifest.get('archive_bytes') or checksum(archive) != manifest.get('archive_sha256'):
        raise RuntimeError('Backup checksum or size mismatch; image was not loaded')
    expanded = 0
    with gzip.open(archive, 'rb') as raw:
        while block := raw.read(1024 * 1024):
            expanded += len(block)
            if expanded > 4 * toolbox.GB:
                raise RuntimeError('Expanded image archive exceeds its limit')
    # Never extract paths on the host. Loading tagged archives could replace a
    # different local image before operation validation, so reject them first.
    docker_manifest = None
    config = None
    total = 0
    with tarfile.open(archive, 'r|gz') as source:
        for entry in source:
            parts = Path(entry.name).parts
            if not parts or '..' in parts or Path(entry.name).is_absolute() or entry.issym() or entry.islnk() or not (entry.isfile() or entry.isdir()):
                raise RuntimeError('Unsafe image archive member')
            total += entry.size + 512
            if total > 4 * toolbox.GB:
                raise RuntimeError('Expanded image archive exceeds its limit')
            if entry.name == 'manifest.json':
                if docker_manifest is not None or entry.size > 1024 * 1024:
                    raise RuntimeError('Invalid Docker image manifest')
                docker_manifest = json.load(source.extractfile(entry))
            if entry.name in (image[7:]+'.json', 'blobs/sha256/'+image[7:]):
                if config is not None or entry.size > 1024 * 1024:
                    raise RuntimeError('Invalid Docker image configuration')
                data = source.extractfile(entry).read()
                if hashlib.sha256(data).hexdigest() != image[7:]:
                    raise RuntimeError('Image configuration differs from its immutable identity')
                config = json.loads(data)
    if not isinstance(docker_manifest, list) or len(docker_manifest) != 1 or docker_manifest[0].get('RepoTags'):
        raise RuntimeError('Backup must contain one untagged immutable image')
    if docker_manifest[0].get('Config') not in (image[7:]+'.json', 'blobs/sha256/'+image[7:]):
        raise RuntimeError('Docker manifest differs from backup image identity')
    if not config or config.get('os') != 'linux' or config.get('architecture') != toolbox.ARCH:
        raise RuntimeError('Archived image platform differs from the backup manifest')
    return manifest, archive


def restore(directory):
    manifest, archive = inspect_backup(directory)
    toolbox.preflight(4 * toolbox.GB)
    toolbox.monitored(['docker', 'load', '--input', str(archive)], timeout_seconds=900)
    image = manifest['image_id']
    if toolbox.image_bytes(image) > toolbox.IMAGE_LIMIT:
        raise RuntimeError('Restored image exceeds the profile size limit')
    measured = toolbox.probe(image)
    toolbox_probe.validate_runtime(measured, manifest['runtime'])
    from toolbox_validation import validate_image
    validate_image(image)
    # A failed identity check or operation suite leaves the active pin untouched.
    toolbox.save_pin(image, measured)
    print(json.dumps({'status': 'restored-and-validated', 'image_id': image,
                      'scope': 'image-only; existing workspace state and datasets are preserved'}))
