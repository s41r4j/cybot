"""Pin the upstream single-target CORS engine and its sequential adapter."""
import hashlib
import json
from pathlib import Path
import shutil
import zipfile

from javascript_profile import unpack_wheel
from patched_go_tools import patch_source
import toolbox


def prepare(dest):
    lock_path = toolbox.ROOT/'docker/toolbox/cors.lock.json'
    lock = json.loads(lock_path.read_text())
    root = dest/'lib/cors'
    archive = dest/'cors-engine.whl'
    toolbox.download(lock['engine'], archive)
    # The library's full ten-check engine is used sequentially for one target.
    # Unused CLI concurrency, build copies, embedded old eggs and images are not
    # runtime inputs. Every selected source/data/license byte is pinned below.
    with zipfile.ZipFile(archive) as source:
        for name, expected in lock['files'].items():
            if name not in ('CORScanner/common/corscheck.py','CORScanner/origins.json','CORScanner/LICENSE'):
                raise RuntimeError('Unexpected CORS library source selection')
            entries = [entry for entry in source.infolist() if entry.filename == name]
            if len(entries) != 1 or entries[0].file_size > 128*1024:
                raise RuntimeError('Missing or oversized CORS library input')
            data = source.read(entries[0])
            if hashlib.sha256(data).hexdigest() != expected:
                raise RuntimeError('CORS library source changed')
            target = root/name
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(data)
    archive.unlink()
    patches = patch_source(root,lock['patches'])
    for name, asset in lock['wheels'].items():
        archive = dest/'cors-dependency.whl'
        toolbox.download(asset, archive)
        unpack_wheel(archive,dest/'lib/python',dest/'share/licenses/python'/name)
        archive.unlink()
    notices = dest/'share/licenses/corscanner';notices.mkdir(parents=True)
    shutil.copyfile(root/'CORScanner/LICENSE',notices/'LICENSE')
    shutil.copyfile(toolbox.ROOT/'docker/toolbox/corscanner_wrapper.py',root/'adapter.py')
    (dest/'bin/corscanner').write_text('#!/bin/sh\nset -eu\nexec python3 -B /opt/cybot/lib/cors/adapter.py "$@"\n')
    (dest/'bin/corscanner').chmod(0o755)
    shutil.copyfile(lock_path,root/'source.lock.json')
    from library_metadata import install
    web=json.loads((toolbox.ROOT/'docker/toolbox/web.lock.json').read_text())
    install(root,'corscanner',lock['version'],lock['engine'],
            {'requests':web['wafw00f']['wheels']['requests']['version'],'tldextract':lock['wheels']['tldextract']['version']},root/'CORScanner/LICENSE')
    builds = dest/'share/builds';builds.mkdir(parents=True,exist_ok=True)
    (builds/'cors-source.json').write_text(json.dumps({'source_lock_sha256':hashlib.sha256(lock_path.read_bytes()).hexdigest(),'patches':patches},indent=2)+'\n')
