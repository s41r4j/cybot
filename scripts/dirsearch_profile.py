"""Prepare the pinned Dirsearch library API, not its unrelated CLI backends."""
import hashlib
import json
from pathlib import Path
import shutil
import tarfile

import toolbox


def prepare(dest):
    lock_path=toolbox.ROOT/'docker/toolbox/dirsearch.lock.json'
    lock=json.loads(lock_path.read_text())
    archive=dest/'dirsearch.tar.gz';toolbox.download(lock['source'],archive)
    root=dest/'lib/dirsearch'
    expected={row['path']:row['sha256'] for row in lock['files']}
    if len(expected)!=len(lock['files']):raise RuntimeError('Duplicate source record')
    found=set();total=0
    with tarfile.open(archive) as source:
        for member in source:
            parts=Path(member.name).parts
            if not parts or parts[0]!='dirsearch-'+lock['source']['commit'] or '..' in parts or Path(member.name).is_absolute():
                raise RuntimeError('Unexpected Dirsearch source archive path')
            name='/'.join(parts[1:])
            if name not in expected:continue
            if name in found or not member.isfile() or member.size>128*1024:
                raise RuntimeError('Invalid selected Dirsearch source')
            data=source.extractfile(member).read();total+=len(data)
            if total>2*1024**2 or hashlib.sha256(data).hexdigest()!=expected[name]:
                raise RuntimeError('Dirsearch source differs from the pinned library')
            target=root/'dirsearch'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);found.add(name)
    if found!=set(expected):raise RuntimeError('Incomplete Dirsearch library source')
    archive.unlink()
    notices=dest/'share/licenses/dirsearch';notices.mkdir(parents=True)
    toolbox.download(lock['notice'],notices/'GPL-2.0.txt')
    shutil.copyfile(root/'dirsearch/README.md',notices/'upstream-README.md')
    shutil.copyfile(toolbox.ROOT/'docker/toolbox/dirsearch_wrapper.py',root/'adapter.py')
    shutil.copyfile(lock_path,root/'source.lock.json')
    binary=dest/'bin/dirsearch';binary.write_text('#!/bin/sh\nset -eu\nexec python3 -B /opt/cybot/lib/dirsearch/adapter.py "$@"\n');binary.chmod(0o755)
