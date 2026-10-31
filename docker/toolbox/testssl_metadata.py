"""Verify installed TestSSL engine/data bytes against the checked Debian package."""
import hashlib
from pathlib import Path, PurePosixPath
import re


def verify(lock, root=Path('/')):
    if lock.get('schema')!=1 or lock.get('version')!='3.2.1' or not isinstance(lock.get('runtime_files'),list) or not 1<=len(lock['runtime_files'])<=64:
        raise RuntimeError('Invalid TestSSL source manifest')
    root=root.resolve(strict=True)
    expected={};digest=hashlib.sha256();total=0
    for row in lock['runtime_files']:
        name=row.get('path','');relative=PurePosixPath(name)
        if not relative.is_absolute() or '..' in relative.parts or not (name=='/usr/bin/testssl' or name.startswith('/etc/testssl/')) or name in expected:
            raise RuntimeError('Unexpected TestSSL source path')
        if not re.fullmatch('[a-f0-9]{64}',row.get('sha256','')) or type(row.get('size')) is not int or not 0<row['size']<=4*1024**2:
            raise RuntimeError('Invalid TestSSL source identity')
        path=root.joinpath(*relative.parts[1:])
        for candidate in [path,*path.parents]:
            if candidate==root:break
            if candidate.is_symlink():raise RuntimeError('Unexpected TestSSL source symlink')
        if not path.is_file() or path.stat().st_size!=row['size']:
            raise RuntimeError('TestSSL source size differs from the checked package')
        actual=hashlib.sha256(path.read_bytes()).hexdigest()
        if actual!=row['sha256']:raise RuntimeError('TestSSL source bytes differ from the checked package')
        total+=row['size']
        if total>8*1024**2:raise RuntimeError('TestSSL source exceeds its bound')
        expected[name]=actual
    actual=set()
    base=root/'etc/testssl'
    if not base.is_dir() or base.is_symlink():raise RuntimeError('Missing regular TestSSL data directory')
    for index,path in enumerate(base.rglob('*')):
        if index>256 or path.is_symlink():raise RuntimeError('Unexpected TestSSL data tree')
        if path.is_file():actual.add('/'+str(path.relative_to(root)))
    if actual|{'/usr/bin/testssl'}!=set(expected):raise RuntimeError('TestSSL runtime file set differs from the checked package')
    for name,value in sorted(expected.items()):digest.update(name.encode()+b'\0'+bytes.fromhex(value))
    return digest.hexdigest()
