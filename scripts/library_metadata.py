"""Describe checked upstream library variants using standard installed metadata.

Keep the canonical upstream name/version for conservative advisory matching.
The summary and provenance explicitly identify CYBOT's selected-source variant;
this does not assert that the upstream CLI or its unused backends are installed.
"""
import base64
import csv
import hashlib
import io
import importlib.metadata
import json
from pathlib import Path
import re


def install(root,name,version,source,requires,license_file):
    if not re.fullmatch(r'[a-z][a-z0-9-]*',name) or not re.fullmatch(r'\d+\.\d+\.\d+',version):
        raise RuntimeError('Invalid library advisory identity')
    if not source.get('url','').startswith('https://') or not re.fullmatch('[a-f0-9]{64}',source.get('sha256','')):
        raise RuntimeError('Missing checked library source')
    dist=root/(name+'-'+version+'.dist-info');dist.mkdir()
    fields=['Metadata-Version: 2.1','Name: '+name,'Version: '+version,
            'Summary: CYBOT checked-source sequential library variant; upstream CLI backends are not installed',
            'Requires-Python: >=3.11']
    for package,pin in sorted(requires.items()):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',package) or not re.fullmatch(r'[A-Za-z0-9.+-]+',pin):
            raise RuntimeError('Invalid pinned library dependency')
        fields.append('Requires-Dist: '+package+'=='+pin)
    (dist/'METADATA').write_text('\n'.join(fields)+'\n\nChecked source and variant scope are recorded in the adjacent source.lock.json.\n')
    (dist/'INSTALLER').write_text('cybot-checked-source\n')
    (dist/'direct_url.json').write_text(json.dumps({'url':source['url'],'archive_info':{'hashes':{'sha256':source['sha256']}}},sort_keys=True)+'\n')
    (dist/'LICENSE').write_bytes(license_file.read_bytes())
    record=io.StringIO();writer=csv.writer(record,lineterminator='\n')
    for path in sorted(root.rglob('*')):
        if path.is_symlink():raise RuntimeError('Library metadata must not follow source symlinks')
        if not path.is_file():continue
        data=path.read_bytes()
        digest=base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
        writer.writerow([str(path.relative_to(root)),'sha256='+digest,len(data)])
    writer.writerow([str((dist/'RECORD').relative_to(root)),'',''])
    (dist/'RECORD').write_text(record.getvalue())


def verify(root,name,version,lock_sha256,adapter_sha256):
    """Check source/adapter bytes, provenance and installed-file records."""
    def digest(path):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2*1024**2:
            raise RuntimeError('Expected bounded regular library source')
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if root.is_symlink():raise RuntimeError('Unexpected library root symlink')
    if digest(root/'source.lock.json')!=lock_sha256 or digest(root/'adapter.py')!=adapter_sha256:
        raise RuntimeError('Library source lock or adapter differs from the current source')
    lock=json.loads((root/'source.lock.json').read_text())
    expected=lock['files'] if isinstance(lock['files'],dict) else {'dirsearch/'+row['path']:row['sha256'] for row in lock['files']}
    for file,original in expected.items():
        patch=lock.get('patches',{}).get(file)
        required=patch['after_sha256'] if patch else original
        if digest(root/file)!=required:raise RuntimeError('Library code differs from checked source: '+file)
    dist=root/(name+'-'+version+'.dist-info')
    for file in ('METADATA','RECORD','direct_url.json'):digest(dist/file)
    metadata=importlib.metadata.PathDistribution(dist)
    if metadata.version!=version or metadata.metadata['Name']!=name:
        raise RuntimeError('Installed library advisory identity changed')
    source=lock.get('engine') or lock['source']
    direct=json.loads((dist/'direct_url.json').read_text())
    if direct!={'url':source['url'],'archive_info':{'hashes':{'sha256':source['sha256']}}}:
        raise RuntimeError('Installed library provenance changed')
    records=list(csv.reader((dist/'RECORD').read_text().splitlines()));paths=set()
    for row in records:
        if len(row)!=3 or Path(row[0]).is_absolute() or '..' in Path(row[0]).parts or row[0] in paths:
            raise RuntimeError('Unsafe or duplicate installed-file record')
        paths.add(row[0]);path=root/row[0]
        if path.is_symlink() or not path.is_file():raise RuntimeError('Missing regular installed library file')
        if row[0]==str((dist/'RECORD').relative_to(root)):
            if row[1:]!=['','']:raise RuntimeError('Invalid self record')
            continue
        value='sha256='+base64.urlsafe_b64encode(bytes.fromhex(digest(path))).decode().rstrip('=')
        size=path.stat().st_size
        if row[1]!=value or row[2]!=str(size):raise RuntimeError('Installed library file changed')
    allowed=set(expected)|{'adapter.py','source.lock.json'}|{str((dist/file).relative_to(root)) for file in ('METADATA','INSTALLER','direct_url.json','LICENSE','RECORD')}
    actual={str(path.relative_to(root)) for path in root.rglob('*') if path.is_file()}
    if paths!=actual or actual!=allowed or any(path.is_symlink() for path in root.rglob('*')):
        raise RuntimeError('Unrecorded library runtime file')
    return metadata.version
