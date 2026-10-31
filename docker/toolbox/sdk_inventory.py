"""Measure every operational Go SDK executable; compiler tools are not samples."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def sdk_files(root):
    files = {}
    for folder in ('bin','pkg/tool'):
        base = root/folder
        if not base.is_dir() or base.is_symlink(): raise RuntimeError('Missing regular SDK binary directory')
        for path in sorted(base.rglob('*')):
            if path.is_symlink(): raise RuntimeError('Unexpected SDK executable symlink')
            if path.is_dir(): continue
            if not path.is_file() or not path.stat().st_mode & 0o111 or path.stat().st_size>128*1024**2:
                raise RuntimeError('Unexpected SDK executable input')
            files[str(path.relative_to(root))]=path
    if not 3<=len(files)<=32 or 'bin/go' not in files or 'bin/gofmt' not in files:
        raise RuntimeError('Incomplete or oversized SDK executable inventory')
    return files


def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as source:
        while chunk:=source.read(1024*1024): value.update(chunk)
    return value.hexdigest()


def source_manifest(root,version,arch,asset_sha256,goos='linux'):
    return {'schema':1,'version':version,'arch':arch,'os':goos,'asset_sha256':asset_sha256,
            'files':{name:digest(path) for name,path in sdk_files(root).items()}}


def measure(root,manifest):
    if manifest.get('schema')!=1 or manifest.get('os') not in ('linux','darwin') or manifest.get('arch') not in ('amd64','arm64') or not re.fullmatch(r'1\.\d+\.\d+',manifest.get('version','')) or not re.fullmatch(r'[a-f0-9]{64}',manifest.get('asset_sha256','')):
        raise RuntimeError('Invalid SDK source manifest')
    files=sdk_files(root)
    if set(files)!=set(manifest.get('files',{})): raise RuntimeError('SDK executable set changed')
    result={}
    env=dict(os.environ,GOTOOLCHAIN='local',GOFLAGS='',GOWORK='off',GOENV='off',GOTELEMETRY='off',GOPROXY='off',GOSUMDB='off',GOROOT=str(root))
    for relative,path in files.items():
        actual=digest(path)
        if actual!=manifest['files'][relative]: raise RuntimeError('SDK executable differs from verified source: '+relative)
        output=subprocess.run([str(root/'bin/go'),'version','-m',str(path)],capture_output=True,text=True,check=True,timeout=15,env=env).stdout
        if len(output)>65536 or not output.splitlines() or output.splitlines()[0]!=str(path)+': go'+manifest['version']:
            raise RuntimeError('SDK executable reports a different compiler: '+relative)
        settings=dict(re.findall(r'^\s*build\s+(GOOS|GOARCH|CGO_ENABLED)=(\S+)',output,re.M))
        if settings.get('GOOS')!=manifest['os'] or settings.get('GOARCH')!=manifest['arch']:
            raise RuntimeError('SDK executable has a different platform: '+relative)
        name='go' if relative=='bin/go' else 'go-sdk-'+re.sub(r'[^a-zA-Z0-9.-]','-',relative)
        if name in result: raise RuntimeError('Duplicate SDK executable identity')
        result[name]={'path':str(path),'sha256':actual,'reported_version':manifest['version']}
    return result


if __name__=='__main__':
    root=Path('/opt/go')
    manifest_path=Path('/opt/cybot/share/builds/go-sdk.json')
    if manifest_path.is_symlink() or manifest_path.stat().st_size>65536: raise RuntimeError('Invalid SDK source record')
    manifest=json.loads(manifest_path.read_text())
    if manifest.get('os')!='linux': raise RuntimeError('Runtime SDK must target Linux')
    print(json.dumps({'binaries':measure(root,manifest),'source':manifest,'manifest_sha256':digest(manifest_path),'helper_sha256':digest(Path(__file__))}))
