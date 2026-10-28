#!/usr/bin/env python3
"""Scan public source using an official checksum-pinned Gitleaks executable."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1]

def scanner(archive=None):
    lock=json.loads((ROOT/'release/secret-scanner.lock.json').read_text())
    arch={'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','AMD64':'amd64'}.get(platform.machine())
    system={'Darwin':'darwin','Linux':'linux'}.get(platform.system())
    asset=lock['assets'].get(f'{system}/{arch}')
    if not asset: raise RuntimeError('Secret scanner bootstrap supports Linux/macOS AMD64/ARM64; use a validated scanner on this OS')
    if archive:
        if archive.stat().st_size > 64*1024*1024: raise RuntimeError('Scanner archive is too large')
        data=archive.read_bytes()
    else:
        with urllib.request.urlopen(asset['url'],timeout=60) as response:
            data=response.read(64*1024*1024+1)
    if len(data)>64*1024*1024 or hashlib.sha256(data).hexdigest()!=asset['sha256']:
        raise RuntimeError('Secret scanner release checksum mismatch')
    return data

def scan(source,history=False,archive=None):
    data=scanner(archive)
    with tempfile.TemporaryDirectory(prefix='cybot-secrets-') as temp:
        root=Path(temp);binary=root/'gitleaks'
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            members=[m for m in archive.getmembers() if m.isfile() and Path(m.name).name=='gitleaks']
            if len(members)!=1 or members[0].size>200*1024*1024: raise RuntimeError('Invalid scanner archive')
            binary.write_bytes(archive.extractfile(members[0]).read())
        binary.chmod(0o700)
        command=[str(binary),'git' if history else 'dir',str(source.resolve()),'--config',str(ROOT/'.gitleaks.toml'),'--redact=100','--no-banner','--report-format=json','--report-path',str(root/'report.json')]
        subprocess.run(command,check=True,timeout=120)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('source',type=Path);parser.add_argument('--history',action='store_true');parser.add_argument('--archive',type=Path,help='Use an already downloaded archive, still verified against the pinned SHA-256')
    args=parser.parse_args();scan(args.source,args.history,args.archive)
