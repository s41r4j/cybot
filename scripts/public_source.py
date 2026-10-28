#!/usr/bin/env python3
"""Export an allowlisted public source snapshot; never copy Git history or state."""
import argparse
import hashlib
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = {'.github', 'catalog', 'cmd', 'configs', 'docker', 'docs', 'examples',
               'internal', 'pkg', 'release', 'rules', 'schemas', 'scripts', 'website'}
FILES = {'.dockerignore', '.gitattributes', '.gitignore', '.gitleaks.toml', '.goreleaser.yaml',
         'go.mod', 'go.sum', 'docker-compose.toolbox.yml', 'README.md', 'ROADMAP.md', 'LICENSE', 'SECURITY.md',
         'THIRD_PARTY_NOTICES.md', 'CONTRIBUTING.md'}
PRIVATE_PARTS = {'.git', '.cybot', '.aws', '.codex', '.agents', 'node_modules',
                 '__pycache__', 'videos', 'nasa-recon', 'reference', 'backups'}

def public_files(root=ROOT):
    for top in sorted(root.iterdir()):
        if top.name not in DIRECTORIES | FILES:
            continue
        candidates = sorted(top.rglob('*')) if top.is_dir() else [top]
        for path in candidates:
            rel = path.relative_to(root)
            if any(part in PRIVATE_PARTS for part in rel.parts):
                continue
            if path.is_symlink():
                raise RuntimeError('Public source must not follow symlinks: ' + str(rel))
            if not path.is_file() or path.suffix in ('.pyc', '.log', '.db'):
                continue
            if rel.parts[:2] == ('docs', 'images') or path.name == '.DS_Store':
                continue
            if path.name.startswith('build-result') or path.name == 'core-runtime.lock.json':
                continue
            if str(rel) == 'docs/deepseek-cybot-assessment.md':
                continue
            yield path, rel

def source_digest(root=ROOT):
    digest = hashlib.sha256()
    for path, rel in public_files(root):
        if rel.parts[0] not in {'.github', 'cmd', 'internal', 'pkg', 'catalog', 'schemas', 'rules', 'configs', 'docker', 'scripts'} and path.name not in {'go.mod', 'go.sum', 'docker-compose.toolbox.yml', '.gitleaks.toml', '.goreleaser.yaml'}:
            continue
        digest.update(str(rel).replace('\\', '/').encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()

def export(destination, root=ROOT):
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError('Destination must be a new or empty directory')
    if destination == root.resolve() or root.resolve() in destination.parents:
        raise RuntimeError('Export destination must be outside the private checkout')
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    for path, rel in public_files(root):
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        count += 1
    return count

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', nargs='?', type=Path)
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(source_digest())
    elif args.destination:
        print(f'Exported {export(args.destination)} public files to {args.destination}')
    else:
        parser.error('provide a destination or --digest')
