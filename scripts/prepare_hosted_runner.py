#!/usr/bin/env python3
"""Reclaim unused SDKs only inside a disposable GitHub-hosted Linux job VM.

This is CI setup, not a local toolbox cleanup command. No Docker images,
containers, project state, caches or user directories are deleted.
"""
import os
from pathlib import Path
import shutil
import subprocess

GB = 1000**3
SDK_PATHS = ('/usr/local/lib/android', '/usr/share/dotnet', '/usr/local/.ghcup')


def prepare():
    if any(os.environ.get(key) != value for key,value in {
        'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_OS':'Linux'
    }.items()):
        raise RuntimeError('CI disk preparation is restricted to disposable GitHub-hosted Linux jobs')
    workspace = Path(os.environ.get('GITHUB_WORKSPACE',''))
    if not workspace.is_absolute() or not workspace.is_dir():
        raise RuntimeError('Missing hosted-job workspace')
    for name in SDK_PATHS:
        free = shutil.disk_usage(workspace).free
        print(f'Hosted runner free disk: {free/GB:.2f} GB',flush=True)
        if free >= 30*GB: return
        path = Path(name)
        if not path.exists(): continue
        if path.is_symlink() or path.resolve() != path or not path.is_dir():
            raise RuntimeError('Refusing unexpected preinstalled SDK path: '+name)
        print('Removing unused preinstalled SDK from this disposable job VM: '+name,flush=True)
        subprocess.run(['sudo','-n','rm','-rf','--one-file-system','--',name],check=True,timeout=180)
    free = shutil.disk_usage(workspace).free
    if free < 30*GB:
        raise RuntimeError(f'Hosted runner has {free/GB:.2f} GB free; 30 GB is required to preserve the 20 GB product budget plus 10 GB host reserve')


if __name__ == '__main__': prepare()
