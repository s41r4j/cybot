#!/usr/bin/env python3
"""Collect notices for modules actually imported by the CLI, plus Go itself."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess

def objects(text):
    decoder=json.JSONDecoder()
    while text.strip():
        text=text.lstrip(); value,end=decoder.raw_decode(text); yield value; text=text[end:]

def collect(output):
    modules={}
    packages=subprocess.check_output(['go','list','-deps','-json','./cmd/cybot'],text=True)
    for package in objects(packages):
        module=package.get('Module',{})
        if module and not module.get('Main'):
            modules[module['Path']]=module
    output.mkdir(parents=True,exist_ok=True)
    inventory=[]
    for name,module in sorted(modules.items()):
        source=Path(module['Dir']); target=output/name; target.mkdir(parents=True,exist_ok=True)
        notices=[path for path in source.iterdir() if path.is_file() and path.name.upper().startswith(('LICENSE','COPYING','NOTICE'))]
        if not notices:
            raise RuntimeError('Dependency has no root license/notice; review manually: '+name)
        for notice in notices: shutil.copy2(notice,target/notice.name)
        inventory.append({'module':name,'version':module.get('Version'),'notices':[str((target/path.name).relative_to(output)) for path in notices]})
    goroot=Path(subprocess.check_output(['go','env','GOROOT'],text=True).strip())
    (output/'go').mkdir(exist_ok=True);shutil.copy2(goroot/'LICENSE',output/'go/LICENSE')
    target=output/'bundled-prompt-pack';target.mkdir(exist_ok=True)
    shutil.copy2('internal/packs/builtin/LICENSE',target/'LICENSE')
    (output/'modules.json').write_text(json.dumps(inventory,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,default=Path('release-notices'))
    collect(parser.parse_args().output)
