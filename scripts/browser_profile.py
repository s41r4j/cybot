"""Pinned Chromium and browser CLI, measured independently of help/presence checks."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile

import toolbox


def prepare(dest):
    lock = json.loads((toolbox.ROOT/'docker/toolbox/browser.lock.json').read_text())
    (dest/'bin').mkdir(exist_ok=True)
    binary = dest/'bin/agent-browser'
    toolbox.download(lock['agent_browser']['assets'][toolbox.ARCH], binary)
    binary.chmod(0o755)
    notices = dest/'share/licenses/agent-browser'
    for name, asset in lock['agent_browser']['source_files'].items():
        path = notices/name
        path.parent.mkdir(parents=True, exist_ok=True)
        toolbox.download(asset, path)
    shutil.copyfile(toolbox.ROOT/'docker/toolbox/browser.lock.json', dest/'browser.lock.json')
    pins = ' '.join(name+'='+version for name, version in lock['packages'][toolbox.ARCH].items())
    (dest/'Dockerfile').write_text((toolbox.ROOT/'docker/toolbox/browser.Dockerfile').read_text().replace('@PACKAGE_PINS@', pins))
    shutil.copyfile(toolbox.ROOT/'scripts/toolbox-browser-entrypoint.sh', dest/'entrypoint.sh')
    (dest/'entrypoint.sh').chmod(0o755)
    toolbox.prepare_cli(dest)


def probe(image):
    lock = json.loads((toolbox.ROOT/'docker/toolbox/browser.lock.json').read_text())
    commands = {
        'cybot': ('/opt/cybot/bin/cybot', '/opt/cybot/bin/cybot --version'),
        'agent-browser': ('/opt/cybot/bin/agent-browser', '/opt/cybot/bin/agent-browser --version'),
        'chromium': ('/usr/lib/chromium/chromium', '/usr/bin/chromium --version'),
        'chromium-launcher': ('/usr/bin/chromium', '/usr/bin/chromium --version'),
        'python': ('/usr/bin/python3', 'python3 -c "import platform; print(platform.python_version())"'),
    }
    lines = ['set -eu']
    for name, (path, command) in commands.items():
        lines += [f"printf '\\nCYBOT_HASH {name} '", 'sha256sum '+path,
                  f"printf 'CYBOT_VERSION {name}\\n'", command+' 2>&1', "printf '\\nCYBOT_END\\n'"]
    lines += ["printf 'CYBOT_BROWSER_DATA\\n'", "python3 -B - <<'PY'", 'import hashlib,json,pathlib,subprocess',
              'data={}',
              "for name,directory in {'chromium-tree':'/usr/lib/chromium','source-notices':'/opt/cybot/share/licenses/agent-browser'}.items():",
              ' digest=hashlib.sha256()', ' for path in sorted(pathlib.Path(directory).rglob("*")):',
              '  if path.is_symlink(): digest.update(str(path.relative_to(directory)).encode()+b"\\0LINK\\0"+str(path.readlink()).encode())',
              '  elif path.is_file(): digest.update(str(path.relative_to(directory)).encode()+b"\\0"+hashlib.sha256(path.read_bytes()).digest())',
              ' data[name]=digest.hexdigest()',
              "data['source-lock']=hashlib.sha256(pathlib.Path('/opt/cybot/manifest/browser.lock.json').read_bytes()).hexdigest()",
              'packages=dict(line.split("=",1) for line in subprocess.check_output(["dpkg-query","-W","-f=${Package}=${Version}\\n",*'+repr(list(lock['packages'][toolbox.ARCH]))+'],text=True).splitlines())',
              'all_packages=dict(line.split("=",1) for line in subprocess.check_output(["dpkg-query","-W","-f=${binary:Package}=${Version}\\n"],text=True).splitlines())',
              'print(json.dumps({"data":data,"packages":packages,"all_packages":all_packages}))', 'PY', "printf 'CYBOT_END\\n'"]
    toolbox.STATE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='probe-', dir=toolbox.STATE) as temp:
        output = Path(temp)/'probe.txt'
        try:
            toolbox.run(['exec','sh','-c','\n'.join(lines)],image=image,network='none',output=output,timeout_seconds=120)
        except RuntimeError:
            if output.exists(): (toolbox.STATE/'probe-error.txt').write_bytes(output.read_bytes()[-65536:])
            raise
        text = output.read_text()
    extra = re.search(r'CYBOT_BROWSER_DATA\n(.*?)\nCYBOT_END',text,re.S)
    if not extra: raise RuntimeError('Missing browser runtime inventory')
    report = dict(json.loads(extra[1]), binaries={})
    if report['packages'] != lock['packages'][toolbox.ARCH]: raise RuntimeError('Browser runtime package versions differ from source lock')
    for name,(path,_) in commands.items():
        digest = re.search(r'CYBOT_HASH '+name+r' ([a-f0-9]{64})\s',text)
        output = re.search(r'CYBOT_VERSION '+name+r'\n(.*?)\nCYBOT_END',text,re.S)
        version = re.search(r'(?<!\d)(\d+\.\d+\.\d+(?:\.\d+)?)(?!\d)',output[1]) if output else None
        if not digest or not version: raise RuntimeError('Incomplete browser runtime measurement: '+name+'\n'+text[-4000:])
        report['binaries'][name] = {'path':path,'sha256':digest[1],'reported_version':version[1]}
    if report['binaries']['agent-browser']['sha256'] != lock['agent_browser']['assets'][toolbox.ARCH]['sha256'] or report['binaries']['agent-browser']['reported_version'] != lock['agent_browser']['version']:
        raise RuntimeError('Browser CLI differs from its checksum-pinned release')
    if report['binaries']['chromium']['reported_version'] != lock['packages'][toolbox.ARCH]['chromium'].split('-')[0]:
        raise RuntimeError('Chromium executable version differs from its pinned package')
    return report
