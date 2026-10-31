"""Prepare and measure the bounded HTTP discovery/fingerprinting profile."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile
import tempfile

from javascript_profile import unpack_wheel
from patched_go_tools import patch_source, prepare as prepare_go
import toolbox


def extract_source(archive, destination):
    total = 0
    count = 0
    seen = set()
    with tarfile.open(archive) as source:
        for member in source:
            count += 1
            raw_parts = Path(member.name).parts
            if count > 10000 or '..' in raw_parts or Path(member.name).is_absolute() or member.issym() or member.islnk():
                raise RuntimeError('Unsafe web-tool source archive')
            parts = raw_parts[1:]
            if not parts:
                if member.isdir(): continue
                raise RuntimeError('Missing source archive root directory')
            if member.isdir():
                continue
            if not member.isfile():
                raise RuntimeError('Unexpected source archive member')
            if parts in seen:
                raise RuntimeError('Duplicate source archive member')
            seen.add(parts)
            total += member.size
            if total > 64 * 1024**2:
                raise RuntimeError('Web-tool source exceeds its extraction limit')
            target = destination.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as incoming, target.open('wb') as output:
                shutil.copyfileobj(incoming, output)


def prepare(dest):
    lock = json.loads((toolbox.ROOT/'docker/toolbox/web.lock.json').read_text())
    (dest/'bin').mkdir(exist_ok=True)
    prepare_go(dest, set(lock['go_tools']))
    root = dest/'lib/whatweb'
    archive = dest/'whatweb.tar.gz'
    toolbox.download(lock['whatweb']['source'], archive)
    extract_source(archive, root)
    archive.unlink()
    patches = {'whatweb': patch_source(root, lock['whatweb']['patches'])}
    gems = dest/'gems'; gems.mkdir()
    for name, asset in lock['whatweb']['gems'].items():
        toolbox.download(asset, gems/(name+'-'+asset['version']+'.gem'))
    python = dest/'lib/python'; python.mkdir(parents=True)
    for name, asset in lock['wafw00f']['wheels'].items():
        archive = dest/'input.whl'
        toolbox.download(asset, archive)
        unpack_wheel(archive, python, dest/'share/licenses/python'/name)
        archive.unlink()
    patches['wafw00f'] = patch_source(python, lock['wafw00f']['patches'])
    from cors_profile import prepare as prepare_cors
    prepare_cors(dest)
    from dirsearch_profile import prepare as prepare_dirsearch
    prepare_dirsearch(dest)
    tls=dest/'lib/testssl';tls.mkdir()
    shutil.copyfile(toolbox.ROOT/'docker/toolbox/testssl_wrapper.py',tls/'adapter.py')
    shutil.copyfile(toolbox.ROOT/'docker/toolbox/testssl_metadata.py',tls/'metadata.py')
    shutil.copyfile(toolbox.ROOT/'docker/toolbox/testssl.lock.json',tls/'source.lock.json')
    binary=dest/'bin/testssl';binary.write_text('#!/bin/sh\nset -eu\nexec python3 -B /opt/cybot/lib/testssl/adapter.py "$@"\n');binary.chmod(0o755)
    shutil.copyfile(toolbox.ROOT/'scripts/library_metadata.py',dest/'lib/source_library_metadata.py')
    builds = dest/'share/builds'; builds.mkdir(parents=True, exist_ok=True)
    (builds/'web-source.json').write_text(json.dumps({'source_lock_sha256': hashlib.sha256((toolbox.ROOT/'docker/toolbox/web.lock.json').read_bytes()).hexdigest(), 'patches': patches}, indent=2)+'\n')
    for name, command in {
        'whatweb': 'exec ruby /opt/cybot/lib/whatweb/whatweb "$@"',
        'wafw00f': "exec python3 -B -c 'from wafw00f.main import main; main()' \"$@\"",
    }.items():
        path = dest/'bin'/name
        path.write_text('#!/bin/sh\nset -eu\n'+command+'\n')
        path.chmod(0o755)
    for name in ('common-wordlist', 'wordlist-license'):
        asset = json.loads((toolbox.ROOT/'docker/toolbox/core.lock.json').read_text())['data'][name]
        target = dest/('share/seclists/Discovery/Web-Content/common.txt' if name == 'common-wordlist' else 'share/seclists/LICENSE')
        target.parent.mkdir(parents=True, exist_ok=True)
        toolbox.download(asset, target)
    shutil.copyfile(toolbox.ROOT/'docker/toolbox/web.lock.json', dest/'web.lock.json')
    dockerfile = (toolbox.ROOT/'docker/toolbox/web.Dockerfile').read_text()
    pins = ' '.join(name+'='+version for name, version in lock['packages'][toolbox.ARCH].items())
    (dest/'Dockerfile').write_text(dockerfile.replace('@PACKAGE_PINS@', pins))
    shutil.copyfile(toolbox.ROOT/'scripts/toolbox-web-entrypoint.sh', dest/'entrypoint.sh')
    (dest/'entrypoint.sh').chmod(0o755)
    toolbox.prepare_cli(dest)


def probe(image):
    lock = json.loads((toolbox.ROOT/'docker/toolbox/web.lock.json').read_text())
    commands = {
        'cybot': ('/opt/cybot/bin/cybot', '--version'),
        'httpx': ('/opt/cybot/bin/httpx', '-version'),
        'ffuf': ('/opt/cybot/bin/ffuf', '-V'),
        'gobuster': ('/opt/cybot/bin/gobuster', '--version'),
        'whatweb': ('/opt/cybot/bin/whatweb', '--version'),
        'whatweb-engine': ('/opt/cybot/lib/whatweb/whatweb', ''),
        'wafw00f': ('/opt/cybot/bin/wafw00f', '--version'),
        'wafw00f-engine': ('/opt/cybot/lib/python/wafw00f/main.py', ''),
        'corscanner': ('/opt/cybot/bin/corscanner', '--version'),
        'corscanner-engine': ('/opt/cybot/lib/cors/CORScanner/common/corscheck.py', ''),
        'dirsearch': ('/opt/cybot/bin/dirsearch', '--version'),
        'dirsearch-engine': ('/opt/cybot/lib/dirsearch/dirsearch/lib/core/api.py', ''),
        'testssl': ('/opt/cybot/bin/testssl','--version'),
        'testssl-engine': ('/usr/bin/testssl','--version'),
        'openssl': ('/usr/bin/openssl','version'),
        'ruby': ('/usr/bin/ruby', '-e "puts RUBY_VERSION"'),
        'python': ('/usr/bin/python3', '-c "import platform; print(platform.python_version())"'),
    }
    lines = ['set -eu']
    for name, (path, flag) in commands.items():
        command = path+' '+flag
        if name.endswith('-engine') and name!='testssl-engine':
            command = commands[name.removesuffix('-engine')][0]+' --version'
        lines += [f"printf '\\nCYBOT_HASH {name} '", 'sha256sum '+path,
                  f"printf 'CYBOT_VERSION {name}\\n'", command+' 2>&1', "printf '\\nCYBOT_END\\n'"]
    gems = list(lock['whatweb']['gems'])
    gem_code = 'require "json"; puts '+json.dumps(gems)+'.to_h { |name| [name, Gem::Specification.find_by_name(name).version.to_s] }.to_json'
    # Inventory full interpreted source/dependencies, not only tiny launchers.
    libraries={name:{'root':'/opt/cybot/lib/'+folder,'version':version,
                    'lock':hashlib.sha256((toolbox.ROOT/('docker/toolbox/'+lock_name+'.lock.json')).read_bytes()).hexdigest(),
                    'adapter':hashlib.sha256((toolbox.ROOT/('docker/toolbox/'+adapter_name+'_wrapper.py')).read_bytes()).hexdigest()}
               for name,folder,lock_name,adapter_name,version in [('corscanner','cors','cors','corscanner','0.9.7'),('dirsearch','dirsearch','dirsearch','dirsearch','0.5.0')]}
    lines += ["printf 'CYBOT_WEB_DATA\\n'", "python3 -B - <<'PY'", 'import hashlib,json,pathlib,importlib.metadata,subprocess,sys',
              'data={}',
              "for name, directory in {'whatweb-source':'/opt/cybot/lib/whatweb','ruby-gems':'/opt/cybot/lib/gems','python-wheels':'/opt/cybot/lib/python','cors-source':'/opt/cybot/lib/cors','dirsearch-source':'/opt/cybot/lib/dirsearch'}.items():",
              ' digest=hashlib.sha256()', ' for path in sorted(pathlib.Path(directory).rglob("*")):',
              '  if path.is_symlink(): raise RuntimeError("Unexpected runtime dependency symlink")',
              '  if path.is_file(): digest.update(str(path.relative_to(directory)).encode()+b"\\0"+hashlib.sha256(path.read_bytes()).digest())',
              ' data[name]=digest.hexdigest()',
              "for name,path in {'web-source-lock':'/opt/cybot/manifest/web.lock.json','web-source-build':'/opt/cybot/share/builds/web-source.json','cors-source-build':'/opt/cybot/share/builds/cors-source.json'}.items(): data[name]=hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()",
              'packages=dict(line.split("=",1) for line in subprocess.check_output(["dpkg-query","-W","-f=${Package}=${Version}\\n",*'+repr(list(lock['packages'][toolbox.ARCH]))+'],text=True).splitlines())',
              'gems=json.loads(subprocess.check_output(["ruby","-e",'+repr(gem_code)+'],text=True))',
              'wheels={name:importlib.metadata.version(name) for name in '+repr(list(lock['wafw00f']['wheels'])+list(json.loads((toolbox.ROOT/'docker/toolbox/cors.lock.json').read_text())['wheels']))+'}',
              "sys.path.insert(0,'/opt/cybot/lib')",'from source_library_metadata import verify',
              'libraries='+repr(libraries),
              "sources={name:verify(pathlib.Path(row['root']),name,row['version'],row['lock'],row['adapter']) for name,row in libraries.items()}",
              "data['source-metadata-helper']=hashlib.sha256(pathlib.Path('/opt/cybot/lib/source_library_metadata.py').read_bytes()).hexdigest()",
              "sys.path.insert(0,'/opt/cybot/lib/testssl')",'from metadata import verify as verify_testssl',
              "data['testssl-files']=verify_testssl(json.loads(pathlib.Path('/opt/cybot/lib/testssl/source.lock.json').read_bytes()))",
              "for name in ['adapter.py','metadata.py','source.lock.json']:data['testssl-'+name]=hashlib.sha256((pathlib.Path('/opt/cybot/lib/testssl')/name).read_bytes()).hexdigest()",
              'print(json.dumps({"data":data,"packages":packages,"ruby_gems":gems,"python_packages":wheels,"source_libraries":sources}))', 'PY', "printf 'CYBOT_END\\n'"]
    toolbox.STATE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='probe-', dir=toolbox.STATE) as temp:
        output = Path(temp)/'probe.txt'
        try:
            toolbox.run(['exec', 'sh', '-c', '\n'.join(lines)], image=image, network='none', output=output, timeout_seconds=120)
        except RuntimeError:
            if output.exists(): (toolbox.STATE/'probe-error.txt').write_bytes(output.read_bytes()[-65536:])
            raise
        text = output.read_text()
    extra = re.search(r'CYBOT_WEB_DATA\n(.*?)\nCYBOT_END', text, re.S)
    if not extra:
        raise RuntimeError('Missing web runtime dependency inventory')
    report = dict(json.loads(extra[1]), binaries={})
    for target,source in [('adapter.py','testssl_wrapper.py'),('metadata.py','testssl_metadata.py'),('source.lock.json','testssl.lock.json')]:
        if report['data'].get('testssl-'+target)!=hashlib.sha256((toolbox.ROOT/'docker/toolbox'/source).read_bytes()).hexdigest():
            raise RuntimeError('TestSSL adapter/source manifest differs from the checked build')
    if report['source_libraries']!={name:row['version'] for name,row in libraries.items()} or report['data']['source-metadata-helper']!=hashlib.sha256((toolbox.ROOT/'scripts/library_metadata.py').read_bytes()).hexdigest():
        raise RuntimeError('Interpreted source metadata differs from its checked library/adapter')
    wheels = dict(lock['wafw00f']['wheels'], **json.loads((toolbox.ROOT/'docker/toolbox/cors.lock.json').read_text())['wheels'])
    for field, expected in [('packages', lock['packages'][toolbox.ARCH]), ('ruby_gems', {name:row['version'] for name,row in lock['whatweb']['gems'].items()}), ('python_packages', {name:row['version'] for name,row in wheels.items()})]:
        if report[field] != expected: raise RuntimeError('Web runtime dependency versions differ: '+field)
    for name in commands:
        digest = re.search(r'CYBOT_HASH '+name+r' ([a-f0-9]{64})\s+(\S+)', text)
        value = re.search(r'CYBOT_VERSION '+name+r'\n(.*?)\nCYBOT_END', text, re.S)
        version = re.search(r'(?<!\d)(\d+\.\d+\.\d+)(?!\d)', value[1]) if value else None
        if not digest or not version: raise RuntimeError('Incomplete web runtime measurement: '+name+'\n'+text[-4000:])
        expected = lock['go_tools'].get(name) or lock.get(name.removesuffix('-engine'), {}).get('version')
        if name in ('corscanner','corscanner-engine'): expected = '0.9.7'
        if name in ('dirsearch','dirsearch-engine'): expected = '0.5.0'
        if name in ('testssl','testssl-engine'): expected = '3.2.1'
        if name=='openssl':expected=lock['packages'][toolbox.ARCH]['openssl'].split('-')[0]
        if expected and version[1] != expected: raise RuntimeError('Web runtime version mismatch: '+name)
        report['binaries'][name] = {'path':digest[2], 'sha256':digest[1], 'reported_version':version[1]}
    return report
