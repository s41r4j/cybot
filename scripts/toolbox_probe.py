"""Read-only measurements from a core image; all commands are fixed locally."""
import json
import re

BINARIES = {
    'cybot': ('/opt/cybot/bin/cybot', '--version'),
    'httpx': ('/opt/cybot/bin/httpx', '-version'),
    'katana': ('/opt/cybot/bin/katana', '-version'),
    'nuclei': ('/opt/cybot/bin/nuclei', '-version'),
    'dnsx': ('/opt/cybot/bin/dnsx', '-version'),
    'subfinder': ('/opt/cybot/bin/subfinder', '-version'),
    'ffuf': ('/opt/cybot/bin/ffuf', '-V'),
    'nmap': ('/usr/bin/nmap', '--version'),
    'gitleaks': ('/opt/cybot/bin/gitleaks', 'version'),
    'syft': ('/opt/cybot/bin/syft', 'version'),
    'naabu': ('/opt/cybot/bin/naabu', '-version'),
}

def script(binaries=None, packages=True):
    binaries = BINARIES if binaries is None else binaries
    lines = ['set -eu']
    for name, (path, flag) in binaries.items():
        lines += [f"printf '\\nCYBOT_HASH {name} '", f'sha256sum {path}',
                  f"printf 'CYBOT_VERSION {name}\\n'", f'{path} {flag} 2>&1', "printf '\\nCYBOT_END\\n'"]
    if packages:
        lines += ["printf 'CYBOT_PACKAGES\\n'", "dpkg-query -W -f='${Package}=${Version}\\n' nmap nmap-common ca-certificates jq libpcap0.8t64", "printf 'CYBOT_END\\n'"]
    return '\n'.join(lines)

def parse(text, binaries=None, packages=True):
    binaries = BINARIES if binaries is None else binaries
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    report = {'binaries': {}, 'packages': {}}
    for name, (path, _) in binaries.items():
        digest = re.search(r'CYBOT_HASH ' + name + r' ([a-f0-9]{64})\s', text)
        output = re.search(r'CYBOT_VERSION ' + name + r'\n(.*?)\nCYBOT_END', text, re.S)
        if not digest or not output:
            raise RuntimeError('Incomplete runtime probe: ' + name)
        version = re.search(r'(?i)(?:version[: ]+|\bv)(?:v)?(\d+\.\d+(?:\.\d+)?|dev)\b', output[1])
        if not version:
            version = re.search(r'^\s*(\d+\.\d+\.\d+)\s*$', output[1])
        if not version:
            raise RuntimeError('Unrecognized version output for ' + name + ': ' + output[1])
        report['binaries'][name] = {'path': path, 'sha256': digest[1], 'reported_version': version[1]}
    if packages:
        inventory = re.search(r'CYBOT_PACKAGES\n(.*?)\nCYBOT_END', text, re.S)
        if not inventory:
            raise RuntimeError('Missing package inventory')
        report['packages'] = dict(line.split('=', 1) for line in inventory[1].splitlines())
    return report

def validate_source(report, source):
    for name, entry in source['tools'].items():
        if report['binaries'][name]['reported_version'] != entry['reported_version']:
            raise RuntimeError('Runtime version differs from source lock: ' + name)
        # Upstream release identity and the embedded version string are
        # separate measurements (dnsx v1.3.0 embeds 1.2.3).
        report['binaries'][name]['release_version'] = entry['version'].removeprefix('v')
    if report['packages'] != source['packages']:
        raise RuntimeError('Installed package versions differ from source lock')

def validate_runtime(report, expected):
    if report != expected:
        raise RuntimeError('Installed binary hashes or package versions differ from the validated runtime lock')
