"""Pinned offline vulnerability and infrastructure configuration scanning."""
import json
from pathlib import Path
import re
import shutil
import tarfile
import tempfile

import toolbox
import toolbox_probe


def prepare(dest):
    lock = json.loads((toolbox.ROOT/'docker/toolbox/supplychain.lock.json').read_text())
    for name, spec in lock['tools'].items():
        archive = dest/'tool-download'
        toolbox.download(spec['assets'][toolbox.ARCH], archive)
        toolbox.unpack_binary(archive, name, dest)
        archive.unlink()
    archive = dest/'db.tar.gz'
    toolbox.download(lock['data']['trivy-db'], archive)
    target = dest/'share/trivy/db'; target.mkdir(parents=True)
    total = 0
    with tarfile.open(archive) as source:
        found = set()
        for member in source:
            if not member.isfile() or member.name not in ('trivy.db', 'metadata.json'):
                continue
            total += member.size
            if total > 1536 * 1024**2:
                raise RuntimeError('Trivy database exceeds the supply-chain profile limit')
            with source.extractfile(member) as src, (target/member.name).open('wb') as out:
                shutil.copyfileobj(src, out)
            found.add(member.name)
    if found != {'trivy.db', 'metadata.json'}:
        raise RuntimeError('Incomplete vulnerability database archive')
    archive.unlink()
    shutil.copy(toolbox.ROOT/'docker/toolbox/supplychain.Dockerfile', dest/'Dockerfile')
    shutil.copy(toolbox.ROOT/'docker/toolbox/supplychain.lock.json', dest/'supplychain.lock.json')
    shutil.copy(toolbox.ROOT/'scripts/toolbox-supplychain-entrypoint.sh', dest/'entrypoint.sh')
    (dest/'entrypoint.sh').chmod(0o755)
    toolbox.prepare_cli(dest)


def probe(image):
    binaries = {'cybot': ('/opt/cybot/bin/cybot', '--version'),
                'trivy': ('/opt/cybot/bin/trivy', '--version'),
                'syft': ('/opt/cybot/bin/syft', 'version')}
    script = toolbox_probe.script(binaries, packages=False)
    script += "\nprintf 'CYBOT_DATABASE '\nsha256sum /opt/cybot/share/trivy/db/trivy.db\n"
    with tempfile.TemporaryDirectory(prefix='probe-', dir=toolbox.STATE) as temp:
        output = Path(temp)/'result.txt'
        toolbox.run(['exec', 'sh', '-c', script], image=image, network='none', output=output, timeout_seconds=120)
        text = output.read_text()
    report = toolbox_probe.parse(text, binaries, packages=False)
    source = json.loads((toolbox.ROOT/'docker/toolbox/supplychain.lock.json').read_text())
    toolbox_probe.validate_source(report, source)
    digest = re.search(r'CYBOT_DATABASE ([a-f0-9]{64})\s', text)
    if not digest:
        raise RuntimeError('Missing installed vulnerability database measurement')
    report['data'] = {'trivy-db': {'sha256': digest[1], 'source': source['data']['trivy-db']}}
    return report
