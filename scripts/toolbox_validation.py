#!/usr/bin/env python3
"""Run real core-tool integration tests in a network-isolated, bounded container."""
import json
import os
from pathlib import Path
import re
import tempfile
import toolbox


def validate_image(image, source_cli=False):
    toolbox.preflight(3 * toolbox.GB)
    toolbox.image_bytes(image)
    toolbox.STATE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='validation-', dir=toolbox.STATE) as work:
        work = Path(work)
        env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=toolbox.ARCH,
                   GOMAXPROCS='1', GOMEMLIMIT='512MiB', GOCACHE=str(work/'cache'), GOTOOLCHAIN=toolbox.GO_TOOLCHAIN)
        toolbox.monitored(['go','test','-p','1','-c','-o',str(work/'core.test'),'./internal/capability'],env=env,timeout_seconds=300)
        mounts = [(work/'core.test','/validation/core.test')]
        if source_cli:
            toolbox.monitored(['go','build','-p','1','-trimpath','-ldflags=-s -w','-o',str(work/'cybot'),'./cmd/cybot'],env=env,timeout_seconds=300)
            mounts.append((work/'cybot','/opt/cybot/bin/cybot'))
        output = toolbox.STATE / 'core-tests.txt'
        output.unlink(missing_ok=True)
        succeeded = False
        try:
            toolbox.run(['exec','env','CYBOT_LIVE_CORE=1','CYBOT_LIVE_ASSESSMENT=1','SYFT_CHECK_FOR_APP_UPDATE=false','/validation/core.test','-test.v','-test.run=^TestLive','-test.timeout=180s'],
                        image=image, network='none', mounts=mounts,
                        output=output,timeout_seconds=200)
            succeeded = True
        finally:
            if output.exists():
                text=output.read_text()
                print(text)
                report={'platform':'linux/'+toolbox.ARCH,'image_id':json.loads(toolbox.docker('image','inspect',image))[0]['Id'],
                        'network':'none','status':'passed' if succeeded else 'failed',
                        'cli':'source-overlay' if source_cli else 'installed-image',
                        'passed':re.findall(r'^--- PASS: (\S+)',text,re.M),
                        'failed':re.findall(r'^--- FAIL: (\S+)',text,re.M),
                        'scope':'Local fixtures with current-source adapters; fixture wordlists/templates/resolver. Subfinder startup only.'}
                (toolbox.STATE/'core-tests.json').write_text(json.dumps(report,indent=2)+'\n')
