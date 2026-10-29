#!/usr/bin/env python3
"""Run real core-tool integration tests in a network-isolated, bounded container."""
import json
import os
from pathlib import Path
import re
import tempfile
import toolbox
from public_source import source_digest


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
        analysis = toolbox.PROFILE == 'analysis'
        supplychain = toolbox.PROFILE == 'supplychain'
        prefix = toolbox.PROFILE
        output = toolbox.STATE / (prefix+'-tests.txt')
        output.unlink(missing_ok=True)
        reports = toolbox.STATE / 'validation'
        # Stale per-case reports must never survive a failed rerun.
        if reports.exists():
            import shutil
            shutil.rmtree(reports)
        reports.mkdir()
        container_reports = '/workspace/' + str(reports.relative_to(toolbox.ROOT))
        test_pattern = '^TestLiveAnalysis' if analysis else ('^TestLiveSupplyChain' if supplychain else '^TestLive(Core|Assessment|CompactCertification)')
        succeeded = False
        try:
            toolbox.run(['exec','env','CYBOT_LIVE_CORE=1','CYBOT_LIVE_ASSESSMENT=1',
                         'CYBOT_LIVE_ANALYSIS='+('1' if analysis else '0'),
                         'CYBOT_LIVE_SUPPLYCHAIN='+('1' if supplychain else '0'),
                         'CYBOT_VALIDATION_REPORTS='+container_reports,
                         'CYBOT_VALIDATION_SOURCE='+source_digest(),
                         'SYFT_CHECK_FOR_APP_UPDATE=false','/validation/core.test','-test.v','-test.run='+test_pattern,'-test.timeout=480s'],
                        image=image, network='none', mounts=mounts,
                        extra_hosts=[('registry.cybot.invalid', '127.0.0.1')] if supplychain else (),
                        output=output,timeout_seconds=500)
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
                (toolbox.STATE/(prefix+'-tests.json')).write_text(json.dumps(report,indent=2)+'\n')
                # A failed capability must not erase independent operations
                # whose positive/negative/failure assertions all passed. The
                # candidate image still cannot be promoted on a suite failure.
                if any(reports.glob('*.json')):
                    from operation_evidence import collect
                    collect(reports, toolbox.probe(image), source_digest(), toolbox.ARCH)
