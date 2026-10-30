"""Build checked scanners and audit one immutable image inside bounded offline containers."""
import hashlib
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import artifact_audit
import module_audit
from package_audit_controls import image_fixture
from package_audit_report import database_fresh, findings, inventory, read_json, summarize
from patched_go_tools import prepare as prepare_go
import toolbox
import toolbox_probe
from public_source import source_digest


def file_hash(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1024*1024): value.update(chunk)
    return value.hexdigest()


def prepare_scanners(root, govulncheck, lock):
    root.mkdir(); (root/'bin').mkdir()
    prepare_go(root,set(lock['go_tools']))
    source = toolbox.ROOT/'docker/toolbox/patched-go'
    manifest = json.loads((source/'manifest.json').read_text())
    audits = {}
    for name, version in lock['go_tools'].items():
        spec = manifest['tools'][name]
        if spec['module'].rsplit('@',1)[1].removeprefix('v') != version:
            raise RuntimeError('Package scanner version differs from its verified source recipe')
        path = root/'bin'/name
        result = artifact_audit.audit(path,govulncheck)
        provenance = root/'share/builds'/(name+'.json')
        dependency_locks = {file:file_hash(source/name/file) for file in ('go.mod','go.sum')}
        result['source_modules'] = module_audit.audit_build(spec,json.loads(provenance.read_text()),
            result['binary_sha256'],result['modules'],dependency_locks,manifest['go-github'])
        result['source_provenance_sha256'] = file_hash(provenance)
        if result['status']!='passed' or any(row['status']!='passed' for row in result['source_modules']):
            raise RuntimeError('The package vulnerability scanner itself has blocking advisories: '+name)
        audits[name]=result
    return audits


def audit(image, measured, work, govulncheck, output):
    lock = json.loads((toolbox.ROOT/'docker/toolbox/package-audit.lock.json').read_text())
    database_fresh(lock['database'],lock['max_database_age_hours'])
    toolbox.preflight(8*toolbox.GB)
    tools = work/'package-scanners'
    scanners = prepare_scanners(tools,govulncheck,lock)
    data = work/'package-data'; data.mkdir(); (data/'tmp').mkdir()
    controls = work/'package-controls'; controls.mkdir()
    identities = {name:image_fixture(controls/(name+'.tar'),toolbox.ARCH,name=='positive') for name in ('positive','negative')}
    (controls/'invalid.tar').write_bytes(b'Not a Docker image archive.\n')
    config = work/'package-config.yaml';config.write_text('{}\n')
    archive = work/'image.tar'
    toolbox.monitored(['docker','image','save','--output',str(archive),image],reserve=4*toolbox.GB,timeout_seconds=300)
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size>4*toolbox.GB:
        raise RuntimeError('Image export exceeds the bounded archive size')
    archive_hash = file_hash(archive)
    db = work/'database.tar.zst'
    toolbox.download(lock['database'],db)
    mounts = [(tools/'bin/syft','/validation/tools/syft'),(tools/'bin/grype','/validation/tools/grype'),
              (archive,'/validation/image.tar'),(db,'/validation/database.tar.zst'),
              (config,'/validation/package-config.yaml'),(controls,'/validation/package-controls')]
    env = ['GOMAXPROCS=1','GOMEMLIMIT=512MiB','SYFT_CHECK_FOR_APP_UPDATE=false','SYFT_JAVA_USE_NETWORK=false',
        'SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false','SYFT_PYTHON_SEARCH_REMOTE_LICENSES=false',
        'SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES=false','GRYPE_CHECK_FOR_APP_UPDATE=false','GRYPE_DB_AUTO_UPDATE=false',
        'GRYPE_DB_REQUIRE_UPDATE_CHECK=false','GRYPE_DB_VALIDATE_AGE=true',
        'GRYPE_DB_MAX_ALLOWED_BUILT_AGE='+str(lock['max_database_age_hours'])+'h',
        'GRYPE_DB_CACHE_DIR=/validation/package-data/db','TMPDIR=/validation/package-data/tmp','SQLITE_TMPDIR=/validation/package-data/tmp']
    def run(args, log, timeout=300, file_limit=None):
        options = {} if file_limit is None else {'file_size_limit':file_limit}
        toolbox.run(['exec','env',*env,*args],image=image,network='none',mounts=mounts,
            writable_mounts=[(data,'/validation/package-data')],output=output/log,timeout_seconds=timeout,**options)
    probe = output/'package-scanner-versions.txt'
    run(['sh','-c',toolbox_probe.script({'syft':('/validation/tools/syft','version'),'grype':('/validation/tools/grype','version')},packages=False)],probe.name,120)
    observed = toolbox_probe.parse(probe.read_text(),{'syft':('/validation/tools/syft','version'),'grype':('/validation/tools/grype','version')},packages=False)
    for name, version in lock['go_tools'].items():
        row=observed['binaries'][name]
        if row['reported_version']!=version or row['sha256']!=scanners[name]['binary_sha256']:
            raise RuntimeError('Mounted package scanner differs from its audited executable')
        scanners[name]['reported_version']=version
    run(['/validation/tools/grype','--config','/validation/package-config.yaml','db','import','/validation/database.tar.zst'],
        'package-db-import.txt',1200,6*1024**3)
    hydrated = data/'db/6/vulnerability.db'
    if not hydrated.is_file() or hydrated.is_symlink() or hydrated.stat().st_size>6*1024**3:
        raise RuntimeError('Imported package database is missing or oversized')
    database_hash = file_hash(hydrated)
    def scan(subject, name, image_id):
        sbom_path = '/validation/package-data/'+name+'-sbom.json'
        result_path = '/validation/package-data/'+name+'-matches.json'
        run(['/validation/tools/syft','--config','/validation/package-config.yaml','docker-archive:'+subject,'--scope','squashed','-o','syft-json='+sbom_path],name+'-catalog.txt')
        run(['/validation/tools/grype','--config','/validation/package-config.yaml','sbom:'+sbom_path,'-o','json','--file',result_path],name+'-scan.txt')
        sbom, matches = read_json(data/(name+'-sbom.json')),read_json(data/(name+'-matches.json'))
        packages,_,_,_ = inventory(sbom,image_id,toolbox.ARCH)
        rows = findings(matches,image_id,{row['id'] for row in packages},lock['go_tools']['grype'])
        status = matches.get('descriptor',{}).get('db',{}).get('status',{})
        if status.get('valid') is not True or status.get('built')!=lock['database']['created'] or status.get('schemaVersion')!=lock['database']['schema_version']:
            raise RuntimeError('Package scanner used an invalid or different database')
        return sbom,matches,rows
    _,_,positive = scan('/validation/package-controls/positive.tar','positive',identities['positive'])
    if not {'libssl3','lodash'}.issubset({row['package'] for row in positive}):
        raise RuntimeError('Package audit failed to detect known vulnerable OS and language controls')
    _,_,negative = scan('/validation/package-controls/negative.tar','negative',identities['negative'])
    if negative: raise RuntimeError('Clean synthetic package fixture produced invented vulnerability matches')
    try:
        run(['/validation/tools/syft','--config','/validation/package-config.yaml','docker-archive:/validation/package-controls/invalid.tar','-o','syft-json'], 'package-failure-control.txt',60)
    except RuntimeError:
        diagnostic = (output/'package-failure-control.txt').read_text().lower()
        if 'archive' not in diagnostic or not any(word in diagnostic for word in ('error','failed','unable','could not')):
            raise RuntimeError('Package failure control did not establish a scanner input error')
    else:
        raise RuntimeError('Package cataloger accepted a malformed Docker archive')
    sbom, matches, _ = scan('/validation/image.tar','image',image)
    result = summarize(sbom,matches,image,toolbox.ARCH,toolbox.PROFILE,measured,lock)
    for path, expected in [(archive,archive_hash),(hydrated,database_hash),*[(tools/'bin'/name,row['binary_sha256']) for name,row in scanners.items()]]:
        if file_hash(path)!=expected: raise RuntimeError('A package audit input changed during analysis')
    result.update(scanners=scanners,image_archive_sha256=archive_hash,database_file_sha256=database_hash,
        sbom_sha256=file_hash(data/'image-sbom.json'),scanner_report_sha256=file_hash(data/'image-matches.json'),
        controls={'positive':'passed','negative':'passed','failure':'passed'},network='none',
        source_sha256=source_digest(),checked_at=datetime.now(timezone.utc).isoformat())
    shutil.copyfile(data/'image-sbom.json',output/'package-sbom.json')
    shutil.copyfile(data/'image-matches.json',output/'package-matches.json')
    (output/'package-audit.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
