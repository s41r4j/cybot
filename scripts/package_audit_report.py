"""Validate and summarize complete installed-package scans; unknown coverage stays explicit."""
from collections import Counter
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import PurePosixPath
import re

OS_TYPES = {'deb', 'apk', 'rpm'}


def database_fresh(asset, max_hours=72):
    stamp = datetime.fromisoformat(asset['created'].replace('Z', '+00:00'))
    now = datetime.now(timezone.utc)
    if stamp.tzinfo is None or stamp > now+timedelta(minutes=5) or stamp < now-timedelta(hours=max_hours):
        raise RuntimeError('Package vulnerability database is stale or has an invalid date')


def read_json(path, maximum=64*1024**2):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise RuntimeError('Package scanner did not produce a bounded regular JSON report')
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeError) as error:
        raise RuntimeError('Malformed package scanner report') from error
    if not isinstance(value, dict): raise RuntimeError('Expected an object package scanner report')
    return value


def inventory(sbom, image_id, arch):
    source = sbom.get('source', {})
    metadata = source.get('metadata', {})
    if source.get('type') != 'image' or metadata.get('imageID') != image_id:
        raise RuntimeError('SBOM is not bound to the exact Linux image under audit')
    try:
        if not isinstance(metadata.get('config'),str) or len(metadata['config'])>2*1024**2: raise ValueError('missing image config')
        raw = base64.b64decode(metadata['config'],validate=True)
        config = json.loads(raw)
        if 'sha256:'+hashlib.sha256(raw).hexdigest()!=image_id or config.get('architecture')!=arch or config.get('os')!='linux':
            raise ValueError('image config identity/platform mismatch')
        if metadata.get('architecture') not in ('',None,arch) or metadata.get('os') not in ('',None,'linux'): raise ValueError('contradictory image platform')
    except (ValueError,TypeError) as error:
        raise RuntimeError('SBOM image config does not establish the expected immutable platform') from error
    distro = sbom.get('distro', {})
    if distro.get('id') not in ('debian', 'alpine') or not distro.get('versionID'):
        raise RuntimeError('Image operating-system identity is missing or unsupported')
    artifacts = sbom.get('artifacts')
    if not isinstance(artifacts, list) or not artifacts: raise RuntimeError('Package inventory is empty')
    packages, seen, go_files, cgo_files = [], set(), set(), set()
    for row in artifacts:
        if not isinstance(row, dict) or not all(isinstance(row.get(key), str) and row[key] for key in ('id','name','type')) or not isinstance(row.get('version'), str):
            raise RuntimeError('Package inventory contains an incomplete package identity')
        if row['id'] in seen: raise RuntimeError('Package inventory contains duplicate identities')
        seen.add(row['id'])
        packages.append({key:row.get(key, '') for key in ('id','name','version','type','purl')})
        native = row.get('metadata') or {}
        if isinstance(native,dict) and native.get('goCompiledVersion'):
            settings = native.get('goBuildSettings') or {}
            if isinstance(settings,list): settings={entry.get('key'):entry.get('value') for entry in settings if isinstance(entry,dict)}
            for location in row.get('locations', []):
                path = location.get('path', '')
                if not isinstance(path, str) or not path.startswith('/') or '..' in PurePosixPath(path).parts or '\x00' in path:
                    raise RuntimeError('Go binary inventory contains an unsafe path')
                go_files.add(path)
                if settings.get('CGO_ENABLED')=='1': cgo_files.add(path)
    if not any(row['type'] in OS_TYPES for row in packages):
        raise RuntimeError('No installed operating-system packages were cataloged')
    return packages, distro, sorted(go_files), sorted(cgo_files)


def findings(scan, image_id, package_ids, version):
    if scan.get('source', {}).get('type') != 'image' or scan.get('source', {}).get('target', {}).get('imageID') != image_id:
        raise RuntimeError('Vulnerability scan describes a different image')
    descriptor = scan.get('descriptor', {})
    if descriptor.get('name') != 'grype' or descriptor.get('version') != version:
        raise RuntimeError('Unexpected package vulnerability scanner identity')
    config = descriptor.get('configuration', {})
    if config.get('only-fixed') or config.get('only-notfixed') or config.get('ignore-wontfix'):
        raise RuntimeError('Package findings were filtered before review')
    matches, ignored = scan.get('matches'), scan.get('ignoredMatches', [])
    if not isinstance(matches, list) or not isinstance(ignored, list):
        raise RuntimeError('Vulnerability scan lacks explicit complete match arrays')
    results = []
    for suppressed, rows in ((False,matches),(True,ignored)):
        for row in rows:
            if not isinstance(row,dict): raise RuntimeError('Malformed vulnerability match')
            artifact, vulnerability = row.get('artifact', {}), row.get('vulnerability', {})
            if not isinstance(artifact,dict) or not isinstance(vulnerability,dict) or artifact.get('id') not in package_ids or not isinstance(vulnerability.get('id'), str) or not vulnerability.get('id') or not vulnerability.get('severity'):
                raise RuntimeError('Vulnerability finding lacks a cataloged package or advisory identity')
            detail = {key:vulnerability.get(key) for key in ('id','severity','dataSource','namespace','urls','fix')}
            results.append({'package_id':artifact['id'], 'package':artifact.get('name',''),
                'version':artifact.get('version',''), 'type':artifact.get('type',''),
                'advisory':detail, 'match_details':row.get('matchDetails', []),
                'ignored':suppressed})
    # Ignored/suppressed findings also require review; an empty visible table
    # cannot silently turn a configured ignore into security clearance.
    return results


def mapped_components(profile, measured, packages, required):
    rows = []
    source_packages = measured.get('packages', {})
    expectations = {
        'core': {'nmap': [('deb','nmap',source_packages.get('nmap'))]},
        'supplychain': {},
        'analysis': {'semgrep': [('python','semgrep','1.172.0')]},
        'web': {'wafw00f':[('python','wafw00f','2.4.2')], 'wafw00f-engine':[('python','wafw00f','2.4.2')],
                'ruby':[('deb','ruby3.3',source_packages.get('ruby3.3'))], 'python':[('deb','python3.13',source_packages.get('python3.13'))]},
        'browser': {'chromium':[('deb','chromium',source_packages.get('chromium'))],
                    'chromium-launcher':[('deb','chromium',source_packages.get('chromium'))],
                    'python':[('deb','python3.13',source_packages.get('python3.13'))]},
    }[profile]
    normalize = lambda name: name.lower().replace('_','-')
    for name in required:
        constraints = expectations.get(name, [])
        identities = []
        for kind, package, version in constraints:
            identities += [row['id'] for row in packages if row['type']==kind and normalize(row['name'])==normalize(package) and row['version']==version and version]
        mapped = bool(constraints) and len(identities)>=len(constraints)
        rows.append({'component':name,'binary_sha256':measured['binaries'][name]['sha256'],
                     'status':'mapped' if mapped else 'unmapped', 'package_ids':sorted(identities),
                     'scope':'Installed distribution-package advisory coverage' if mapped else 'Standalone/native dependency coverage still requires review'})
    for field, kind in [('python_packages','python'),('ruby_gems','gem')]:
        for name, version in measured.get(field, {}).items():
            identities = [row['id'] for row in packages if row['type']==kind and normalize(row['name'])==normalize(name) and row['version']==version]
            rows.append({'component':kind+':'+name,'status':'mapped' if identities else 'unmapped','package_ids':identities,
                         'scope':'Measured interpreted dependency package'})
    return rows


def summarize(sbom, scan, image_id, arch, profile, measured, lock):
    packages, distro, go_files, cgo_files = inventory(sbom,image_id,arch)
    matches = findings(scan,image_id,{row['id'] for row in packages},lock['go_tools']['grype'])
    components = mapped_components(profile,measured,packages,lock['native_components'][profile])
    measured_go = {row['path'] for name,row in measured['binaries'].items() if name not in lock['native_components'][profile]}
    unmeasured_go = sorted(set(go_files)-measured_go)
    unmapped = sorted(row['component'] for row in components if row['status']!='mapped')
    unknown = [row['id'] for row in packages if not row['version'] or row['version'].lower() in ('unknown','unresolved')]
    ready = not matches and not unmapped and not unmeasured_go and not unknown and not cgo_files
    return {'schema_version':1,'status':'passed' if ready else 'blocked','image_id':image_id,'profile':profile,'platform':'linux/'+arch,
        'scope':'Installed OS and language-package advisories; standalone/native coverage gaps remain explicit',
        'distro':distro,'package_counts':dict(Counter(row['type'] for row in packages)),
        'inventory':packages,'findings':matches,'components':components,
        'unmapped_components':unmapped,'unmeasured_go_binaries':unmeasured_go,'unknown_version_packages':unknown,
        'unscanned_cgo_binaries':cgo_files,
        'os_status':'blocked' if any(row['type'] in OS_TYPES for row in matches) else 'passed',
        'database':lock['database']}


def validate_clear_report(report, policy, image_id, profile):
    """Release checks cannot accept a Boolean without package/coverage proof."""
    if report.get('schema_version')!=1 or report.get('status')!='passed' or report.get('image_id')!=image_id or report.get('network')!='none':
        raise ValueError('package advisory audit is incomplete or not bound to the offline-tested image')
    if report.get('database')!=policy['database']:
        raise ValueError('package vulnerability database differs from the required source lock')
    try: database_fresh(report['database'],policy['max_database_age_hours'])
    except RuntimeError as error: raise ValueError(str(error)) from error
    for key in ('image_archive_sha256','database_file_sha256','sbom_sha256','scanner_report_sha256'):
        if not re.fullmatch('[a-f0-9]{64}',report.get(key,'')): raise ValueError('package audit input/report checksum is missing')
    if report.get('controls')!={'positive':'passed','negative':'passed','failure':'passed'}:
        raise ValueError('package audit lacks real positive, negative and failure controls')
    for key in ('findings','unmapped_components','unmeasured_go_binaries','unknown_version_packages','unscanned_cgo_binaries'):
        if not isinstance(report.get(key),list) or report[key]: raise ValueError('package audit contains findings or incomplete dependency coverage')
    rows = report.get('inventory')
    if not isinstance(rows,list) or not rows or not any(row.get('type') in OS_TYPES for row in rows):
        raise ValueError('installed OS package inventory is missing')
    identities={row.get('id') for row in rows}
    if None in identities or len(identities)!=len(rows): raise ValueError('package identities are missing or duplicated')
    components=report.get('components')
    if not isinstance(components,list) or len({row.get('component') for row in components})!=len(components):
        raise ValueError('native component coverage is missing or duplicated')
    if not set(policy['native_components'][profile]).issubset({row.get('component') for row in components}):
        raise ValueError('required native component is missing from package coverage')
    for component in components:
        if component.get('status')!='mapped' or not component.get('package_ids') or not set(component['package_ids']).issubset(identities):
            raise ValueError('native component is not tied to the package inventory')
    for name,version in policy['go_tools'].items():
        scanner=report.get('scanners',{}).get(name,{})
        if scanner.get('status')!='passed' or scanner.get('reported_version')!=version or not re.fullmatch('[a-f0-9]{64}',scanner.get('binary_sha256','')) or not re.fullmatch('[a-f0-9]{64}',scanner.get('source_provenance_sha256','')):
            raise ValueError('package scanner lacks a checked source/binary identity')
        reviews=scanner.get('source_modules',[])
        if not reviews or any(row.get('status')!='passed' for row in reviews):
            raise ValueError('package scanner source advisory review is missing or blocked')
