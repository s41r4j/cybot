"""Check upstream identities hidden by local Go '(devel)' replacements."""
from datetime import datetime, timezone
import hashlib
import json
import urllib.request


def query(module, version):
    request = urllib.request.Request('https://api.osv.dev/v1/query',
        data=json.dumps({'package': {'name': module, 'ecosystem': 'Go'}, 'version': version}).encode(),
        headers={'Content-Type': 'application/json', 'User-Agent': 'CYBOT-release-audit'})
    with urllib.request.urlopen(request, timeout=45) as response:
        data = response.read(4 * 1024**2 + 1)
    if len(data) > 4 * 1024**2:
        raise RuntimeError('Oversized upstream module advisory response')
    result = json.loads(data)
    if not isinstance(result, dict) or not isinstance(result.get('vulns', []), list):
        raise RuntimeError('Invalid upstream module advisory response')
    return result


def assess(spec, advisories, source_build=False):
    module, version = spec['module'].rsplit('@', 1)
    findings = []
    for advisory in advisories.get('vulns', []):
        if not isinstance(advisory.get('id'), str):
            raise RuntimeError('Upstream advisory identifier is missing')
        row = {'id': advisory['id'], 'summary': advisory.get('summary', ''),
               'status': 'review-required', 'record': advisory}
        # The Go database uses an open-ended range for this incident. The
        # primary advisory explicitly excludes binaries built from source.
        # Restrict the review to this exact verified source input; never waive
        # arbitrary versions, downloaded binaries or other advisories.
        if source_build and module == 'github.com/aquasecurity/trivy' and version == 'v0.72.0' \
                and spec.get('sum') == 'h1:W3v+NE94olOzk3nSwwha59DTBsbcgLRXa4QNSJpRQQM=' \
                and advisory['id'] == 'GO-2026-4919':
            row.update(status='not-affected',
                reason='Verified source build of the exact v0.72.0 module. The primary incident advisory excludes source-built binaries; compromised release artifacts were a separate delivery path.',
                reference='https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23')
        findings.append(row)
    return {'module': module, 'upstream_version': version, 'upstream_sum': spec['sum'],
            'status': 'blocked' if any(row['status'] == 'review-required' for row in findings) else 'passed',
            'scope': 'conservative upstream module-version check; supplements compiled symbol analysis',
            'checked_at': datetime.now(timezone.utc).isoformat(), 'findings': findings,
            'response_sha256': hashlib.sha256(json.dumps(advisories, sort_keys=True).encode()).hexdigest()}


def audit_build(spec, provenance, binary_sha256, modules, expected_locks, replacement):
    if provenance.get('kind') != 'cybot-patched-upstream' or provenance.get('binary_sha256') != binary_sha256 \
            or provenance.get('upstream_module') != spec['module'] or provenance.get('upstream_sum') != spec['sum'] \
            or provenance.get('dependency_locks') != expected_locks:
        raise RuntimeError('Source-build provenance differs from the measured executable or committed dependency locks')
    module, version = spec['module'].rsplit('@', 1)
    if {'path': module, 'version': '(devel)'} not in modules:
        raise RuntimeError('Source-built main module differs from the compiled inventory')
    reports = [assess(spec, query(module, version), source_build=True)]
    if {'path': './.cybot-patches/go-github', 'version': '(devel)'} in modules:
        if provenance.get('patch_module') != replacement['module'] or provenance.get('patch_module_sum') != replacement['sum']:
            raise RuntimeError('Locally replaced dependency source identity differs')
        module, version = replacement['module'].rsplit('@', 1)
        reports.append(assess(replacement, query(module, version), source_build=True))
    return reports
