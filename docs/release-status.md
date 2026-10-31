# Release status — 2026-10-31

CYBOT is public source in active development. A stable release covering the
entire catalog is **not yet certified**. The release requirement includes every
one of the 84 tools and 71 capabilities; no entries are removed from the gate to
increase a percentage.

## The six repair areas

| Area | Source changes | Remaining release evidence |
| --- | --- | --- |
| 1. Scope binding | Filesystem mapping follows capability kind; URLs, hostnames, IPs and typed host/interface targets cannot become file mounts. This also fixes Windows URL execution. Browser actions require explicit approval even under advisory policy; sessions are anonymous, isolated and restricted to the requested hostname. Explicit local://HOSTNAME and interface://INTERFACE targets require approval. Unimplemented operations fail explicitly. Windows and other source checks pass at the Debian 13 candidate. | Compatible runtime/lab evidence for every specialist adapter; service-start/status commands are not accepted as complete operations. |
| 2. Scanner errors | Failed scanners retain parser-validated matches and redacted evidence, explicitly marked incomplete. Truncated JSONL recovery stops at the first invalid record; failed or skipped stages cannot feed downstream input. A real Nuclei cancellation control preserves its earlier match. Failures never promote unknown confidence to 100%. Zero-file Semgrep/Gosec and targetless Trivy reports are partial. Recovery fixtures pass on both Linux architectures at the last green checkpoint. | Full positive/negative/failure fixtures for remaining scanners and fresh evidence after runtime changes. |
| 3. Heuristic findings | URL classification returns investigation candidates and never creates vulnerability findings. Finding review requires explicit operator assertions and hash-verified stored evidence; prose alone stays UNVERIFIED. | Independent review remains necessary; operator assertions do not prove exploitability. |
| 4. Toolchain | Go 1.26.10 pinned; source and measured executable/source-identity audits pass on both Linux architectures, including all operational SDK executables. Full package scans now complete and retain their findings. Git LFS is now rebuilt from checked 3.8.1 source with fixed networking dependencies; native operation and Linux ARM64 binary/provenance checks pass. | Fresh image evidence for the Git LFS repair and Debian 13 migration, OS/library findings, source-version reconciliation, native-component coverage and release provenance still block certification. |
| 5. Distribution | Public repository and website, release gate, immutable image pull/validation, local pins, and verified core image backup/restore on both Linux architectures. | Successful publishing pipeline, clean-machine installation and compatible image evidence. No completed stable release is claimed. |
| 6. Publication hygiene | MIT license, security policy, third-party notices, strict example, and allowlisted clean source export. Private research remains locally preserved and is excluded from public source/history. | Ongoing secret scanning and third-party asset/license review for each release. |

## What passes locally

Fresh Go tests and vet pass with Go 1.26.10. Source govulncheck reports no known
reachable vulnerabilities after toolchain/dependency updates. Python tests
cover budget/locking/promotion, source export, and fail-closed release gating.
Regression cases cover the previously reproduced scope and result failures.
These are source and contract checks, not 84-tool live certification.

The local Docker daemon is unavailable. Historical 2026-10-22 compact-core
results are retained as historical records and do not certify the changed source.
The complete [CI run at revision `2fdc975`](https://github.com/s41r4j/cybot/actions/runs/41170012156)
passed source checks on Linux AMD64/ARM64, macOS and Windows, and real-operation
fixtures in all five native Linux toolbox profiles on both architectures.
Both compact-core jobs also passed the actual checksummed image backup/restore
round trip. Installed-CLI, JavaScript extraction and finding-review controls
passed on both Linux architectures.
Its source-bound reports certify **24 tools and 27 capabilities** functionally;
they do not certify the entire 84-tool/71-capability catalog or the security of
every bundled executable. Later source changes require fresh certificates.
Windows/AD and account-level cloud tests are explicitly deferred because no
compatible labs were supplied. Their catalog entries remain visible and required
by the full-release gate. External providers and specialist runtimes still need
authorized operation tests.

## Complete inventory and gate

- `cybot capability coverage` enumerates every tool/capability and implementation gap without running tools.
- `release/catalog-coverage.json` is the complete exported inventory.
- `release/catalog-baseline.json` prevents silently dropping catalog entries from release validation.
- `release/readiness.json` records the current full-product gate result.
- `docs/tool-support.md` lists every tool and capability for review.

Run `python3 scripts/release_gate.py --output release/readiness.json`. Exit 1
means release evidence is incomplete. The gate requires source-matching evidence,
executable hashes, supported platform/version, checksummed reports and real
positive/negative/failure cases. Binary presence and help/version output cannot
satisfy the gate. Tool evidence is required for each declared release platform.

## Specialist work still required

The inventory exposes unfinished adapters and tools without executable capability
mappings. Some high-level catalog operations currently perform only enumeration,
status or startup. These require actual operation contracts and validation, not
renaming those outcomes to successful execution. They remain within the full
release requirement and prevent a stable release while unfinished.

No cloud resources, real credentials, public targets, messages or campaigns are
created by the offline validation workflow.

## Expanded operation evidence

The web profile uses CORScanner 0.9.7's pinned library engine
for one target at a time. Strict JSON retains CORS header candidates without
creating vulnerability findings. Verified TLS, no redirects, offline suffix data,
anonymous sessions and explicit transport/HTTP errors replace keyword parsing.
Native loopback positive/negative/failure, trusted/untrusted TLS and redirect
controls pass on both Linux architectures at revision `2fdc975`.

Dirsearch 0.5.0 is now mapped to `dir.bruteforce` alongside Gobuster and FFUF.
The upstream sequential API emits structured progress through the CYBOT wrapper;
no completion marker means incomplete coverage. Earlier HTTP matches survive
request errors and malformed-output failures. The adapter enforces the target
origin/base path, verified TLS, no redirects, a 1 MiB response bound and a bounded
wordlist. CLI recursion/authentication/native backends are not exposed. Native
positive/negative/failure and boundary controls pass for all three engines on
both Linux architectures at revision `2fdc975`. The 84/71 baseline is unchanged.

The image audit builds source-checked Syft/Grype scanners and inspects the
immutable operation-tested image inside network-isolated containers. Database
age/hash, affected OpenSSL/Lodash controls, an empty-match fixture and an invalid
archive are checked. The stderr, image-layer file-limit and CI-capacity repairs
now pass on both Linux architectures; source checks also pass on Windows/macOS.

All ten full image audits complete at this checkpoint, and all remain blocked.
The compiled Go checks pass (including every operational SDK executable), while
package and native-coverage findings prevent a security certificate:

| Profile | Matches per architecture | Additional coverage gaps |
| --- | ---: | --- |
| Core | 269 | Source-built module versions need source-identity reconciliation. |
| Analysis | 394 | Bundled Git LFS was not measured; Cgo and standalone-engine coverage, plus source-built version reconciliation. |
| Supply chain | 237 | Source-built module versions need source-identity reconciliation. |
| Web | 417 | Source-library/WhatWeb identities and source-built module version reconciliation. |
| Browser | 750 | Standalone Rust/native dependency coverage for agent-browser. |

These are scanner match records, including repeated binary/source-package
matches and conservative results; they are not counts of independently verified
exploitable vulnerabilities. The release-specific Debian tracker still marks checked Chromium records as
vulnerable on Bookworm while marking Trixie fixed; the generic upstream version
description is insufficient to clear them. The next validation candidate moves
the core, web, browser and supply-chain images to checksum-pinned Debian 13,
with package versions verified against both architecture indexes. This updates
Python, Ruby, Nmap and the Chromium security packages. It also records checked
CORScanner/Dirsearch source-library identities and tests advisory detection for
Debian, npm, Python, Ruby and Rust dependency records against a fresh pinned
database. These changes still require fresh Linux image results; the figures
above remain the last green checkpoint. Raw matches remain retained. Critical Ruby/OS findings and unresolved native coverage still
block release; no blanket suppression is applied.

Runtime jobs have a 90-minute limit. Individual memory, CPU, process, output and
storage bounds remain enforced. Hosted Linux setup may reclaim only listed
unused SDKs inside its disposable VM; local/self-hosted environments are
rejected. The 20 GB product budget and 10 GB host reserve remain in place.
Image cataloging has a separate 4 GB temporary-file bound for real layers;
parsed scanner reports remain capped at 64 MiB.

The public-history scan exposed a legacy Sourcegraph-rule false positive:
560 matches were full upstream fix-commit URLs in the retained advisory reports.
The exception requires that rule, the exact report-path form and a complete JSON
URL line for the reviewed upstream repositories. The official scanner still
detects generated prefixed/unprefixed token controls, query-string credentials
and the same hash URL outside those reports. All 41 public commits pass with
the reviewed configuration; private local branches are not scanned or exported.


The optional `browser` profile pins the official agent-browser 0.40.0 Linux
assets and Chromium 156 packages. Browser operations use fresh anonymous
sessions, ignore host browser/provider configuration, restrict requests to the
requested hostname and explicitly close their owned sessions. The current
snapshot URL delimiter is parsed correctly. Interactive mode supports up to
16 explicit click/wait actions from an input JSON file; actions require
`--approve` even under advisory policy. Selectors are sent as JSON arguments,
and command arrays are omitted from stored browser output. This is bounded
interaction, not arbitrary script execution or persistent authenticated browsing.
Native diagnostic controls and both Linux profiles pass, including actual clicks,
isolated storage, hostname filtering and untrusted-TLS failure controls.
Planning accepts the same bounded input file as execution.

The optional `web` profile pins WhatWeb 0.6.4, WAFW00F 2.4.2, Gobuster 3.8.2,
HTTPx and FFUF. Its build runs real loopback positive/negative/failure controls
for `tech.fingerprint`, `waf.detect` and `dir.bruteforce`. Additional controls
reject untrusted TLS, accept an explicitly trusted fixture CA, prevent the two
fingerprint engines from following redirects, and retain partial Gobuster
matches when request errors occur. TLS verification is enabled by exact-input
source patches in WhatWeb and WAFW00F; this does not assert the same property
for every other scanner. Gobuster's quiet-mode patch preserves request errors.
Native diagnostic tests and both Linux container profiles pass; these three
additions now count in the source-bound functional totals. The profile uses
the same runtime and storage limits; operation validation has networking disabled.

`python3 scripts/toolbox.py --profile analysis build` builds a separate pinned
Semgrep/Gosec image with the Go SDK and local rules. Runtime networking and Go
dependency downloads are disabled. The profile retains the same 2 GiB RAM,
one-CPU, 3 GB image and 20 GB storage admission limits as the compact profile.
Code with external Go dependencies needs those dependencies available locally.
The analysis profile also supplies GF/Anew. `pattern.detect` extracts URL
candidates with the bundled pattern and deduplicates their stream without
modifying input files. Missing pattern/grep failures are preserved even when
upstream GF returns exit zero. This operation does not test URLs for vulnerabilities.

`python3 scripts/toolbox.py --profile supplychain build` prepares Trivy, Grype,
Syft and immutable upstream vulnerability databases. The databases live in checksummed,
read-only mounted dataset outside the image layers. Filesystem scans use a
memory-backed artifact cache. Dataset storage remains inside the 20 GB budget.
Terraform/IaC fixture tests require no cloud account. Java database and
account-level cloud operations are not supplied by this profile. Grype hydrates
its own database with its pinned executable in a bounded, network-isolated import
container; CYBOT does not fabricate its import/checksum metadata.
Container fixtures cover Docker-save archives, OCI layout directories and a
TLS-verified loopback registry. Local configuration fixtures compare public SSH
ingress with a private-CIDR control; they do not create cloud resources.

CI now produces individual positive/negative/failure operation reports, binds
them to measured executable hashes and source fingerprints, and merges both
architectures into a full-catalog gate artifact. A startup/help probe cannot
produce these certificates. Missing or stale reports keep the relevant entries
blocked; passing source CI does not override the full-product gate.
Independent passed operations remain available in the evidence artifact even
when another profile test fails. A failed suite never promotes its candidate image.
Profile runtime histories live under `.cybot/runtimes/PROFILE`; validation writes
only to its separately mounted report directory. Private research and unrelated
root state remain outside the toolbox's state mount.

HTTP mapping controls distinguish a reachable page without links from an
unreachable target. DNS controls distinguish NXDOMAIN and successful empty
A/AAAA answers from SERVFAIL, missing response status and resolver silence.
The DNS adapter retains response codes without expanding its queries beyond
A/AAAA. Official DNSx release 1.3.0 still self-reports 1.2.3; certificates retain
both values and bind the executable hash to its release archive.

The external-executable dependency audit is also in progress. Verified upstream
HTTPx, Katana and DNSx diagnostic binaries contain affected compiled dependencies
and older Go runtimes. Passing functional fixtures does not clear those findings
or certify the final toolbox security. Patched rebuilds need their own dependency
audit and fresh platform operation evidence before release.

HTTPx/DNSx/Katana now have reproducible source-build recipes with exact module
checksums, committed dependency locks, Go 1.26.10, and a hash-checked migration
from unmaintained OpenPGP code. Diagnostic patched builds pass the binary Go
vulnerability audit and the HTTP/DNS loopback controls; Linux image validation
remains a separate requirement. Image build manifests distinguish these CYBOT
patched executables from upstream release binaries.

`python3 scripts/toolbox.py --profile core audit` copies measured executables
from the validated image and scans their exact bytes. The same action supports
analysis and supplychain. CI retains these reports even when vulnerabilities
block an audit. Stripped-binary conservative matches remain blockers, and a
passing Go audit cannot substitute for the unfinished OS/native-language audit.
The full-release gate requires artifact-security proof for all ten Linux
profile/architecture combinations in addition to operation certificates.

The next repair batch also supplies locked rebuilds for FFUF, Subfinder,
Gitleaks and Gosec. Diagnostic binaries clear the Go audit; FFUF/Gitleaks/Gosec
pass their real positive/negative/failure controls. Subfinder's provider-list
check remains startup validation until real provider response controls pass.
New installed-CLI fixtures cover curated CVE/ATT&CK lookups, classification,
persisted reports and evidence-backed finding review, including tampered
evidence rejection. These new certificates are counted only after CI executes
all controls on the new source revision.

An executable without readable compiled-module metadata stays audit-failed.
The audit continues checking independent executables and retains that failure.
The compiler check also rejects older/unrecognized Go versions, including
experimental version strings that could otherwise hide standard-library gaps.

JavaScript extraction now selects JSLuice's actual `urls` mode and parses its
JSONL contract. LinkFinder's URL/path output has dedicated normalization;
zero-exit diagnostics fail explicitly. Both engines require one bounded local
file. Relative paths remain observations, absolute URL credentials are redacted,
and input files are preserved. The analysis image builds the C-backed parser
in a separate bounded stage from verified/vendored source and includes pinned
Python dependencies and notices for LinkFinder. This operation remains
experimental and requires fresh Linux image controls before certification.

Artifact reports now carry the operation-tested image ID and profile. The full
gate rejects a security audit from a different image even when selected launcher
hashes happen to match. Coverage enumeration is offline and cannot trigger an
unrelated prompt-pack update. FFUF source builds use its upstream release linker
flags so its embedded version matches the verified 2.2.1 source tag.

Naabu, Nuclei and Syft also have checksum-verified source rebuilds and committed
dependency locks. Diagnostic binaries pass their Go audits and real loopback or
local-package positive/negative/failure controls. Syft additionally updates its
containerd and OpenTelemetry dependencies. Nuclei's required kin-openapi update
includes a hash-checked compatibility patch and focused upstream-package tests;
unsupported OpenAPI 3.1 numeric exclusive bounds fail instead of generating
unchecked examples. Native Linux image tests remain required for these builds.

The legacy backup helpers now select validated profile pins instead of an old
hard-coded ARM64 tag. A backup directory contains the immutable image archive
and a mandatory checksummed manifest. Restore validates profile/platform, rejects
tag-bearing archives, measures the loaded image and reruns operation fixtures
before selecting its pin. These image-only backups preserve existing workspace
state and require separate data backups; they do not claim full data rollback.
Both Linux core jobs include the actual backup/restore round trip.


The supply-chain/secret-scanner repair batch adds locked source builds for Trivy,
Grype and TruffleHog. Grype migrates its completion client from the deprecated
Docker SDK to the maintained Moby API, with focused loopback daemon controls.
Trivy retains upstream JSONv2 compilation and updates VEX discovery, Rekor,
containerd and telemetry dependencies. TruffleHog is built without UPX packing,
so compiled metadata can be audited. Diagnostic binaries clear compiled Go
audits; the native Linux AMD64/ARM64 runtime suites and all measured Go executable/source-identity audits pass for this batch. OS/native-component audit remains incomplete.

Security audits now supplement compiled-symbol checks with advisory queries
for checksum-verified upstream identities hidden by local `(devel)` main modules
and replacements. The exact binary, dependency locks and source provenance must
match before a source-module review is accepted. The Trivy incident record
GO-2026-4919 has an open-ended Go database range; its
[primary advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
explicitly excludes source-built binaries. The recorded not-affected review is
restricted to the exact verified v0.72.0 source input, retains the original
advisory, and never clears downloaded binaries, altered source or another alert.

Final artifact audits must be less than 24 hours old. Release policy changes
are included in the product source fingerprint, so changing required platforms,
audit requirements or inventory cannot reuse earlier certificates. None of
these Go/source-module checks substitutes for the blocked OS/native-component
security audit.


The checked-in `release/validation/` directory now retains all 102 platform-specific
operation reports plus ten full image audit reports from revision `2fdc975`.
`release/readiness.json` is regenerated against the current product digest; it
records 24 tools and 27 capabilities with passing functional proof and keeps the
full release blocked. The website displays that snapshot per entry, including
tested platforms and the remaining release checks.
