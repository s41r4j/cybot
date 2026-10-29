# Release status — 2026-10-29

CYBOT is public source in active development. A stable release covering the
entire catalog is **not yet certified**. The release requirement includes every
one of the 84 tools and 71 capabilities; no entries are removed from the gate to
increase a percentage.

## The six repair areas

| Area | Source changes | Remaining release evidence |
| --- | --- | --- |
| 1. Scope binding | Remote approval cannot invoke local/interface operations. Explicit local://HOSTNAME and interface://INTERFACE targets require approval. Policy preserves resource kind; unimplemented operations fail explicitly. | Real compatible runtime/lab evidence for every specialist adapter; service-start/status commands are not accepted as complete operations. |
| 2. Scanner errors | Tool diagnostics are preserved; zero-file Semgrep/Gosec reports and targetless Trivy reports are partial. Partial scans retain genuine findings. | Full positive/negative/failure fixture coverage for each installed scanner version. |
| 3. Heuristic findings | URL classification returns investigation candidates and never creates vulnerability findings. Finding review requires explicit operator assertions and hash-verified stored evidence; prose alone stays UNVERIFIED. | Independent review remains necessary; operator assertions do not prove exploitability. |
| 4. Toolchain | Go 1.26.10 pinned; affected x/text and x/sys versions updated; source vulnerability scan passes on that compiler. | Scan each final CLI/toolbox artifact and its external executables/OS packages. |
| 5. Distribution | Public repository, versioned build configuration, release gate, immutable image pull/validation, local runtime pins, CI and website source. | Successful publishing pipeline, clean-machine installation and compatible image evidence. No completed stable release is claimed. |
| 6. Publication hygiene | MIT license, security policy, third-party notices, strict example, and allowlisted clean source export. Private research remains locally preserved and is excluded from public source/history. | Ongoing secret scanning and third-party asset/license review for each release. |

## What passes locally

Fresh Go tests and vet pass with Go 1.26.10. Source govulncheck reports no known
reachable vulnerabilities after toolchain/dependency updates. Python tests
cover budget/locking/promotion, source export, and fail-closed release gating.
Regression cases cover the previously reproduced scope and result failures.
These are source and contract checks, not 84-tool live certification.

The local Docker daemon is unavailable. Historical 2026-10-22 compact-core
results are retained as historical records and do not certify the changed source.
The complete [CI run at revision `5944378`](https://github.com/s41r4j/cybot/actions/runs/40814092934)
passed source checks on Linux AMD64/ARM64, macOS and Windows, and real-operation
fixtures in all three native Linux toolbox profiles on both architectures.
Its source-bound reports certify **16 tools and 13 capabilities** functionally;
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
The full-release gate requires artifact-security proof for all six Linux
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
