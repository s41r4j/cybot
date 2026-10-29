# Release status — 2026-10-28

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
The complete source CI run at revision `cde3054` passed on Linux AMD64/ARM64,
macOS and Windows, including both native Linux compact-toolbox fixture jobs.
The expanded code-analysis profile and per-operation certification pipeline
are being validated separately; they are not counted as passed in this snapshot.
Windows,
AD, cloud credentials, external providers and specialist runtimes need compatible
authorized environments and real-operation tests.

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
