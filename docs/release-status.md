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
CI builds/tests compact images on native Linux AMD64 and ARM64 runners. Windows,
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
