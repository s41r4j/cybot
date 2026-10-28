# Validation status — 2026-10-04

> Historical snapshot. Current source repairs, CI and release limitations are recorded in [release-status.md](release-status.md). Machine-local runtime pins now live under `.cybot/toolbox/`; older image IDs do not constitute a published download.

The six approved repair areas have source changes and regression coverage. This document describes what was checked; it does not certify every cataloged tool against live targets.

## Completed source repairs

| Area | Result |
| --- | --- |
| Incorrect findings | SQLMap uses completed parameter blocks; negative SQL/CORS messages do not produce vulnerability findings. Unrecognized output is partial and carries a warning. |
| Output contracts | Dedicated Nmap XML parser; ZAP accepts numeric/string risk fields, preserves alert titles and affected instances, avoids missing-instance crashes, and uses distinct finding IDs. Generic text/JSON becomes unverified observations rather than invalid asset types. Browser malformed/failed batches return errors. |
| Configuration and policy | Working duration syntax in the example config; missing/invalid explicit configs return errors. Warning-only mode remains the default; warnings reach CLI stderr, results, history, and audit. Strict mode is enforced only when explicitly configured. |
| Notes and evidence | Repeated scaffolding preserves files; directory traversal and engagement symlinks do not redirect writes. Recognized credentials are redacted from captured evidence, normalized results, and audit events. Secret-derived IDs use SHA-256. Stored evidence hashes cover the redacted bytes. |
| Persistence and diagnostics | Run history and engagement memory update in one transaction. Audit, persistence, export, and output write failures are surfaced. Plans and workflow definitions do not claim verified tool availability. |
| Documentation and tests | Counts, historical image/backup identifiers, default policy, workflow semantics, and validation claims have been corrected. Regression tests exercise the failures above. |

## Checks performed

- `go test -count=1 ./...`: passes, including the added regression tests.
- `go vet ./...`: passes.
- CLI build: passes.
- CLI smoke tests in temporary directories: discovery, invalid-target planning, warning-only execution, persisted advisories, memory recall, reports, repeat scaffolding, skill export, and tool/skill import across separate invocations.
- `docker compose -f docker-compose.toolbox.yml config --quiet`: passes.
- `bash -n` on every project shell script: passes.
- `git diff --check`: passes.

Tests use temporary state and offline fixtures. Docker command tests replace the Docker executable with a fixture and verify image-specific invocation. Expected alert exit codes are also tested with a local subprocess. These checks do not claim that Docker actually ran a scanner.

## Remaining integration validation

The Docker daemon was unavailable. Starting `/Applications/Docker.app` failed with macOS `kLSNoExecutableErr` (missing executable), so live image health checks and container scans were not performed. No external targets were scanned. No image was rebuilt or published.

After Docker is working, build an image containing this source, run its offline health check, and test installed adapters against dedicated fixtures and an authorized lab. Inspect the declared versus installed versions; `tool doctor` checks presence, not exact version parity. The historical image record reports 58 of 84 discoverable tools available, not universal adapter coverage.

ZAP report collection follows the upstream [baseline scanner contract](https://www.zaproxy.org/docs/docker/baseline-scan/): JSON is written to a report file, and exit codes 1/2 carry alerts. Its floating `stable` image tag still requires separate version verification. A successful offline parser test is not a live ZAP certification.

Redaction covers recognized labels and formats. Unlabeled or encoded secrets can still require manual review. Workflow definitions are ordered templates; they do not schedule or automatically convert hostnames, URLs, local paths, finding text, and source run IDs between steps.
