# Core runtime testing and pins

> Historical snapshot. Current source repairs, CI and release limitations are recorded in [release-status.md](release-status.md). Machine-local runtime pins now live under `.cybot/toolbox/`; older image IDs do not constitute a published download.

Validated locally on Linux/ARM64 in Docker Desktop on 2026-10-22. This covers
CYBOT's compact core, not every tool advertised by the catalog.

The freshly built ARM64 image passed all eleven offline integration tests before
promotion. The full Go suite, `go vet`, 13 Python tests, Compose validation and
shell syntax checks also passed. Machine-readable results are saved in
`docker/toolbox/core-validation.json`; the full inventory and contract-test
coverage are in `docker/toolbox/readiness-validation.json`.

Fresh-state readiness found **11 of 84 catalog tools available**: ten external
core tools plus the built-in system DNS resolver. The other 73 entries require
optional or OS-specific environments. CYBOT itself is the eleventh pinned
executable, not a catalog tool. The image accounts for approximately 896 MB.
One prior image is retained. Total Docker/local-state storage accounting after
cleanup was 14.29 GB, below the 20 GB admission budget.

## Locked versions

| Executable | Pinned release | Runtime version |
| --- | --- | --- |
| httpx | 1.10.0 | 1.10.0 |
| Katana | 1.6.1 | 1.6.1 |
| Nuclei | 3.11.0 | 3.11.0 |
| dnsx | 1.3.0 | **1.2.3** |
| Subfinder | 2.14.0 | 2.14.0 |
| ffuf | 2.2.1 | 2.2.1 |
| Nmap | Debian 7.93+dfsg1-1 | 7.93 |
| Naabu | 2.6.1 | 2.6.1 |
| Gitleaks | 8.30.1 | 8.30.1 |
| Syft | 1.50.0 | 1.50.0 |
| CYBOT | Local development build | dev, pinned by SHA-256 |

The official dnsx 1.3.0 archive self-reports 1.2.3. Both are recorded explicitly;
verification checks the observed version as well as the installed binary hash.
Existing tool versions were retained; three tested tools were added.

`docker/toolbox/core.lock.json` locks release downloads by URL, length and
SHA-256, data revisions, and direct Debian packages. The Dockerfile pins the base
image digest and direct package versions. `core-runtime.lock.json` pins the
installed image ID and all eleven executable hashes. The image contains its
source manifest. The ARM64 image ID is a local artifact, not a portable registry
reference. AMD64 source assets are locked but have not been run here.

## Repeatable checks

```sh
python3 scripts/toolbox.py verify
python3 scripts/test-core.py
GOMAXPROCS=1 GOMEMLIMIT=512MiB go test -p 1 ./...
GOMAXPROCS=1 GOMEMLIMIT=512MiB go vet -p 1 ./...
python3 -m unittest discover -s scripts -p 'test_toolbox*.py'
```

The integration launcher compiles the Go test harness into a disposable cache,
runs it against the installed CLI and core tools with Docker networking disabled,
and removes its temporary cache. Results go to `.cybot/toolbox/core-tests.json`
and `.txt`. The optional `--source-cli` flag overlays a fresh development CLI;
the report explicitly distinguishes that mode. Tests exercise current-source
adapters; the CLI persistence test exercises the installed CLI by default.

| Check | What it proves |
| --- | --- |
| Web mapping | Real httpx and Katana discover a link; normalized schema and evidence are valid |
| Content discovery | Real ffuf finds a local 200 path and excludes a 404 with a two-word fixture list |
| Nuclei | Real engine distinguishes matching/nonmatching local responses using a harmless fixture template |
| Port scan | Real Nmap connects to one open local TCP port and its XML is normalized |
| DNS | Real dnsx resolves a name through an isolated local UDP DNS fixture |
| Subfinder | Production arguments parse and provider list loads; no external providers are queried |
| Naabu | Unprivileged TCP connect scan finds one local service using the production adapter |
| Gitleaks | Synthetic secret detected and redacted; clean control returns no findings |
| Syft | Fixture package and version appear in the CycloneDX evidence |
| Readiness CLI | All 84 tools and 71 capabilities reported; unfinished adapters explicitly identified |
| CLI persistence | A local web.map run survives history/report roundtrip; missing code tools fail explicitly |

The Subfinder adapter previously reused dnsx flags. It now uses Subfinder's own
arguments, with a portable regression test and an offline installed-binary check.
Nmap's catalog declaration now matches the installed 7.93 runtime.

## Scope and remaining work

- Subfinder's online providers, credentials and rate limits remain untested.
- Production Nuclei templates and full-site scans are not exhaustively tested.
- Missing specialist tools are not installed by these checks. Availability means
  an executable can be located, not that every capability using it is validated.
- Amass 5.1.1 needs its engine/database workflow integrated. Its version probe
  passed, but offline `enum -h` timed out. The incompatible legacy adapter now
  returns `ADAPTER_NOT_IMPLEMENTED`; no Amass executable remains installed.
- AMD64, clean-machine installation, published releases and specialist bundles
  still need validation. A passing core test suite does not make the entire
  84-tool catalog release-ready.
- Host `tool doctor` reports a different environment from Docker. Its
  `version_verification: not-checked` is intentional; use `toolbox.py verify`
  for core hash/version verification.

The current image was built fresh from the compact Dockerfile and verified
release assets. The builder, cache, prepared context and test compilation cache
were cleaned up. Image promotion now requires all offline integration tests to
pass; failure leaves the active pin and tags untouched. One prior CYBOT image
is retained under the `-previous` tag. A published release and AMD64 validation
remain separate work.

See [readiness and remaining-tool audit](readiness.md) for parser fixes,
unfinished adapters, contract-test coverage and the complete per-tool inventory.

The supported launcher retains the 2 GiB RAM, one-CPU and no-swap limits. Disk
checks use the existing 20 GB admission/monitoring budget; they are not a global
filesystem quota. Other projects and their containers, volumes and images were
preserved. See [Docker budgets](docker-budget.md) for details.
