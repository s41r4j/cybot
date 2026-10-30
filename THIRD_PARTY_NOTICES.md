# Third-party notices

The optional analysis toolbox uses the pinned upstream Semgrep image and its
bundled dependencies. Semgrep source for that image is available at
https://github.com/semgrep/semgrep/tree/v1.172.0. Its upstream license files remain
in the base image. Gosec is built from the verified Go module version v2.28.0;
the image includes license/notice files for the scanner and its downloaded Go
modules under `/opt/cybot/share/licenses/gosec`. The Go SDK includes its upstream
license at `/opt/go/LICENSE`. CYBOT CLI dependency notices are included under
`/opt/cybot/share/licenses/cybot/dependencies` in every toolbox profile.
GF and Anew are built from the exact Go module revisions in
`docker/toolbox/analysis.lock.json`, using the same verified toolchain. Their MIT
notices are collected alongside the other downloaded Go-module notices. The
`cybot-urls` pattern is part of CYBOT's own MIT-licensed source.

The supply-chain profile preserves Trivy, Grype and Syft notices from their official
release archives under `/opt/cybot/share/licenses`. Its locked vulnerability
database comes from `ghcr.io/aquasecurity/trivy-db`; the exact blob checksum and
publication time are recorded in `docker/toolbox/supplychain.lock.json`.
Database source and license information: https://github.com/aquasecurity/trivy-db.
The Grype database is pinned from https://grype.anchore.io/databases/v6/ using its
published checksum; source and data attribution are maintained at
https://github.com/anchore/grype-db.

CYBOT's own source is MIT licensed. External executables, data sets, rules,
databases, fonts and prompt packs retain their respective licenses. Listing a
tool in the catalog does not redistribute it or grant rights to its source.

- The bundled `mdpsec/bug-bounty-hunting-prompts` adaptation retains its MIT
  license in `internal/packs/builtin/LICENSE`, attribution and provenance.
- Go dependency versions are recorded in `go.mod` and `go.sum`. Release source
  bundles include those manifests; binary distribution must retain applicable
  dependency notices.
- Compact toolbox asset sources and hashes are recorded in
  `docker/toolbox/core.lock.json`. Its build helper collects LICENSE/NOTICE
  files from executable archives into the image. SecLists attribution is
  retained beside the bundled wordlist.
- `catalog/tools.yaml` records declared upstream source/license metadata. That
  metadata is informational and does not establish redistribution permission.
  Specialist tool distributions require their own license review and notices.
- `docker/toolbox/Dockerfile.full` is an unvalidated historical recipe. It is
  excluded from automated release publication and is not a certified full
  distribution.

Release validation must inspect the actual shipped assets and notices. An
MIT project license does not relicense third-party components.

## Patched upstream Go tools

HTTPx, DNSx, Katana, FFUF, Subfinder, Gitleaks, Gosec, Naabu, Nuclei, Syft, Trivy, Grype, TruffleHog and Gobuster are rebuilt from checksum-verified
upstream Go modules with Go 1.26.10 and the committed module locks in
`docker/toolbox/patched-go/`. The original release archive hashes remain as
upstream provenance; these rebuilt executables have their own measured hashes.
The go-github v30 dependency's two OpenPGP imports are migrated to the maintained
ProtonMail implementation using exact input-file hashes. Binary symbols are
retained for artifact vulnerability analysis. Build manifests and copied upstream
dependency licenses are included under `/opt/cybot/share/` in the image.
Nuclei's OpenAPI example generator has an exact-input compatibility patch for
the fixed kin-openapi API. It preserves supported OpenAPI 3.0 boolean bounds and
explicitly rejects unsupported 3.1 numeric exclusive bounds; focused compatibility
tests and their hashes accompany the source-build provenance.
Gitleaks retains the upstream `gore2regex` build mode. Its archive dependency is
updated together with the fixed RAR decoder; the committed locks record the
exact resolved versions.

The JavaScript extraction image also bundles LinkFinder at commit
`1debac5dace4724fd6187c06f133578dae51c86f`, its pinned Python wheels, and
JSLuice at module revision `0ddfab153e06`. JSLuice's URL mode has a hash-checked
patch to surface JavaScript syntax failures. Its build retains compiler/package
metadata and static-runtime notices. The original source licenses, vendored Go
dependency notices, Python wheel notices, musl copyright, and GCC runtime
exception accompany the image under `/opt/cybot/share/licenses/`.

Grype's maintained Docker-client compatibility patch and its loopback tests are
recorded with exact source hashes in the build manifest. TruffleHog retains its
upstream AGPL-3.0 license; the verified source module, dependency locks and build
recipe identify its corresponding source. Upstream source and dependency
licenses accompany the image. Trivy preserves its upstream JSONv2 build mode;
its VEX and signing dependency updates remove the retired cryptography paths.

The web image includes WhatWeb 0.6.4 (GPL-2.0), its complete interpreted source,
and pinned Addressable, Public Suffix and IPAddr gems with their license files.
WAFW00F 2.4.2 retains its BSD-3-Clause license and pinned Python wheel notices.
Exact source and package hashes are recorded in `docker/toolbox/web.lock.json`.
Hash-checked patches enable certificate verification in both WhatWeb TLS
transports and WAFW00F's request engine. Gobuster's quiet-mode patch preserves
request-error diagnostics; explicit error suppression remains an upstream option.
The committed patch recipes and dependency locks identify corresponding source.
