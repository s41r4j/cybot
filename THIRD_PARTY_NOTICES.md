# Third-party notices

The optional analysis toolbox uses the pinned upstream Semgrep image and its
bundled dependencies. Semgrep source for that image is available at
https://github.com/semgrep/semgrep/tree/v1.172.0. Its upstream license files remain
in the base image. Gosec is built from the verified Go module version v2.28.0;
the image includes license/notice files for the scanner and its downloaded Go
modules under `/opt/cybot/share/licenses/gosec`. The Go SDK includes its upstream
license at `/opt/go/LICENSE`. CYBOT CLI dependency notices are included under
`/opt/cybot/share/licenses/cybot/dependencies` in every toolbox profile.

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
