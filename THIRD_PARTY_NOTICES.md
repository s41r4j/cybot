# Third-party notices

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
