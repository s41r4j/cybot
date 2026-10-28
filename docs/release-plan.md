# Project structure and distribution plan

> Historical snapshot. Current source repairs, CI and release limitations are recorded in [release-status.md](release-status.md). Machine-local runtime pins now live under `.cybot/toolbox/`; older image IDs do not constitute a published download.

Planning assessment recorded on 2026-10-21. No release, refactor, installer or
publishing workflow is implemented by this document.

## Assessment

The current Go package layout is a sound base for an initial release. Keep its
core boundaries; address the release pipeline and runtime selection before
undertaking a large folder reorganization.

| Area | Observed state | Planned action |
| --- | --- | --- |
| Entry point | Small `cmd/cybot/main.go` | Keep the entry point thin |
| Core services | Separate orchestrator, execution, policy, evidence, memory and pack packages | Preserve these boundaries |
| Command layer | `internal/app/app.go` combines many command families in one large file | Split into files by command family while keeping shared wiring separate |
| Capabilities | Definitions, adapters and many parsers share the capability package | Separate definitions, adapters and parser files as they grow; introduce subpackages only where dependencies justify them |
| Catalog and schemas | Embedded metadata and schema packages are already separate | Keep versioned contracts and validate catalog-to-adapter consistency |
| AI integrations | CLI adapter definitions exist; installer automation and an MCP server are not implemented | Ship documented CLI/JSON integrations first; treat a real MCP server as a separate milestone |
| Prompt packs | Separate source, layout, updates, storage, rendering and engagement services | Keep prompts independently updatable and runs pinned |
| Host CI | Tests, race checks, vet and CLI build on Linux, macOS and Windows are configured | Add real image/runtime integration jobs and retain test evidence |
| CLI distribution | GoReleaser configuration targets three operating systems and two CPU architectures | Connect it to a tested release workflow and verify reported versions |
| Docker distribution | Build helper selects Linux ARM64; some downloads are ARM64-specific | Parameterize architecture-specific assets and verify AMD64 and ARM64 separately |
| Release identity | Current image tag is local; no Git remote is configured in this checkout | Choose the owned repository, registry namespace, product versions and release channels |
| Licensing | No top-level CYBOT license was found; the prompt bundle has its own license | Choose a project license and review bundled tool/data redistribution requirements before publishing |
| Download size | Historical image metadata reports roughly 8.7 GB; current size is unverified | Measure the fresh image, document requirements, and consider smaller tool bundles after the first release |

## Folder changes to plan

- Keep `cmd/cybot/`, `internal/`, `catalog/`, `schemas/`, `configs/`, `examples/`,
  `rules/`, `docker/`, `scripts/` and `docs/` in their existing roles.
- Split command files by responsibility: capabilities, tools, skills, workflows,
  history/reports, policy and packs. Keep business logic in service packages.
- Add installation/provisioning as a distinct execution dependency when the
  deferred local-fallback work is implemented. Keep tool installation out of
  argument builders and parsers.
- Keep the schema Go types public only if supporting a Go API is intentional.
  The initial supported agent interface should be the CLI and documented JSON
  schemas, with explicit version compatibility.
- Keep runtime databases, evidence, generated reports, compiled binaries and
  exported Docker archives outside release source artifacts.
- Move historical image build records into an archive subdirectory when useful,
  leaving the current lock and provenance manifest easy to identify.
- Review the build context and release archive contents so unrelated reference
  checkouts and local research artifacts are excluded.

## What users receive

Distribute two compatible components:

1. **CYBOT CLI:** a small, versioned executable for the user's operating system
   and CPU. Agents call it through its documented JSON interface.
2. **CYBOT toolbox image:** a versioned Linux container image containing the
   supported security tools and their required reference data. Users pull a
   prebuilt image instead of compiling the toolchain themselves.

The CLI release should declare the exact compatible image digest, adapter/schema
versions and tested capability inventory. The Docker-only route should also let
users invoke the bundled CLI through a documented Compose profile. Both paths
must preserve state, evidence and reports across container replacement.

Docker is the primary runtime. Local execution and host installation modes remain
the separately deferred requirements in the roadmap. Before shipping, normalize
runtime selection: current catalog entries frequently declare native execution,
so the documented Docker-first experience needs an explicit routing layer.

Keep update channels separate:

- **Prompt updates:** use the existing revision updater with one previous version
  retained and engagement pins preserved.
- **Toolbox updates:** publish immutable images and a compatibility manifest;
  validate a new image before selecting it, retaining the previous compatible
  image reference for rollback.
- **CLI updates:** distribute signed/checksummed versioned binaries. Plan an
  explicit upgrade path; do not imply that prompt auto-update upgrades executable
  code, dependencies or container images.

## Initial installation experience

1. User downloads the matching CLI release, or chooses the Docker-only route.
2. A planned setup command checks Docker, host architecture, storage and paths.
3. It pulls the compatible prebuilt toolbox image and runs offline tool health
   checks. Host tools are not installed as part of the normal Docker path.
4. It creates configuration and persistent storage, explains the active policy,
   and reports which capabilities are available, partial or unsupported.
5. It provides the selected agent with short integration instructions and a
   harmless first-run example.

An agent's own permissions still apply. An advertised integration must say whether
it is a tested CLI recipe, an installer, or an actual protocol server.

## Release milestones

### 1. Structure and release identity

Choose the project license, owned repository and registry namespace. Establish
version compatibility rules. Split the largest command/parser files where it
reduces coupling, and document the source-versus-runtime data boundary.

### 2. Docker-first beta

Fix runtime routing, build the image from current source, and run offline health
checks plus bounded tests against a dedicated authorized lab. Publish only the
platforms and capabilities with retained validation evidence. Catalog registration
and cross-compilation alone do not qualify a capability as supported.

### 3. Reproducible distribution

Add a tag-driven release workflow for binaries and toolbox images. Validate both
Linux CPU architectures; test supported host/Docker combinations. Produce
checksums, signatures/provenance, dependency notices and a machine-readable
compatibility/support manifest. Test installation from downloaded release
artifacts on clean environments rather than relying on the developer checkout.

### 4. Upgrade and rollback experience

Implement setup/upgrade diagnostics and test upgrades while preserving databases,
evidence, configuration and pinned engagements. Retaining an old binary or image
does not make a destructive database migration reversible: require backward-
compatible migrations or a verified data backup/restore path before release.
Implement the deferred local fallback only as its own tested milestone.

### 5. Broader distribution

After the direct download and container paths work reliably, add package-manager
distribution and additional agent installers where demand justifies maintenance.
Evaluate smaller, optional toolbox bundles based on measured image size and
actual user workflows.

## Release acceptance criteria

- Fresh binary and Docker-only installs succeed on each claimed platform.
- CLI version, image digest, schemas, adapters and reference-data versions match
  the published compatibility manifest.
- Each capability is labeled tested, partial or unsupported with the reason.
- Offline health checks and authorized lab fixtures pass; failure behavior is
  tested for missing tools, Docker outages, timeouts and incompatible versions.
- First-run, persistent storage, upgrades and rollback work on clean environments.
- Agent discovery, JSON output and installation instructions are verified.
- No local research data, credentials or generated evidence enters release
  archives or build context.
- License/redistribution notices, checksums and release provenance are included.
