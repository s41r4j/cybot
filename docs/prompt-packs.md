# Versioned prompt packs

CYBOT includes the 14 phase prompts from
[mdpsec/bug-bounty-hunting-prompts](https://github.com/mdpsec/bug-bounty-hunting-prompts)
at commit `5ed41580564c978417d5f0105f9c92457d77f3b5`. The original files, MIT
license, README, security policy and adaptation guide are bundled unchanged.
`internal/packs/builtin/provenance.json` records the commit and every file's
SHA-256 checksum.

Prompt packs provide agent guidance and persisted phase handoffs. Capability
mappings describe useful CYBOT building blocks, not full implementations of the
upstream workflow. Upstream private helpers, account provisioning, resource
leases, coverage validators and independent verification remain explicit gaps in
the phase manifest. Pack commands do not run scanners or imported shell blocks.
Use `cybot capability plan` and `cybot run` for actual capability execution.

## Install and inspect

```sh
go build -o cybot ./cmd/cybot
./cybot pack catalog
./cybot pack install mdpsec/bug-bounty-hunting-prompts --bundled
./cybot pack list
./cybot pack plan mdpsec-bounty
```

The bundled install works offline. Omit `--bundled` to fetch the current upstream
`main` revision. `--ref BRANCH_OR_TAG` selects a different tracked ref at initial
installation; a full commit SHA pins it. The importer also accepts a GitHub URL.
Other public repositories can use `phases/phase-NN-name.md`, Markdown beneath
`prompts/`, or root/nested `SKILL.md` files. Standalone prompts and skills are
independent rather than being forced into mdpsec's phase sequence. Repositories
must include a root license (`LICENSE`, `LICENSE.md`, `LICENSE.txt` or `COPYING`).
Their default entries have no curated capability mapping.

For a deliberate integration, put a `cybot-pack.json` manifest in the source
repository. It defines prompt paths, stable IDs, dependency order, capability
mappings, inputs and handoff artifacts; additional Markdown references can be
listed in `documents`. See [the example](../examples/cybot-pack.json). Manifest
phase dependencies must refer to earlier entries; invalid paths, duplicate IDs,
unknown fields and unsupported schema versions are rejected. A manifest also
lets large repositories select a bounded subset of prompts. Graph and mapping
changes then arrive with ordinary source updates, without changing CYBOT code.

`pack show` is the same as `pack plan`: it returns phase order, dependencies,
required inputs, expected handoff artifacts, capability IDs and integration gaps.
It reports tool availability as unchecked. The optional browser branch does not
block the critical-hunt branch. New upstream phases appear as guidance with a
missing-mapping notice. Invalid dependencies cause import to fail.

## Update lifecycle

```sh
./cybot pack update                       # Update all installed packs now
./cybot pack update mdpsec-bounty          # Update one pack now
./cybot pack update --due                 # Respect each source's check interval
./cybot pack watch                        # Keep updating while this process runs
./cybot pack watch --once                 # One due pass, useful for a job runner
./cybot pack check-updates mdpsec-bounty
./cybot pack sync mdpsec-bounty
./cybot pack diff mdpsec-bounty
./cybot pack activate mdpsec-bounty --revision COMMIT_SHA
./cybot pack history mdpsec-bounty
./cybot pack rollback mdpsec-bounty
./cybot pack events mdpsec-bounty
```

An initial install activates its snapshot. Later installs and manual syncs stage
a candidate; `update` additionally validates and activates the candidate. An update
resolves the tracked ref once, downloads all allowed files at
that exact SHA, verifies Git blob IDs, then stores the complete revision in one
transaction. Interrupted downloads, invalid files and checksum failures leave
the active revision intact. Repeated updates reuse already stored revisions.
Before activation, CYBOT checks source integrity, phase dependencies, local
override compatibility, known capability mappings and phase rendering. These
checks validate the integration contract; they do not certify the research
quality of upstream prose or supply missing private services.

The diff reports added, changed and removed paths plus override conflicts. Use
`pack export --revision COMMIT_SHA` to inspect the full candidate text. Activation
switches one pointer transactionally. Retention keeps the active version and
exactly one previous version, plus any staged candidate and revisions pinned by
engagements. Older unreferenced revisions and their overrides are pruned in the
same transaction. An initial install naturally has no previous version until
its first update; older versions are never invented as backups.

Rollback restores the previous revision and its associated overrides, and places
the reverted commit on hold so auto-update cannot immediately reinstall it. A
newer upstream commit may update normally. Explicit `pack activate --revision`
can select the held revision after you decide to retry it. If an installed
snapshot fails local integrity/integration validation, maintenance automatically
restores a healthy previous version when one is available. Semantic prompt
regressions still require an explicit rollback. Updates require no binary or
Docker rebuild.

```yaml
packs:
  auto_update: true
  update_interval: 24h
  update_timeout: 45s
```

Automatic maintenance is enabled by default. `cybot capability coverage` stays
offline so its inventory cannot trigger unrelated prompt updates. Other normal CYBOT commands and prompt
consumers (`pack list`, `show`/`plan`, `render` and `run start`) perform due checks
before reading the active snapshot. Work is bounded by `update_timeout` for the
entire startup pass. Network failures leave commands usable with installed data;
diagnostics go to stderr so structured stdout stays parseable. Pack management
commands, exports and pinned engagement reads remain available without triggering
an update. Set `auto_update: false` or `CYBOT_PACK_AUTO_UPDATE=0` for offline use.

`pack watch` provides continuous maintenance while its process is running, using
the same update interval and a per-source timeout. Its default poll period is the
smaller of the update interval and 15 minutes; `--interval` customizes polling.
It emits JSON lines for changes and errors and stops on Ctrl-C/SIGTERM. It does
not install a system service. When CYBOT is closed and no watcher is running,
maintenance resumes at the next invocation. A shared database lease prevents
competing CLI/watch processes from updating the same pack concurrently; leases
expire after a crashed process. Activation also checks that another process has
not changed the active revision while the source was being downloaded.

`cybot pack check-updates --due` only checks metadata and never activates updates.
Offline bundle installation does not claim a successful GitHub check. Failed
checks use a retry delay capped at 15 minutes. Explicit update/check commands
without `--due` force an immediate attempt. Updates continue across independent
sources if one fails; explicit command failures produce a nonzero exit status.
GitHub requests are unauthenticated and subject to GitHub's public API limits.
Installed snapshots, rendering and history remain available offline.

## Local adaptations and conflicts

Overrides contain replacement prompt `content`, `capabilities`, or both. The CLI
validates every mapped capability ID. Store an override against the active
revision:

```sh
./cybot pack override mdpsec-bounty phase-00-recon --file examples/pack-override.json
./cybot pack overrides mdpsec-bounty
```

Overrides are stored separately from original source bytes and keyed by revision.
When a new revision is first staged, it receives a copy of the active overrides.
Later edits to either revision affect that revision only. If the upstream phase
changes or disappears, the copied override is marked as conflicting and prevents
activation. Resolve it against the candidate, preserving the active revision:

```sh
./cybot pack override mdpsec-bounty phase-00-recon \
  --file examples/pack-override.json --revision CANDIDATE_SHA
./cybot pack overrides mdpsec-bounty --revision CANDIDATE_SHA
# Or discard that candidate's override and use its upstream content:
./cybot pack remove-override mdpsec-bounty phase-00-recon --revision CANDIDATE_SHA
```

An optional `base_sha256` field detects stale override submissions. When rebasing
an exported override, replace this hash with the candidate file hash or omit it
after reviewing the changed source. Removing an upstream phase requires removing
the corresponding candidate override.

## Render and export

```sh
./cybot pack render mdpsec-bounty phase-00-recon --context examples/pack-context.yaml
./cybot pack render mdpsec-bounty phase-00-recon \
  --context examples/pack-context.yaml --output recon-guidance.md
./cybot pack export mdpsec-bounty --output prompt-pack.json
```

Context is a YAML/JSON map of strings. Rendering substitutes `{{variable}}`,
`$YOUR_VARIABLE`, `${YOUR_VARIABLE}` and recognized infrastructure placeholders
in one literal pass. It does not evaluate shell expressions or nested templates.
Missing values appear in `unresolved_inputs`, including required `target` and
`scope`. `--strict` fails when these inputs remain unresolved; it does not certify
private integrations or tool availability. The CYBOT wrapper gives explicit
engagement scope precedence over upstream assumptions about sibling hosts.

`--output` writes Markdown for rendering and JSON for exports, using restrictive
permissions and refusing to overwrite an existing file. JSON exports include the
complete original snapshot, license, phase manifest and that revision's overrides.
The default output is structured JSON; `--format yaml` and `--format markdown`
are also supported. `--revision SHA` selects a stored revision for inspection,
rendering, export, diff and override management.

## Pinned engagements and phase handoffs

```sh
./cybot pack run start mdpsec-bounty --context examples/pack-context.yaml
./cybot pack run render RUN_ID phase-00-recon
./cybot pack run record RUN_ID phase-00-recon --status completed \
  --reason 'Recorded the authorized lab surface and coverage limitations' \
  --artifact phase-summary=/absolute/path/to/summary.md \
  --artifact coverage-and-evidence=/absolute/path/to/coverage.json
./cybot pack run show RUN_ID
```

Starting an engagement freezes the active revision, context and local overrides.
Subsequent pack updates and local edits do not change its rendered guidance.
Context must contain a target and explicit scope; use paths or secret-manager
references instead of passwords, cookies, tokens or other secret values.

Phase records are append-only and accept `completed`, `partial`, `blocked` or
`skipped`. A completed record requires completed dependencies and both named
handoff files. Only optional phases may be skipped. Required phases with missing
prerequisites remain blocked or partial. Each handoff records an absolute file
path and SHA-256 of its current bytes; files remain at their original locations.
Records state that completion is operator-attested and does not certify
independent live verification. No automated finding submission is performed.

## Backend storage and extension points

`internal/packs` provides the import, storage, diff, activation, rendering and
engagement services. `internal/app/packs.go` exposes these through Cobra. Runtime
state is stored in `data_dir/packs.db` alongside the existing `cybot.db`:

| Table | Purpose |
| --- | --- |
| `pack_sources` | Tracked repository/ref, active/previous/candidate pointers, check status |
| `pack_revisions` | Immutable original files, hashes and versioned phase manifest |
| `pack_overrides` | Local adaptations scoped to revision and phase |
| `pack_runs` | Pinned engagement context, override snapshot and phase records |
| `pack_events` | Pack lifecycle and engagement events |
| `pack_update_leases` | Cross-process updater ownership and crash recovery |

Source import allows only supported prompt/document paths or manifest-declared Markdown, rejects
symlinks and truncated trees, and limits files to 1 MiB, packs to 8 MiB and 128
files. Original text is never evaluated. The HTTP path uses CYBOT's existing
HTTPS source restrictions. The independent database adds no migration to existing
capability history and requires no external service or model credentials.
