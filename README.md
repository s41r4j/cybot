# CYBOT

[Website](https://s41r4j.github.io/cybot/) · [Release status](docs/release-status.md) · [Complete catalog coverage](release/catalog-coverage.json) · [Security](SECURITY.md) · [MIT license](LICENSE)

**Active development. Full-catalog release certification is not complete.** All 84 tools and 71 capabilities remain in the validation scope; catalog registration and a passing core suite do not certify the full product.

Docker users: start with the [compact toolbox](docs/docker-budget.md), which caps each run at 2 GiB RAM and one CPU and checks the 20 GB storage budget before work.

CYBOT is a deterministic cybersecurity capability layer for AI agents and humans. Agents discover a documented capability, inspect its plan, execute it with policy advisories by default, and receive a schema-validated normalized result. Tools run through internal adapters.

> Only assess systems you own or are explicitly authorized to test. Experimental catalog entries are not equivalent to installed, verified, or approved functionality.

## What is in this repository

| Area | Current inventory | Source of truth |
| --- | ---: | --- |
| Capability definitions | 71 | `internal/capability/builtin.go` |
| Tools available for discovery | 84 (83 catalog + native DNS resolver) | `cybot tool list` |
| Skill catalog entries | 49 | `catalog/skills.yaml` |
| JSON Schemas | 22 | `schemas/*.json` |
| Agent adapters | 10 | `internal/integration/integration.go` |
| Built-in workflow definitions | 9 | `cybot workflow list` |

The historical ARM64 build record reports 58 of 84 tools available in `cybotainer:2026.08.9-arm64`. This is not a current installation check. `cybot doctor` checks storage and registries; `cybot tool doctor ID` checks binary/image presence. Neither certifies scan accuracy or verifies the declared tool version. Plans report `tool_availability: not-checked`, and workflow definitions carry `status: not-checked`.

Source fixes do not update an existing Docker image. Rebuild and validate the image before expecting these changes inside containers. See [validation status](docs/validation.md).

## Quick start

Build the local CLI with Go 1.26.10 (the pinned release toolchain):

```sh
go build -o cybot ./cmd/cybot
./cybot doctor
./cybot list
./cybot capability list --format markdown
```

Discover before you run:

```sh
# Search and explain the capability, including schemas, workflow, tools, limits,
# permissions, examples, assumptions, and verification steps.
./cybot capability search web
./cybot capability help web.scan --format markdown

# Produce a deterministic execution plan without running anything.
./cybot capability plan web.scan --target https://authorized.example

# Inspect tool availability and provenance. Do not run raw tools directly.
./cybot tool doctor
./cybot tool help nuclei --format markdown
```

Run a named capability after reviewing its plan:

```sh
./cybot run asset.discover --target authorized.example --approve
./cybot run code.audit --target /absolute/path/to/approved/source --approve
./cybot asset discover authorized.example --approve
```

The `asset discover` shortcut is equivalent to `run asset.discover`. All other operations use `cybot run CAPABILITY`.

## Policy and warnings

The default and example configuration use `suggestive` mode: policy mismatches produce warnings and execution continues. Warnings appear on stderr, in the result's `warnings` array, in stored history, and in audit events. `--approve` is optional in this mode.

```yaml
data_dir: .cybot
policy:
  allowed_targets: [authorized.example, '*.authorized.example']
  allowed_capabilities: ['*']
  approval_required: false
  max_rate: 100
  concurrency: 1
  timeout: 30m
  enforcement_mode: suggestive
```

Run with `cybot --config ./cybot.yaml ...`. Explicitly named missing configs, unknown fields, and invalid settings produce a clear error rather than silently falling back. Durations use strings such as `30m`.

`strict` is an optional mode for users who deliberately configure enforcement. In that mode, denied targets/capabilities or missing required approval stop execution. `--approve` does not override a strict target denial. Invalid input, failed tools, timeout, and invalid output remain execution errors in either mode.

`max_rate` limits tool process starts per second within a CYBOT process, not every network request made by those tools. Some adapters also supply fixed tool-specific request limits.

## Daily usage

```sh
# Help and machine-readable documentation
./cybot help
./cybot capability help asset.discover
./cybot tool help httpx
./cybot skill help recon-baseline
./cybot policy help
./cybot schema list
./cybot schema show result --format yaml

# Search all knowledge registries
./cybot capability search dns
./cybot tool search sbom
./cybot skill search supply-chain
./cybot source list
./cybot integration list
./cybot workflow list
./cybot report list

# Operational records
./cybot logs list --limit 50
./cybot history list --limit 50
./cybot history show RUN_ID
./cybot report generate RUN_ID --format markdown
```

Every command accepts `help`, `--help`, and `-h`. The global output selector is `--format json`, `--format yaml`, or `--format markdown`; JSON is the default for agents.

## Capability inventory

Every capability has an input schema, output schema, decision tree, tool-selection explanation, assumptions, verification steps, and next-capability recommendations. `asset.discover` is native DNS resolution; `report.generate` renders a stored normalized result. Other implementations include local classification, finding review, CVE/ATT&CK lookup, browser operations, and catalog adapters. Registration and a `stable` interface label do not establish live tool compatibility.

| Group | Capability IDs |
| --- | --- |
| Core discovery and application review | `asset.discover`, `dns.analyse`, `service.enumerate`, `web.map`, `web.content.discover`, `web.scan`, `api.audit`, `code.audit`, `js.analyse` |
| Defensive / supply chain | `secret.scan`, `dependency.scan`, `container.scan`, `sbom.generate`, `cloud.review`, `report.generate` |
| Intelligence | `cve.lookup`, `mitre.map`, `exploit.search` |
| Browser automation | `web.browse`, `web.automate`, `web.har` |
| Assessment and reconnaissance catalog | `port.scan`, `tech.fingerprint`, `waf.detect`, `dir.bruteforce`, `tls.audit`, `vuln.scan`, `sql.inject`, `dns.enum`, `cors.audit`, `cloud.enum`, `cms.detect`, `xss.detect`, `js.extract`, `pattern.detect`, `web.zap` |
| Offensive / restricted catalog | `password.bruteforce`, `hash.crack`, `email.harvest`, `personnel.osint`, `credential.dump`, `lateral.move`, `active-directory.attack`, `privilege.escalation`, `payload.generate`, `phishing.campaign`, `mitm.assess`, `social.engineer`, `credential.harvest`, `c2.setup`, `c2.operate`, `c2.sliver`, `c2.havoc`, `c2.merlin`, `c2.mythic`, `c2.covenant`, `post.mimikatz`, `post.adcs`, `post.kerberoast`, `post.recon`, `post.exploit`, `post.persistence`, `post.kerberos`, `exploit.framework`, `exploit.execute`, `pivot.tunnel`, `port.forward`, `smb.test`, `persist.install` |

The offensive group has argument builders and catalog adapters. Many use generic output capture, which returns partial results and unverified observations rather than confirmed findings. Specialist tools (hydra, hashcat, john, impacket, netexec, chisel, etc.) are outside the compact toolbox and require separately validated installations; Windows-target tools (mimikatz, Rubeus, Seatbelt, SharpView, etc.) are `supported_os: [windows]` and run on a Windows host where the binary is present. Run `cybot capability coverage` and `cybot tool doctor <id>` before relying on any adapter. Use strict policy and explicit target authorization. Local operations require `local://HOSTNAME`; interface-wide operations require `interface://INTERFACE`. Both always require `--approve`. Unfinished adapters fail explicitly.

## Tool inventory

### Historical full Docker toolchain

The archived `docker/toolbox/Dockerfile.full` was configured to install the
following tools. They are not all included in the current compact image:

```text
subfinder, amass, dnsx, naabu, httpx, katana, nuclei, ffuf,
gitleaks, trufflehog, gosec, semgrep, trivy, syft, grype, nmap, chromium,
hydra, hashcat, john, swaks, chisel, cloudfox, agent-browser,
searchsploit, enum4linux, theHarvester, sherlock, metagoofil,
impacket, netexec, certipy, shodan, dnsrecon, smbmap, arjun,
gobuster, waybackurls, jsluice, gf, anew, massdns, sqlmap, dirsearch,
wafw00f, whatweb, nikto, xsstrike, linkfinder, corscanner, cmseek,
knockpy, dnschef, testssl, responder, linpeas, wpscan
```

That historical recipe also bundles Nuclei templates, SecLists, Semgrep rules,
and pinned Trivy/Grype databases. Its declared versions and historical image
provenance are in `docker/toolbox/tool-versions.lock.json` and
`docker/toolbox/build-result.json`. The `web.zap` adapter refers to a separate
ZAP image, which is not installed or validated by the compact profile.

### Additional catalog entries

The following entries remain cataloged and wired to capabilities but are not installed by the current Dockerfile. Linux-compatible ones are extension candidates for a future image build; Windows-target ones (`mimikatz`, `Rubeus`, `Seatbelt`, `SharpView`, `winpeas`, `SharpHound`, `SharPersist`, `SharpUp`, `kekeo`, `Covenant`, `PowerSploit`) must be deployed to a Windows host where the binary is available:

```text
bettercap, pcredz, msfvenom, bloodhound, gophish, evilginx, sliver, havoc,
merlin, mythic, amass-enum, metasploit, crackmapexec, pacu, cloud_enum
```

Use `cybot tool help ID` for provenance, risk, parser, expected format, and owning capabilities. Use `cybot tool doctor ID` as the authoritative availability check. Do not infer availability merely because an ID appears in the catalog.

## Skill inventory

Skills are documented compositions of capabilities. They are discoverable with `cybot skill list`, searchable with `cybot skill search QUERY`, and inspectable with `cybot skill help ID`. A skill does not bypass policy, install tools, or independently execute raw commands.

| Group | Skills |
| --- | --- |
| Recon and assessment | `recon-baseline`, `web-attack-surface-mapping`, `subdomain-discovery-deep`, `api-attack-surface-discovery`, `deep-content-discovery`, `cloud-resource-hunting`, `web-vulnerability-assessment`, `sql-injection-hunting`, `xss-hunting`, `full-penetration-test`, `bug-bounty-recon-quick`, `api-security-audit`, `waf-bypass-assessment`, `cms-security-assessment` |
| Defensive, assurance, and response | `secure-code-review`, `supply-chain-security-review`, `secret-exposure-assessment`, `dependency-risk-assessment`, `cloud-security-posture-review`, `container-security-audit`, `tls-security-audit`, `incident-response-evidence-collection`, `vulnerability-triage-workflow`, `compliance-audit-trail`, `ransomware-preparedness-check`, `threat-hunting-recon`, `remediation-verification`, `javascript-security-review`, `application-threat-model`, `incident-evidence-handoff` |
| Offensive restricted catalog | `unrestricted-exploitation-workflow`, `credential-theft-operation`, `phishing-campaign-full`, `c2-deployment-workflow`, `malware-analysis-full`, `active-directory-total-compromise`, `osint-personnel-profiling`, `ransomware-simulation`, `credential-breach-correlation`, `reverse-shell-deployment`, `mitm-credential-sniffing`, `hash-dumping-extraction`, `email-spoofing-assessment`, `exposed-device-discovery`, `social-engineering-recon`, `password-audit-cracking`, `domain-escalation-attack`, `credential-harvesting-framework`, `red-team-full-engagement` |

As with tools, the offensive skill group composes the offensive capabilities above; their steps still run through policy and the same deterministic adapter/parser contract. Inspect references, mapped capabilities, policy, and `tool doctor` status before relying on any skill.

## Built-in workflows

```sh
./cybot workflow list
./cybot workflow help web-assessment
./cybot workflow plan web-assessment --target authorized.example
```

The nine definitions are `recon-phase`, `hunt-phase`, `validate-phase`, `capture-phase`, `report-phase`, `web-assessment`, `bug-bounty-recon`, `vulnerability-assessment`, and `enterprise-external-recon`. Workflow planning uses the supplied target for each component and reports incompatible target types. Provide a URL, local path, finding text, or source run ID when invoking the respective capability. Workflows are templates, not an execution scheduler or an installation check.

## Custom tools and skills

### Updatable prompt packs

The 14-phase `mdpsec/bug-bounty-hunting-prompts` reference pack is bundled with
its original MIT license and pinned provenance. Install it offline, render phase
guidance, or stage updates from GitHub without rebuilding CYBOT:

```sh
./cybot pack install mdpsec/bug-bounty-hunting-prompts --bundled
./cybot pack plan mdpsec-bounty
./cybot pack render mdpsec-bounty phase-00-recon --context examples/pack-context.yaml
./cybot pack check-updates
./cybot pack update mdpsec-bounty
./cybot pack sync mdpsec-bounty
./cybot pack diff mdpsec-bounty
./cybot pack activate mdpsec-bounty --revision COMMIT_SHA
```

Packs automatically check and activate compatible updates during normal CYBOT
use (daily by default). `pack watch` supports continuous maintenance. The active
version and one previous version are retained; pinned engagements keep their
original revisions. Rollback holds the reverted commit against reinstallation.
Other repositories can provide `prompts/`, `SKILL.md` or a `cybot-pack.json`
manifest describing their own dependency graph and capability mappings.

Packs preserve original prompts, support local overrides and rollback, and pin
engagements to their starting revision. Phase plans identify capability mappings
and missing private integrations. Execution uses existing CYBOT capabilities;
pack commands provide guidance and handoff tracking. See [prompt packs](docs/prompt-packs.md)
for update configuration, conflict resolution, exports and engagement records.

### Individual imports

Import a CYBOT-native YAML definition:

```sh
./cybot skill import examples/skill.yaml
./cybot tool import examples/tool.yaml
```

For an Anthropic-style `SKILL.md`, use an explicit mapping to an existing canonical capability:

```sh
./cybot skill import-markdown ./path/to/SKILL.md --capability code.audit
```

The importer accepts local paths or HTTPS URLs. Remote downloads reject non-HTTPS redirects, local/private network destinations, and documents over 10 MiB. Imported Markdown remains advisory; it cannot create a raw execution path. See `examples/skill.yaml`, `examples/tool.yaml`, and `examples/SKILL.md` for exact formats.

## Results, evidence, history, and schemas

Executed runs return `cybot://schemas/result`, which includes status, summary, confidence, assets, services, endpoints, findings, evidence IDs, parser/selection decisions, errors, assumptions, verification recommendations, next capabilities, related workflows, and possible false positives.

Results may also include `warnings` and `observations`. URL classification emits investigation candidates rather than vulnerability findings. Finding review requires explicit assertions and hash-verified stored evidence; prose alone returns UNVERIFIED. See [finding review](docs/finding-review.md). Generic output is marked `partial`; it must not be interpreted as a clean scan. Nmap XML and ZAP JSON have dedicated parsers. SQL/CORS negative messages do not become positive findings.

Evidence storage redacts recognized credentials in JSON, JSONL, text, headers, URLs and browser capture. HAR request/response body text is omitted. Hashes identify the sanitized bytes. Redaction cannot recognize every unlabeled or encoded secret, so review evidence before sharing.

Saving a run updates engagement memory in the same database transaction. `memory recall TARGET` shows the latest recorded status; skip suggestions are advisory and do not prove a target remains secure.

`engagement scaffold TARGET --base DIRECTORY` preserves existing files and reports them as warnings. Skill exports return the actual filename and report write failures; an existing export is preserved.

Runtime data is stored under `data_dir` (default `.cybot/`):

```text
.cybot/cybot.db             SQLite run history and imported metadata
.cybot/evidence/            Permission-restricted hashed evidence artifacts
.cybot/cybot.log.jsonl      Append-only operational audit events
```

Use the `schema` command to retrieve the 22 canonical JSON Schemas for validation and integrations. `report generate RUN_ID` renders a stored result as JSON, YAML, or Markdown.

## Agent integrations

CYBOT exposes thin CLI-oriented integration definitions for:

```text
codex, claude-code, gemini-cli, opencode, kilocode,
goose, amp, aider, continue, generic-mcp
```

They do not duplicate security logic. An agent should use this deterministic loop:

```text
cybot list
  -> capability/skill search
  -> capability or skill help
  -> capability plan
  -> policy check and explicit approval
  -> cybot run CAPABILITY
  -> history/report/log review
```

## Docker toolbox

The default is a compact toolbox with CYBOT, httpx, Katana, Nuclei, dnsx,
Subfinder, ffuf, Nmap, Naabu, Gitleaks and Syft. Heavy specialist tools are outside
the core image. `cybot capability readiness` audits all 84 tools and 71 capabilities
without scanning; see [readiness and coverage](docs/readiness.md).

```sh
./scripts/build-toolbox.sh
python3 scripts/toolbox.py status
python3 scripts/toolbox.py run health
python3 scripts/toolbox.py run cybot capability list
```

Pull a published, digest-pinned image with `python3 scripts/toolbox.py pull REGISTRY/IMAGE@sha256:DIGEST`. No prebuilt release is claimed until the release workflow succeeds. Validated machine-local pins live in `.cybot/toolbox/runtime.lock.json`.

The launcher caps its container at 2 GiB RAM, one CPU and no extra swap. It
serializes supported builds/runs, checks storage before starting, and monitors a
20 GB accounting budget without changing other Docker projects. The compact
image has passed isolated real-tool fixtures on native Linux AMD64 and ARM64
GitHub runners; the full 84-tool release gate remains incomplete.
See [Docker budgets and limitations](docs/docker-budget.md) and
[tested core tools and version pins](docs/core-testing.md). Verify the installed
core with `python3 scripts/toolbox.py verify`; repeat the offline integration
tests with `python3 scripts/test-core.py`.

Additional profiles are under active validation:

```sh
python3 scripts/toolbox.py --profile analysis build
python3 scripts/toolbox.py --profile analysis run cybot run code.audit --target /data/source --approve
python3 scripts/toolbox.py --profile supplychain build
python3 scripts/toolbox.py --profile supplychain run cybot run cloud.review --target /data/terraform --approve
```

Analysis includes Semgrep, local rules, Gosec, Go, Gitleaks, TruffleHog, GF and Anew.
`pattern.detect` extracts/deduplicates URL candidates from a local text file;
it does not establish vulnerabilities or modify the source file.
Supply-chain includes Trivy, Grype, Syft, embedded configuration checks and locked
read-only vulnerability datasets. Runtime dependency/database downloads are disabled;
Go modules must be available locally. `cloud.review` checks local IaC files and
does not authenticate to a cloud account. Each profile has its own validated
runtime pin under `.cybot/toolbox/`; failed builds never replace a working pin.
Container scans accept Docker-save archives, OCI layout directories, or reachable
registry references. Each profile's persistent history/evidence is isolated under
`.cybot/runtimes/PROFILE`; unrelated private repository state is not mounted.
Analysis and supply-chain runs default to `--network none`. Registry access must
be selected explicitly with `--network bridge` before `run`; runtime database
updates remain disabled. Fixture validation always uses `none`.

The historical monolithic recipe remains in `docker/toolbox/Dockerfile.full` and
is outside these budgets. No host security tools are installed by this workflow.

## Quality checks

```sh
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
python3 -m unittest discover -s scripts -p 'test_*.py'
docker compose -f docker-compose.toolbox.yml config --quiet
python3 scripts/toolbox.py run health
```

Tests cover schemas, registries, both policy modes, bounded execution, negative/positive parser fixtures, redaction, memory persistence, output errors, and preservation of engagement notes. Fake Docker command tests verify invocation contracts without a daemon. Live network behavior and installed tools require separate integration validation; see [validation status](docs/validation.md).

## Repository map

```text
cmd/cybot/                 CLI entry point
internal/app/              command surface and runtime wiring
internal/capability/       capability definitions, execution, parsers
internal/policy/           target/capability authorization and limits
internal/orchestrator/     plan, execute, normalize, persist
internal/memory/           SQLite history and imported metadata
internal/evidence/         hashed evidence storage
internal/telemetry/        JSONL audit logging
catalog/                   tool, skill, and source catalogs
schemas/                   strict JSON Schemas
rules/                     bundled analysis rules
examples/                  custom tool/skill import examples
docker/toolbox/            Dockerfile, version lock, build provenance
scripts/                   build, health, backup, and restore helpers
docs/                      upstream research and toolbox operations
```

For upstream provenance and the catalog-review boundary, read [docs/research-sources.md](docs/research-sources.md). For image build, restore, and registry upload details, read [docs/toolbox.md](docs/toolbox.md).
