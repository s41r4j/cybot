# Readiness and remaining-tool audit

> Historical snapshot. Current source repairs, CI and release limitations are recorded in [release-status.md](release-status.md). Machine-local runtime pins now live under `.cybot/toolbox/`; older image IDs do not constitute a published download.

CYBOT is a deterministic execution layer for an external agent. Catalog entries
are discoverable descriptions, not proof that a tool is installed or an adapter
performs the advertised operation.

```sh
python3 scripts/toolbox.py run cybot capability readiness
python3 scripts/toolbox.py verify
python3 scripts/test-core.py
```

The first command checks all 84 registered tools and all 71 capabilities. It runs
bounded binary-presence checks, not target scans. Its JSON is suitable for agents:

| Status | Meaning |
| --- | --- |
| `built-in` | No external tool dependency; input, policy and runtime data still matter |
| `ready-to-test` | Required executables are present and the adapter has tool-specific normalization; behavior is not certified by this status |
| `partial` | A usable adapter exists, but optional dependencies or normalization are incomplete |
| `unavailable` | Required tools are missing, unsupported on this OS, or no executable adapter is available |
| `not-implemented` | The configured calls do not implement the advertised operation |

Tool availability, adapter implementation and output normalization are separate
fields. The audit reports actual execution steps, including whether each is
required. It never labels an installed binary as a passed security assessment.
Credentialed integrations, databases, browser engines, target reachability and
Windows-specific runtimes still need their own environment-specific validation.

## Measured result on 2026-10-22

| Inventory | Count |
| --- | ---: |
| Catalog tools available in compact Docker | 11 |
| Catalog tools unavailable here | 73 |
| Capabilities ready for target-specific testing | 9 |
| Capabilities with partial tool/normalization coverage | 5 |
| Built-in capabilities | 5 |
| Capabilities unavailable here | 47 |
| Capabilities consisting of unfinished adapters | 5 |

All eleven offline integration tests passed against the freshly built image.
It is approximately **896 MB**, with **14.29 GB** total Docker/local-state
accounting after cleanup. The previous image is retained. Container limits remain
2 GiB RAM, one CPU, no extra swap; build cache is zero after cleanup.

## Changes from this audit

- Added pinned Naabu 2.6.1, Gitleaks 8.30.1 and Syft 1.50.0 after real offline
  fixture tests. Naabu uses TCP connect mode, two workers and ten probes per second.
- Gitleaks detects a synthetic token, accepts its findings exit code, redacts
  evidence and returns no findings for the clean control. The initial alphabetic
  token matched Gitleaks' documented example-token allowlist; the positive control
  now uses a synthetic value outside that allowlist. No real credentials are used.
- Syft produces a CycloneDX inventory containing the fixture package/version,
  without downloading packages or contacting registries.
- Valid JSON with an error or wrong report shape no longer becomes a clean result
  for the covered structured adapters. Endpoint reports cannot invent a URL from
  the requested target when the tool omitted it.
- WPScan now reads explicit vulnerability records rather than matching words such
  as "vulnerabilities" in negative messages. Missing API coverage remains partial.
  This parser has fixture coverage; the WPScan executable was not installed.
- Nikto's output no longer goes through the unrelated Nuclei parser. MassDNS text
  no longer goes through a JSON asset parser. Both remain observations-only until
  version-specific normalization is validated.
- Metasploit help, Covenant help, Kekeo exit, PowerSploit module listing and GF
  pattern listing return `ADAPTER_NOT_IMPLEMENTED` instead of successful execution
  of their advertised capabilities. The catalog remains discoverable.
- Amass 5.1.1's legacy adapter is explicitly incomplete. The version command passed,
  but `enum -h` tried to start the engine and hit the offline test timeout. No
  enumeration was validated, and the temporary container/binary was removed.
- New image candidates must pass the offline integration suite before tags or the
  active runtime pin change. A regression test proves failed validation does not
  promote a candidate. One previous CYBOT image is retained.

## Coverage boundaries

The full Go suite covers 83 parser handlers with an error-report regression and
61 external capabilities with missing-dependency regressions. These are contract
tests, not live certification of absent tools. The readiness inventory covers
all 84 catalog tools, including OS-specific failures. The real-binary suite covers
the compact installed set using local fixtures and disabled Docker networking;
Subfinder's check covers arguments/provider-list startup only.

The separate `assessment.lock.json` records official release URLs, lengths and
SHA-256 values for the four additional binaries inspected in this audit, including
Amass. Successful additions are also in `core.lock.json`; all installed executable
hashes are in `core-runtime.lock.json`. No host security-tool installation is used.

A single Apple Silicon Docker environment cannot validate Windows-only tools,
cloud accounts, AD domains, external reconnaissance providers or every scanner
ruleset. Those are remaining test environments, not hidden successes. Keep them
out of release-ready claims until their specific integration tests pass.

## Upstream contracts consulted

- [Amass 5.1.1 CLI and engine startup](https://github.com/owasp-amass/amass/blob/v5.1.1/cmd/amass/main.go)
- [Gitleaks 8.30.1 rules and allowlists](https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml)
- [WPScan vulnerability-report fixture](https://github.com/wpscanteam/wpscan/blob/master/spec/output/wp_version/with_vulns.json)
- [WPScan API coverage fixture](https://github.com/wpscanteam/wpscan/blob/master/spec/output/vuln_api/all_ok.json)

The measured inventory and validation results are in
`docker/toolbox/readiness-validation.json` and `docker/toolbox/core-validation.json`.
