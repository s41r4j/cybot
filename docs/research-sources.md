# Curated upstream research

CYBOT metadata is derived from authoritative upstream projects and preserves the source URL in every tool entry.

- ProjectDiscovery: subfinder, dnsx, naabu, httpx, katana, nuclei — https://github.com/projectdiscovery
- OWASP Amass — https://github.com/owasp-amass/amass
- Gitleaks — https://github.com/gitleaks/gitleaks
- TruffleHog — https://github.com/trufflesecurity/trufflehog
- gosec — https://github.com/securego/gosec
- Semgrep — https://github.com/semgrep/semgrep
- Trivy — https://github.com/aquasecurity/trivy
- Syft — https://github.com/anchore/syft
- ffuf — https://github.com/ffuf/ffuf
- Official MCP Go SDK — https://github.com/modelcontextprotocol/go-sdk
- Anthropic Agent Skills — https://github.com/anthropics/skills
- Anthropic Cybersecurity Skills — https://github.com/mukul975/Anthropic-Cybersecurity-Skills (Apache-2.0; reviewed at `e612f4944c55d306bb75565022442d7da8cf2b9a`)
- wshobson Agent Skills — https://github.com/wshobson/agents (reviewed at `c4b82b0ad771190355eb8e204b1329732a18449a`)

Some declared versions are `unresolved` or use floating image tags. These produce reproducibility warnings. Tool doctor checks binary/image presence and reports that version verification was not performed. Strict policy is optional; generic parsers retain unverified observations. Source references identify provenance, not current installation or accuracy.

## Curated skill policy

CYBOT bundles normalized skill metadata across defensive review, reconnaissance, assessment, and offensive categories. Each bundled skill contains capability-only steps, JSON-schema-backed CYBOT metadata, examples, requirements, and commit-pinned provenance. The source libraries were reviewed for useful patterns, but their scripts and raw commands were not imported.

The catalog includes offensive workflow metadata. These entries must not be presented as independently validated functionality. Imported user `SKILL.md` content also remains advisory until explicitly mapped to an existing CYBOT capability, so it cannot create an unreviewed execution path.
