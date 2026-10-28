# CYBOT Roadmap

## Current foundation

- Versioned prompt/skill packs with manifest-based integration, automatic GitHub updates, one previous revision for rollback, revision-scoped overrides, update leases and pinned phase handoffs
- 71 registered capability definitions, 84 discoverable tools, 49 skills, and 9 workflow templates
- Schema validation, evidence, audit logs, and SQLite history/engagement memory
- Warning-only policy by default; strict enforcement when explicitly selected
- Native and Docker execution adapters and CLI integration definitions
- Regression fixtures for negative findings, Nmap XML, ZAP JSON, generic observations, redaction, saved notes, config handling, and persistence errors

Registration and metadata stability do not certify tool compatibility. Generic parsers retain observations with partial status. Docker and live target validation are separate gates; historical build records are not current health checks. See [validation status](docs/validation.md).

## Next: authorized integration validation and release hardening

1. Run network capabilities against a dedicated, explicitly authorized lab target and retain golden outputs.
2. Add AMD64 validation and publish a multi-architecture manifest only after parity checks pass.
3. Add signed image provenance and an external registry digest to the lock record.
4. Expand negative fixtures for tool regressions, truncation, timeout, and incompatible-version behavior.
5. Add richer report renderers without changing the normalized internal result contract.

## Planned: project structure and user distribution

Recorded on 2026-10-21. See [the structure and release plan](docs/release-plan.md).

Keep the current Go package boundaries, split oversized command/parser files as
needed, and ship a versioned CLI plus a compatible prebuilt Docker toolbox.
Before release, settle project licensing and registry ownership, implement clear
Docker-first routing, validate supported platforms/capabilities, automate release
artifacts, and test clean installation, persistent storage, upgrades and rollback.
CLI, container and prompt updates need distinct compatibility and recovery rules.

## Planned: Docker-first execution with configurable local fallback

Recorded on 2026-10-21. Requirements only; implementation is deferred at the user's request.

- Keep Docker as the primary execution environment. Normal Docker use must not require installing security tools on the host.
- Add an explicit local fallback for cases where Docker or a required container tool is unavailable.
- Provide two local modes: **available tools only**, which never installs anything, and **allow installation**, which can install supported missing tools when enabled.
- Expose the selected runtime, fallback decision, missing dependencies and installation eligibility clearly to AI agents through plans and diagnostics.
- Check operating-system compatibility and tool prerequisites before selecting a fallback; preserve explicit limitations when a tool has no usable local equivalent.
- Test Docker execution, Docker-unavailable fallback, both local modes, installation failures, unsupported platforms and equivalent normalized results using fixtures and an authorized lab where needed.
- Treat inventory registration, detected availability and successful end-to-end execution as separate statuses.

## Explicitly deferred: model-provider credentials

OpenAI and DeepSeek API-key support is a future request. It is not implemented, and CYBOT currently reads, stores, transmits, or logs no model-provider credentials.

Before implementation, design and review OS keychain or external secret-manager storage, redaction, provider allowlists, budgets, timeouts, audit events, and an offline mode. Keys must never enter YAML, SQLite, evidence, logs, reports, or subprocess arguments.

The provider layer must remain optional advisory reasoning. Capability selection, authorization, execution, normalization, and verification stay deterministic.
