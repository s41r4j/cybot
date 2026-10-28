# Docker toolbox

> Historical snapshot. Current source repairs, CI and release limitations are recorded in [release-status.md](release-status.md). Machine-local runtime pins now live under `.cybot/toolbox/`; older image IDs do not constitute a published download.

The default is the compact core image. Read [Docker budgets and operation](docker-budget.md)
for its resource limits, build process, supported commands, storage checks, and
current validation limits.

```sh
./scripts/build-toolbox.sh
python3 scripts/toolbox.py status
python3 scripts/toolbox.py run health
python3 scripts/toolbox.py run cybot capability list
python3 scripts/toolbox.py run cybot capability readiness
python3 scripts/toolbox.py verify
python3 scripts/test-core.py
```

The image contains CYBOT, httpx, Katana, Nuclei, dnsx, Subfinder, ffuf, Nmap,
Naabu, Gitleaks and Syft.
The rest of the capability catalog remains discoverable but needs its tools
installed separately; no automatic specialist-bundle installer is implied.

The launcher uses an immutable local image ID, with binary hashes and package
revisions in `docker/toolbox/core-runtime.lock.json`. Source archives and data
are pinned in `docker/toolbox/core.lock.json`. See [core testing](core-testing.md)
for exact coverage and remaining gaps. `tool doctor` checks availability;
`toolbox.py verify` checks the core runtime versions and hashes.

The [historical full toolbox records](toolbox-full-history.md) preserve the old
image and backup identities. That full recipe is no longer the default and does
not meet the compact profile's resource budget.

Build candidates must pass offline integration tests before activation. See
[readiness and coverage](readiness.md) for the full catalog audit.
