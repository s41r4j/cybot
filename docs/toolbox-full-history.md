# CYBOT monolithic toolbox image

> The default is now the budgeted **core** profile. See [compact Docker operation](docker-budget.md) for current commands, limits and included tools. The full-image records and build requirements below are historical; the full recipe is now `Dockerfile.full` and is not the default.

CYBOT uses one persistent image containing the core executable, security tools, parsers' upstream binaries, Nuclei templates, SecLists, Semgrep rules, and pinned Trivy/Grype vulnerability databases:

```text
cybotainer:2026.08.9-arm64
```

The local ARM64 tag is intended for this Mac. Build an AMD64 variant on an AMD64 builder before publishing a multi-architecture registry tag.

The historical build is recorded in `docker/toolbox/build-result.json`. Its recorded identity is:

```text
image:  cybotainer:2026.08.9-arm64
digest: sha256:d9bb1758c781ef1ea60700db615d38a2af6fbc247f58ec608308d24a4ab8013e
size:   8,651,349,760 bytes
```

## Build

Docker Desktop should have at least 8 GB memory and 40 GB free storage. For a clean first build, budget roughly 10–15 GB of internet transfer; registry caching, vulnerability-database size, and upstream dependency changes can move that number. Rebuilds reuse Docker layers and normally require much less. From the repository root:

```sh
chmod +x scripts/*.sh
# Historical full build recipe: docker/toolbox/Dockerfile.full
# Not executed by the current budgeted helper.
```

The build is fail-closed: if a pinned tool cannot compile or install, Docker does not produce the final tag. The image is not pruned or deleted by any project script.

## Validate installation

The health command checks that every binary and bundled data directory exists. It does not scan a target:

```sh
docker run --rm --network none cybotainer:2026.08.9-arm64 health
docker run --rm --network none cybotainer:2026.08.9-arm64 versions
```

## Operate safely

Create `data/` and `reports/`, place only authorized inputs in `data/`, then use the hardened Compose profile:

```sh
mkdir -p data reports
docker compose -f docker-compose.toolbox.yml run --rm toolbox health
docker compose -f docker-compose.toolbox.yml run --rm toolbox cybot capability list
```

The Compose service is read-only, drops Linux capabilities, prevents privilege escalation, mounts input read-only, and keeps CYBOT state, reports, and runtime caches in explicit volumes. The vulnerability databases remain immutable inside the image; only transient scanner caches are writable. Capabilities requiring raw sockets need a separately reviewed profile; do not grant broad privileges to the default service.

## Backup before upload

Keep the local image and make a checksum-protected archive:

```sh
./scripts/backup-toolbox.sh
```

This creates:

```text
backups/cybot-toolbox-2026.08.9-arm64.tar.gz
backups/cybot-toolbox-2026.08.9-arm64.tar.gz.sha256
```

The historical backup record lists 8,534,595,571 bytes and the following SHA-256. Check that the archive exists and verify its checksum before restoring:

```text
fa11932ebd159a50630fdbecb1f4965417d3c61aa877bef6735c03bd844a089c
```

Restore it with:

```sh
./scripts/restore-toolbox.sh backups/cybot-toolbox-2026.08.9-arm64.tar.gz
```

Do not use `docker image prune --all`, `docker system prune --all`, or delete the tag until a verified backup or registry copy exists.

Earlier build records are retained in `docker/toolbox/build-result-*.json`. Inspect Docker to establish which images still exist locally. A source change requires a new image build before container execution reflects that change.

## Capability validation status

The latest historical record reports 71 capability plans and 58 of 84 tools available. Its recorded offline runs are `cve.lookup`, `mitre.map`, and `secret.scan`; it reports no external target scans. These records do not certify every adapter or the current source tree.

Current source regression tests exercise Nmap/XML, ZAP/JSON, browser capture redaction, generic output schemas, warning-only/strict behavior, and persistence. The fake Docker tests check invocation arguments and expected exit codes without a daemon. Live Docker checks remain separate. See [validation status](validation.md).

ZAP runs in its separate image with a writable work directory, report-file collection, and alert exit codes 1/2 treated as report-bearing results. The adapter follows the upstream [ZAP baseline contract](https://www.zaproxy.org/docs/docker/baseline-scan/). ZAP's `stable` tag floats; pin an image digest for reproducibility.

## Upload to a registry

Authenticate, tag, and push without removing the local tag:

```sh
docker login REGISTRY
docker tag cybotainer:2026.08.9-arm64 REGISTRY/OWNER/cybot-toolbox:2026.08.9-arm64
docker push REGISTRY/OWNER/cybot-toolbox:2026.08.9-arm64
docker image inspect REGISTRY/OWNER/cybot-toolbox:2026.08.9-arm64
```

Record the pushed digest in `docker/toolbox/tool-versions.lock.json`. For a multi-platform release, build ARM64 and AMD64 variants with Buildx and publish one manifest list only after both pass the same health check.

## Install or update tools

Do not install tools interactively into a running container: those changes disappear and cannot be reproduced. Instead:

1. Update the exact version in `docker/toolbox/Dockerfile`.
2. Update `docker/toolbox/tool-versions.lock.json` and `catalog/tools.yaml`.
3. Rebuild under a new date/version tag.
4. Run the binary health check and adapter fixtures.
5. Back up the new image.
6. Push it, record its registry digest, and only then activate affected capabilities.

This process makes the image—not an undocumented container—the stable artifact.
