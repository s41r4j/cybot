# Compact Docker operation

The default toolbox is the `core` profile. CYBOT remains a deterministic CLI;
this image contains no AI model. Use a tool-enabled external agent to call it.

## Default budgets

| Resource | Enforcement |
| --- | --- |
| Tool container memory | 2 GiB hard cgroup limit, no extra swap |
| Tool container CPU | One CPU maximum |
| Processes | 256 per container |
| Concurrent containers | Supported helper builds and runs are serialized; the Docker container name also blocks overlapping adapter runs |
| Temporary files | 128 MiB each for `/tmp` and cache; 16 MiB configuration tmpfs |
| Captured tool output | 8 MiB stdout, 1 MiB stderr; overflow cancels the command and fails explicitly |
| Individual output file | 64 MiB in the compact launcher and Compose configuration |
| Default orchestration | One tool step at a time; web tool internal parallelism is also reduced |
| Image acceptance | No more than 3 GB using the larger of inspected and on-disk image sizes |
| Build container | Dedicated builder, 1 GiB RAM including swap, one CPU, one build step at a time |
| Storage admission | 20 GB total accounting ceiling with 2 GB reserved before runs and 4 GB before builds |
| Host free space | Preserve at least 10 GB, plus the operation's reserve at admission |

RAM and image size use different measures: Docker's `2g` is 2 GiB, approximately
2.15 decimal GB. The intended operating budget is 2–3 GB including overhead.
The launcher cannot impose a total Docker Desktop memory cap without affecting
other projects. It checks VM headroom and caps its own container; it does not
change global Docker settings. A demanding scan can fail its limit instead of
being allowed to consume unlimited memory.

Storage accounting conservatively includes **all Docker images, containers,
volumes and build cache**, plus this repository's `.cybot`, `reports` and
`backups` directories. On macOS it also accounts for allocated blocks in the
standard Docker Desktop disk image, using the larger value. A 1 TB sparse disk's
logical size is not its actual disk consumption. External input data is not
copied into the image. Custom Docker disk locations are not measured as raw
files; Docker's inventory still counts their managed objects.

Storage checks are admission and periodic monitoring, **not filesystem quotas**.
They stop only the operation launched by this helper when the reserve is reached.
Other projects can grow independently, and raw `docker run` commands can bypass
the launcher. A strict machine-wide 20 GB quota would also constrain other Docker
projects, so it is deliberately not changed. No unrelated container is stopped
or image, cache, volume or data directory pruned.

## Build and use

For development, Python 3, Go matching `go.mod`, and a local Docker Unix engine
are required. Published images will not require end users to compile tools.

```sh
python3 scripts/toolbox.py status
./scripts/build-toolbox.sh
python3 scripts/toolbox.py run health
python3 scripts/toolbox.py run cybot capability list
python3 scripts/toolbox.py run cybot capability plan web.map --target https://lab.example
```

`run` accepts the core entrypoint commands: `cybot`, `exec`, `health`, `versions`,
`help`, and a noninteractive `shell`. It never implicitly pulls an image. It
mounts `data` read-only and persists reports/state through `reports` and `.cybot`.
On Linux, those directories must be writable by container UID 10001. Existing
named volumes from the old toolbox are preserved; they are not migrated or deleted.

The helper uses a temporary, allowlisted build context containing runtime assets,
not the repository. Downloads are pinned by version, length and SHA-256 in
`docker/toolbox/core.lock.json`. It strips archive content down to binaries and
license notices, retains only the common web wordlist, and includes pinned Nuclei
templates. Go compilation is serial with a private disposable cache and a soft
512 MiB Go memory target; that host compiler target is not an OS hard memory cap.
Only the runtime enters the final Debian image. Direct Debian package revisions
are pinned and checked against the source lock. Builds fail if those revisions
are no longer available; transitive package resolution still uses Debian's
repositories. This is not yet a fully reproducible release build.

Runs use the immutable local image ID in `.cybot/toolbox/runtime.lock.json`, which also
records binary SHA-256 values and installed package revisions. `python3
scripts/toolbox.py verify` compares the installed runtime against those locks.
Tags are retained for convenience and rollback but do not select the default
runtime. Image IDs are local pins, not published registry digests.

## Image backup and restore

Back up only a validated profile pin, then restore its checksummed directory:

```sh
python3 scripts/toolbox.py --profile core backup backups/core-snapshot
python3 scripts/toolbox.py --profile core restore backups/core-snapshot
```

The backup publishes `image.tar.gz` and a required `manifest.json` together. It
records the exact image ID, architecture, profile, binary hashes and archive
checksum. Backups stay within the workspace's accounted `backups/` directory;
existing destinations are preserved. Archive creation is bounded and uses the
same operation lock and storage admission as other toolbox operations.

Restore rejects missing manifests, changed bytes, the wrong platform/profile,
path escapes, multiple images and tag-bearing archives before Docker load. It
measures the loaded image and reruns real-operation fixtures before changing the
active pin. A failed validation keeps the previous pin. A checksum detects
changed bytes; it does not authenticate an untrusted backup's publisher.

These are **image-only** backups. Existing configuration, evidence, reports and
external vulnerability databases remain in their current directories and need
their own data-backup strategy. Supply-chain restores require the matching
verified external datasets to be present. Legacy full-image `.tar.gz` files
without this manifest are not accepted by the current restore helper. CI runs
the compact-core backup/restore path on both native Linux architectures.

The helper checks versions/hashes and runs the offline integration suite on a candidate before tagging it active and retains the previous
active image under the `-previous` tag. Space for the candidate and previous image
must fit the admission budget. Temporary archives, compiler cache and the private
builder/cache are removed after the build. No global prune command is used.

The Compose file requires an explicit image pin and applies the same container resource caps:

```sh
CYBOT_IMAGE="$(python3 scripts/toolbox.py image)" docker compose -f docker-compose.toolbox.yml config
```

Prefer the Python
launcher for disk monitoring and the launch lock: `docker compose run` can create
additional one-off containers, bypassing `container_name` concurrency protection.
Direct Go Docker adapters also cap their containers, refuse implicit pulls, use
the shared run name, bound output, and remove their exact container on completion
or cancellation. Their arbitrary caller-supplied mounts do not have a filesystem
quota and do not invoke the Python storage monitor.

## Included and optional tools

Core includes CYBOT, httpx, Katana (non-headless), Nuclei, dnsx, Subfinder, ffuf,
Nmap, Naabu, Gitleaks and Syft. Heavy browser, code-analysis, cloud and specialist toolchains remain
outside core; availability checks must report them missing. Catalog membership
does not claim installation. The historical full build recipe is retained as
`docker/toolbox/Dockerfile.full`; it is **outside these budgets** and is not used
by the default build helper or Compose configuration. Automatic optional-bundle
installation and host-tool fallback are not implemented by this change.

## Cleanup

First inspect `docker system df -v`. An unreferenced volume or stopped container
can still contain valuable project data. The helper cleans only the temporary
assets and builder it creates. Preserve the active/previous images and state.
Before removing any other object, identify its owner and purpose. There is no
automatic deletion of evidence or reports to satisfy the budget; further work is
refused when space is insufficient.

## References

- [Docker container resource limits](https://docs.docker.com/engine/containers/resource_constraints/)
- [Dedicated builder resource limits](https://docs.docker.com/build/builders/drivers/docker-container/)
- [Docker Desktop disk usage](https://docs.docker.com/desktop/troubleshoot-and-support/faqs/macfaqs/)

## Validation on 2026-10-22

- Built and ran the ARM64 core image on Docker Desktop. AMD64 downloads are
  locked but an AMD64 image was not run in this session.
- All eleven core executables were found. The dnsx archive is verified against
  the official v1.3.0 release hash, but its embedded version command prints
  1.2.3; do not claim exact runtime-version parity for that binary.
- A local HTTP fixture completed `web.map` with both httpx and Katana and
  returned three endpoints. Highest sampled container memory was about 27 MiB;
  this is a small fixture, not a worst-case memory benchmark.
- Nuclei matched a harmless local marker template. This verifies the executable
  and local HTTP path, not every bundled template or the full `web.scan` workload.
- Live cgroups reported memory.max=2147483648, memory.swap.max=0,
  cpu.max="100000 100000" and pids.max=256.
- A second launch was refused while the first stayed running. Interrupting the
  launcher removed its own container. A Go-runner timeout also removed its
  exact container, verified against the live engine.
- Go tests and vet, Python budget/integrity/locking tests, shell syntax and
  Compose validation passed. No external website was scanned.
- The dedicated builder and its cache were removed; its newly downloaded
  BuildKit image was removed too. Existing project containers and volumes were
  preserved. There was no pre-existing build cache to reclaim.
