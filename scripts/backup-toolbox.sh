#!/usr/bin/env bash
set -euo pipefail

image="${CYBOT_TOOLBOX_IMAGE:-cybotainer:2026.08.9-arm64}"
destination="${1:-backups/cybot-toolbox-2026.08.9-arm64.tar.gz}"
mkdir -p "$(dirname "$destination")"

docker image inspect "$image" >/dev/null
docker save "$image" | gzip -9 > "$destination"
archive_dir="$(cd "$(dirname "$destination")" && pwd)"
archive_name="$(basename "$destination")"
(
  cd "$archive_dir"
  shasum -a 256 "$archive_name" > "${archive_name}.sha256"
)

echo "Backup: $destination"
echo "Checksum: ${destination}.sha256"
