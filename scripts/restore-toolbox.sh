#!/usr/bin/env bash
set -euo pipefail

archive="${1:?usage: scripts/restore-toolbox.sh BACKUP.tar.gz}"
checksum="${archive}.sha256"

if [[ -f "$checksum" ]]; then
  expected="$(awk 'NR == 1 { print $1 }' "$checksum")"
  actual="$(shasum -a 256 "$archive" | awk '{ print $1 }')"
  [[ -n "$expected" && "$actual" == "$expected" ]] || {
    echo "backup checksum mismatch" >&2
    exit 1
  }
  echo "$archive: OK"
fi

gzip -dc "$archive" | docker load
image="${CYBOT_TOOLBOX_IMAGE:-cybotainer:2026.08.9-arm64}"
docker image inspect "$image" --format 'restored {{.RepoTags}} {{.Id}}'
