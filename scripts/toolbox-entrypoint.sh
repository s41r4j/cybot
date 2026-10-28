#!/usr/bin/env bash
set -euo pipefail

trivy_cache="${TRIVY_CACHE_DIR:-/home/cybot/.cache/trivy}"
trivy_bundled="${TRIVY_BUNDLED_CACHE_DIR:-/opt/cybot/share/trivy-cache}"
mkdir -p "$trivy_cache"
if [[ ! -f "$trivy_cache/db/metadata.json" ]]; then
  if [[ -e "$trivy_cache/db" || -L "$trivy_cache/db" ]]; then
    echo "Trivy runtime cache contains an incomplete db entry: $trivy_cache/db" >&2
    exit 1
  fi
  ln -s "$trivy_bundled/db" "$trivy_cache/db"
fi

case "${1:-help}" in
  help)
    cat <<'EOF'
CYBOT Toolbox

  cybot-toolbox help       Show this help
  cybot-toolbox health     Check every installed binary
  cybot-toolbox versions   Print the pinned lock manifest
  cybot-toolbox shell      Open an interactive shell
  cybot-toolbox cybot ...  Run the CYBOT CLI
  cybot-toolbox exec ...   Run an internal tool (normally CYBOT does this)

Mount authorized targets read-only at /data and reports at /reports.
EOF
    ;;
  health)
    shift
    exec /usr/local/bin/cybot-toolbox-health "$@"
    ;;
  versions)
    exec jq . /opt/cybot/manifest/tool-versions.lock.json
    ;;
  shell)
    exec /bin/bash
    ;;
  cybot)
    shift
    exec /opt/cybot/bin/cybot "$@"
    ;;
  exec)
    shift
    if [[ $# -eq 0 ]]; then
      echo "exec requires a command" >&2
      exit 2
    fi
    exec "$@"
    ;;
  *)
    echo "unknown toolbox command: $1" >&2
    exit 2
    ;;
esac
