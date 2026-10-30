#!/bin/sh
set -eu
action="${1:-help}"
shift || true
case "$action" in
  cybot) exec /opt/cybot/bin/cybot "$@" ;;
  exec) exec "$@" ;;
  shell) exec /bin/sh "$@" ;;
  health)
    for tool in cybot agent-browser chromium python3; do command -v "$tool" >/dev/null || { echo "Missing browser dependency: $tool" >&2; exit 1; }; done
    echo 'Browser executables are present; real operation validation is separate.' ;;
  versions) cybot --version; agent-browser --version; chromium --version ;;
  help) echo 'CYBOT browser toolbox: cybot | exec | health | versions | shell' ;;
  *) echo "Unsupported browser entrypoint action: $action" >&2; exit 2 ;;
esac
