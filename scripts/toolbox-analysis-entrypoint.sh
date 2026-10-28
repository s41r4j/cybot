#!/bin/sh
set -eu
case "${1:-help}" in
  health)
    for tool in cybot semgrep gosec go gitleaks trufflehog; do
      command -v "$tool" >/dev/null || exit 1
      printf 'ok\t%s\n' "$tool"
    done
    test -s /opt/cybot/rules/semgrep-security.yaml
    ;;
  versions) cat /opt/cybot/manifest/analysis.lock.json ;;
  cybot) shift; exec /opt/cybot/bin/cybot "$@" ;;
  exec) shift; exec "$@" ;;
  shell) exec /bin/sh ;;
  help) printf '%s\n' 'CYBOT Analysis: cybot, health, versions, exec, shell.' 'Pinned Semgrep, local security rules, Gosec, Go SDK, Gitleaks and TruffleHog.' 'Go dependencies must already be available locally; runtime downloads are disabled.' ;;
  *) printf 'Unknown command: %s\n' "$1" >&2; exit 2 ;;
esac
