#!/bin/sh
set -eu
mkdir -p "$HOME/.config/gf"
cp /opt/cybot/rules/gf/cybot-urls.json "$HOME/.config/gf/cybot-urls.json"
case "${1:-help}" in
  health)
    for tool in cybot semgrep gosec go gitleaks trufflehog gf anew; do
      command -v "$tool" >/dev/null || exit 1
      printf 'ok\t%s\n' "$tool"
    done
    test -s /opt/cybot/rules/semgrep-security.yaml
    ;;
  versions) cat /opt/cybot/manifest/analysis.lock.json ;;
  cybot) shift; exec /opt/cybot/bin/cybot "$@" ;;
  exec) shift; exec "$@" ;;
  shell) exec /bin/sh ;;
  help) printf '%s\n' 'CYBOT Analysis: cybot, health, versions, exec, shell.' 'Pinned Semgrep, Gosec, Go SDK, Gitleaks, TruffleHog, GF and Anew.' 'Go dependencies must already be available locally; runtime downloads are disabled.' ;;
  *) printf 'Unknown command: %s\n' "$1" >&2; exit 2 ;;
esac
