#!/bin/sh
set -eu
case "${1:-help}" in
  health)
    for tool in cybot trivy syft grype; do command -v "$tool" >/dev/null; printf 'ok\t%s\n' "$tool"; done
    test -s "$CYBOT_TRIVY_CACHE_DIR/db/trivy.db"
    test -s "$CYBOT_TRIVY_CACHE_DIR/db/metadata.json"
    test -s "$GRYPE_DB_CACHE_DIR/6/vulnerability.db"
    test -s "$GRYPE_DB_CACHE_DIR/6/import.json"
    ;;
  versions) cat /opt/cybot/manifest/supplychain.lock.json ;;
  cybot) shift; exec /opt/cybot/bin/cybot "$@" ;;
  exec) shift; exec "$@" ;;
  shell) exec /bin/sh ;;
  help) printf '%s\n' 'CYBOT Supply Chain: cybot, health, versions, exec, shell.' 'Pinned Trivy, Grype, Syft and immutable vulnerability datasets; embedded IaC checks.' 'The Java vulnerability database is a separate dependency.' ;;
  *) printf 'Unknown command: %s\n' "$1" >&2; exit 2 ;;
esac
