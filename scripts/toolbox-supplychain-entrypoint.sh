#!/bin/sh
set -eu
case "${1:-help}" in
  health)
    for tool in cybot trivy syft; do command -v "$tool" >/dev/null; printf 'ok\t%s\n' "$tool"; done
    test -s /opt/cybot/share/trivy/db/trivy.db
    test -s /opt/cybot/share/trivy/db/metadata.json
    ;;
  versions) cat /opt/cybot/manifest/supplychain.lock.json ;;
  cybot) shift; exec /opt/cybot/bin/cybot "$@" ;;
  exec) shift; exec "$@" ;;
  shell) exec /bin/sh ;;
  help) printf '%s\n' 'CYBOT Supply Chain: cybot, health, versions, exec, shell.' 'Pinned Trivy, Syft and an immutable vulnerability database; embedded IaC checks.' 'Grype and the Java vulnerability database are separate dependencies.' ;;
  *) printf 'Unknown command: %s\n' "$1" >&2; exit 2 ;;
esac
