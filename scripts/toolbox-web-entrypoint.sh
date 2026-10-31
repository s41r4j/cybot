#!/bin/sh
set -eu
action="${1:-help}"
shift || true
case "$action" in
  cybot) exec /opt/cybot/bin/cybot "$@" ;;
  exec) exec "$@" ;;
  shell) exec /bin/sh "$@" ;;
  health)
    for tool in cybot httpx ffuf gobuster whatweb wafw00f corscanner dirsearch ruby python3; do
      command -v "$tool" >/dev/null || { echo "Missing web runtime dependency: $tool" >&2; exit 1; }
    done
    echo 'Web runtime executables are present; real operation validation is separate.' ;;
  versions)
    cybot --version
    httpx -version
    ffuf -V
    gobuster --version
    whatweb --version
    wafw00f --version
    corscanner --version
    dirsearch --version ;;
  help) echo 'CYBOT web toolbox: cybot | exec | health | versions | shell' ;;
  *) echo "Unsupported web entrypoint action: $action" >&2; exit 2 ;;
esac
