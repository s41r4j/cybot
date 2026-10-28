#!/bin/sh
set -eu
# Nuclei's upstream ignore list belongs in its writable config directory. Keep
# it alongside the pinned templates so scans do not report a missing ignore file.
if [ -f /opt/cybot/share/nuclei-templates/.nuclei-ignore ]; then
  mkdir -p /home/cybot/.config/nuclei
  if [ ! -e /home/cybot/.config/nuclei/.nuclei-ignore ]; then
    cp /opt/cybot/share/nuclei-templates/.nuclei-ignore /home/cybot/.config/nuclei/.nuclei-ignore
  fi
fi
case "${1:-help}" in
  health)
    for tool in cybot httpx katana nuclei dnsx subfinder ffuf nmap gitleaks syft naabu; do
      command -v "$tool" >/dev/null || exit 1
      printf 'ok\t%s\n' "$tool"
    done
    test -d /opt/cybot/share/nuclei-templates/http
    test -s /opt/cybot/share/seclists/Discovery/Web-Content/common.txt
    ;;
  versions) cat /opt/cybot/manifest/core.lock.json ;;
  cybot) shift; exec /opt/cybot/bin/cybot "$@" ;;
  exec) shift; exec "$@" ;;
  shell) exec /bin/sh ;;
  help) printf '%s\n' 'CYBOT Core: cybot, health, versions, exec, shell.' 'Includes web/DNS mapping, Nuclei, content discovery, Nmap/Naabu, Gitleaks and Syft.' 'Browser, static code analysis, cloud and other specialist tools require separate installations.' ;;
  *) printf 'Unknown command: %s\n' "$1" >&2; exit 2 ;;
esac
