#!/usr/bin/env bash
set -euo pipefail

tools=(cybot subfinder dnsx naabu httpx katana nuclei amass ffuf gitleaks trufflehog gosec semgrep trivy syft grype nmap chromium hydra hashcat john swaks chisel theHarvester sherlock metagoofil impacket-secretsdump certipy shodan searchsploit enum4linux dnsrecon smbmap arjun cloudfox agent-browser gobuster waybackurls jsluice gf anew massdns sqlmap dirsearch wafw00f whatweb nikto xsstrike linkfinder corscanner cmseek knockpy dnschef testssl.sh responder linpeas wpscan)
failed=0

for tool in "${tools[@]}"; do
  if path=$(command -v "$tool" 2>/dev/null); then
    printf 'ok\t%s\t%s\n' "$tool" "$path"
  else
    printf 'missing\t%s\n' "$tool" >&2
    failed=1
  fi
done

for directory in /opt/cybot/share/nuclei-templates /opt/cybot/share/seclists /opt/cybot/share/trivy-cache/db /opt/cybot/share/grype-db /opt/cybot/rules; do
  if [[ -d "$directory" ]]; then
    printf 'ok\tdata\t%s\n' "$directory"
  else
    printf 'missing\tdata\t%s\n' "$directory" >&2
    failed=1
  fi
done

if [[ "${1:-}" != "--build" ]]; then
  printf '\nPinned manifest:\n'
  jq -r '.tools | to_entries[] | "\(.key)\t\(.value)"' /opt/cybot/manifest/tool-versions.lock.json
fi

exit "$failed"
