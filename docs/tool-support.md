# Complete tool and capability support matrix

Generated from the executable command surface. All entries remain in the full-release requirement. Implementation is separate from installation and certification. See [release status](release-status.md).

## Tools

| Tool | Implementation | Platform declaration | Actual capability mappings |
| --- | --- | --- | --- |
| `agent-browser` | adapter | undeclared | web.automate, web.browse, web.har |
| `amass` | not-implemented | undeclared | dns.enum |
| `amass-enum` | adapter | undeclared | **no executable mapping** |
| `anew` | adapter | undeclared | **no executable mapping** |
| `arjun` | adapter | undeclared | **no executable mapping** |
| `bettercap` | adapter | undeclared | mitm.assess |
| `bloodhound` | adapter | undeclared | active-directory.attack, privilege.escalation |
| `certipy` | adapter | undeclared | post.adcs |
| `chisel` | not-implemented | undeclared | pivot.tunnel, port.forward |
| `cloud_enum` | adapter | undeclared | cloud.enum |
| `cloudfox` | adapter | undeclared | **no executable mapping** |
| `cmseek` | adapter | undeclared | cms.detect |
| `corscanner` | adapter | undeclared | cors.audit |
| `covenant` | not-implemented | windows | c2.covenant |
| `crackmapexec` | adapter | undeclared | smb.test |
| `dirsearch` | adapter | undeclared | **no executable mapping** |
| `dnschef` | not-implemented | undeclared | c2.setup |
| `dnsrecon` | adapter | undeclared | dns.enum |
| `dnsx` | adapter | linux | dns.analyse |
| `enum4linux` | adapter | undeclared | smb.test |
| `evilginx` | adapter | undeclared | credential.harvest, phishing.campaign |
| `ffuf` | adapter | linux | dir.bruteforce, web.content.discover |
| `gf` | not-implemented | undeclared | pattern.detect |
| `gitleaks` | adapter | linux | secret.scan |
| `gobuster` | adapter | undeclared | dir.bruteforce |
| `gophish` | not-implemented | undeclared | phishing.campaign, social.engineer |
| `gosec` | adapter | linux | code.audit |
| `grype` | adapter | undeclared | container.scan, dependency.scan |
| `hashcat` | adapter | undeclared | hash.crack |
| `havoc` | adapter | undeclared | c2.havoc |
| `httpx` | adapter | linux | api.audit, tech.fingerprint, web.map |
| `hydra` | adapter | undeclared | password.bruteforce |
| `impacket` | adapter | undeclared | active-directory.attack, credential.dump, lateral.move, smb.test |
| `john` | adapter | undeclared | hash.crack |
| `jsluice` | adapter | undeclared | js.extract |
| `katana` | adapter | linux | web.map |
| `kekeo` | not-implemented | windows | post.kerberos |
| `knockpy` | adapter | undeclared | **no executable mapping** |
| `linkfinder` | adapter | undeclared | js.extract |
| `linpeas` | adapter | undeclared | post.recon |
| `massdns` | adapter | undeclared | **no executable mapping** |
| `merlin` | adapter | undeclared | c2.merlin, c2.operate |
| `metagoofil` | adapter | undeclared | **no executable mapping** |
| `metasploit` | not-implemented | undeclared | exploit.execute, exploit.framework, post.exploit |
| `mimikatz` | adapter | windows | post.mimikatz |
| `msfvenom` | adapter | undeclared | c2.setup, payload.generate |
| `mythic` | not-implemented | undeclared | c2.mythic, c2.operate |
| `naabu` | adapter | linux | port.scan, service.enumerate |
| `netexec` | adapter | undeclared | active-directory.attack, credential.dump, lateral.move, smb.test |
| `nikto` | adapter | undeclared | vuln.scan |
| `nmap` | adapter | linux | port.scan |
| `nuclei` | adapter | linux | api.audit, vuln.scan, web.scan |
| `pacu` | adapter | undeclared | **no executable mapping** |
| `pcredz` | adapter | undeclared | credential.harvest |
| `powersploit` | not-implemented | windows | post.exploit |
| `responder` | adapter | undeclared | **no executable mapping** |
| `rubeus` | adapter | windows | post.kerberoast, post.kerberos |
| `searchsploit` | adapter | undeclared | exploit.search |
| `seatbelt` | adapter | windows | post.recon |
| `semgrep` | adapter | linux | code.audit, js.analyse |
| `sharphound` | adapter | windows | post.recon |
| `sharppersist` | not-implemented | windows | persist.install, post.persistence |
| `sharpup` | adapter | windows | post.recon |
| `sharpview` | adapter | windows | post.recon |
| `sherlock` | adapter | undeclared | personnel.osint, social.engineer |
| `shodan` | adapter | undeclared | **no executable mapping** |
| `sliver` | adapter | undeclared | c2.operate, c2.sliver |
| `smbmap` | adapter | undeclared | smb.test |
| `sqlmap` | adapter | undeclared | sql.inject |
| `subfinder` | adapter | linux | dns.enum |
| `swaks` | adapter | undeclared | **no executable mapping** |
| `syft` | adapter | linux | sbom.generate |
| `system-dns-resolver` | built-in | darwin, linux, windows | asset.discover |
| `testssl` | adapter | undeclared | tls.audit |
| `theharvester` | adapter | undeclared | email.harvest, personnel.osint |
| `trivy` | adapter | undeclared | cloud.review, container.scan, dependency.scan |
| `trufflehog` | adapter | undeclared | secret.scan |
| `wafw00f` | adapter | undeclared | waf.detect |
| `waybackurls` | adapter | undeclared | **no executable mapping** |
| `whatweb` | adapter | undeclared | tech.fingerprint |
| `winpeas` | adapter | windows | post.recon |
| `wpscan` | adapter | undeclared | cms.detect |
| `xsstrike` | adapter | undeclared | xss.detect |
| `zap` | adapter | undeclared | web.zap |

## Capabilities

| Capability | Implementation | Executable tools |
| --- | --- | --- |
| `active-directory.attack` | adapter | bloodhound, impacket, netexec |
| `api.audit` | adapter | httpx, nuclei |
| `asset.discover` | adapter | system-dns-resolver |
| `c2.covenant` | not-implemented | covenant |
| `c2.havoc` | adapter | havoc |
| `c2.merlin` | adapter | merlin |
| `c2.mythic` | not-implemented | mythic |
| `c2.operate` | partial | merlin, mythic, sliver |
| `c2.setup` | partial | dnschef, msfvenom |
| `c2.sliver` | adapter | sliver |
| `classify.endpoint` | built-in | built-in |
| `cloud.enum` | adapter | cloud_enum |
| `cloud.review` | adapter | trivy |
| `cms.detect` | adapter | cmseek, wpscan |
| `code.audit` | adapter | gosec, semgrep |
| `container.scan` | adapter | grype, trivy |
| `cors.audit` | adapter | corscanner |
| `credential.dump` | adapter | impacket, netexec |
| `credential.harvest` | adapter | evilginx, pcredz |
| `cve.lookup` | built-in | built-in |
| `dependency.scan` | adapter | grype, trivy |
| `dir.bruteforce` | adapter | ffuf, gobuster |
| `dns.analyse` | adapter | dnsx |
| `dns.enum` | partial | amass, dnsrecon, subfinder |
| `email.harvest` | adapter | theharvester |
| `exploit.execute` | not-implemented | metasploit |
| `exploit.framework` | not-implemented | metasploit |
| `exploit.search` | adapter | searchsploit |
| `hash.crack` | adapter | hashcat, john |
| `js.analyse` | adapter | semgrep |
| `js.extract` | adapter | jsluice, linkfinder |
| `lateral.move` | adapter | impacket, netexec |
| `mitm.assess` | adapter | bettercap |
| `mitre.map` | built-in | built-in |
| `password.bruteforce` | adapter | hydra |
| `pattern.detect` | not-implemented | gf |
| `payload.generate` | adapter | msfvenom |
| `persist.install` | not-implemented | sharppersist |
| `personnel.osint` | adapter | sherlock, theharvester |
| `phishing.campaign` | partial | evilginx, gophish |
| `pivot.tunnel` | not-implemented | chisel |
| `port.forward` | not-implemented | chisel |
| `port.scan` | adapter | naabu, nmap |
| `post.adcs` | adapter | certipy |
| `post.exploit` | not-implemented | metasploit, powersploit |
| `post.kerberoast` | adapter | rubeus |
| `post.kerberos` | partial | kekeo, rubeus |
| `post.mimikatz` | adapter | mimikatz |
| `post.persistence` | not-implemented | sharppersist |
| `post.recon` | adapter | linpeas, seatbelt, sharphound, sharpup, sharpview, winpeas |
| `privilege.escalation` | adapter | bloodhound |
| `report.generate` | built-in | built-in |
| `sbom.generate` | adapter | syft |
| `secret.scan` | adapter | gitleaks, trufflehog |
| `service.enumerate` | adapter | naabu |
| `smb.test` | adapter | crackmapexec, enum4linux, impacket, netexec, smbmap |
| `social.engineer` | partial | gophish, sherlock |
| `sql.inject` | adapter | sqlmap |
| `tech.fingerprint` | adapter | httpx, whatweb |
| `tls.audit` | adapter | testssl |
| `validate.finding` | built-in | built-in |
| `vuln.scan` | adapter | nikto, nuclei |
| `waf.detect` | adapter | wafw00f |
| `web.automate` | adapter | agent-browser |
| `web.browse` | adapter | agent-browser |
| `web.content.discover` | adapter | ffuf |
| `web.har` | adapter | agent-browser |
| `web.map` | adapter | httpx, katana |
| `web.scan` | adapter | nuclei |
| `web.zap` | adapter | zap |
| `xss.detect` | adapter | xsstrike |
