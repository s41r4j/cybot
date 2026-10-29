package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/s41r4j/cybot/pkg/schema"
	jsonschemas "github.com/s41r4j/cybot/schemas"
)

type AssetDiscover struct{ Resolver *net.Resolver }

func (AssetDiscover) ID() string { return "asset.discover" }
func (AssetDiscover) Definition() schema.CapabilityDefinition {
	return schema.CapabilityDefinition{
		ID: "asset.discover", Title: "Asset Discovery", Version: "1.0.0", Category: "discovery", Stability: "stable",
		Documentation: schema.Documentation{
			Description: "Resolve one policy-authorized hostname into a sorted, deduplicated set of IP assets.", Purpose: "Provide deterministic, normalized DNS asset discovery without asking an AI to choose or operate a raw tool.",
			Arguments:      []schema.Argument{{Name: "target", Type: "hostname", Required: true, Description: "Policy-authorized DNS hostname without a path."}, {Name: "approve", Type: "boolean", Required: true, Description: "Confirms authorization when policy requires approval.", Default: false}},
			Examples:       []schema.Example{{Description: "Resolve an authorized target", Command: "cybot asset discover example.com --approve", Output: jsonRaw(`{"status":"completed","assets":[{"value":"93.184.216.34","type":"ipv4","confidence":1,"source":"dns"}]}`)}},
			ExpectedOutput: "A cybot.result object with deterministically sorted assets, an execution decision trace, confidence, verification advice, and next capabilities.", OutputSchema: "cybot://schemas/result",
			Limitations: []string{"DNS answers can vary by resolver, location, and time.", "This version performs DNS resolution only; it does not enumerate subdomains or ports."}, RequiredPermissions: []string{"Authorization to query the target hostname", "Network access to the configured DNS resolver"},
			RelatedCommands: []string{"cybot capability help asset.discover", "cybot run asset.discover --target HOST --approve", "cybot schema show result"}, CommonMistakes: []string{"Passing a URL instead of a hostname", "Assuming DNS ownership proves authorization", "Omitting --approve when approval is required"}, BestPractices: []string{"Restrict allowed_targets in policy", "Persist the run ID for reporting", "Verify important addresses using an independent authorized source"},
		},
		InputSchema: jsonRaw(`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,"required":["target"],"properties":{"target":{"type":"string","format":"hostname"}}}`), OutputSchema: jsonschemas.Must("result"),
		Workflow:    []schema.DecisionNode{{ID: "validate-target", Action: "Validate target through policy", Condition: "target is present, allowed, and approved", OnSuccess: "dns-resolution", OnFailure: "deny"}, {ID: "dns-resolution", Action: "Resolve A and AAAA records using the system resolver", Condition: "target passed policy", OnSuccess: "normalize", OnFailure: "fail"}, {ID: "normalize", Action: "Deduplicate and lexicographically sort addresses", Condition: "resolver returned addresses", OnSuccess: "verify"}, {ID: "verify", Action: "Attach confidence and verification guidance", Condition: "normalized assets are available", OnSuccess: "return"}, {ID: "return", Action: "Return strict cybot.result", Condition: "all prior stages completed", Terminal: true}},
		ToolChoices: []schema.ToolChoice{{ToolID: "system-dns-resolver", SelectedWhen: "asset.discover receives a hostname", SkipWhen: "target validation fails", Reason: "It is available without an external tool and produces structured host-address mappings."}, {ToolID: "subdomain-enumerator", SelectedWhen: "never in version 1.0.0", SkipWhen: "always", Reason: "Subdomain enumeration is outside this capability version and would broaden scope."}},
		Assumptions: []string{"The supplied target is a hostname authorized by policy.", "The system DNS resolver is trusted for this run."}, VerificationSteps: []string{"Resolve the hostname with a second authorized resolver.", "Compare returned addresses with known asset inventory."}, RelatedCapabilities: []string{"service.enumerate", "web.map"}, NextCapabilities: []string{"service.enumerate"},
	}
}
func (c AssetDiscover) Run(ctx context.Context, r schema.RunRequest, d Dependencies) (schema.Result, error) {
	target := strings.TrimSpace(r.Target)
	if err := validateHostname(target); err != nil {
		return emptyResult(), err
	}
	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupHost(ctx, target)
	if err != nil {
		return emptyResult(), fmt.Errorf("resolve %q: %w", target, err)
	}
	sort.Strings(ips)
	out := emptyResult()
	seen := map[string]bool{}
	for _, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		kind := "ipv4"
		if strings.Contains(ip, ":") {
			kind = "ipv6"
		}
		out.Assets = append(out.Assets, schema.Asset{Value: ip, Type: kind, Confidence: 1, Source: "dns"})
	}
	out.Summary = fmt.Sprintf("Resolved %s to %d unique IP asset(s).", target, len(out.Assets))
	out.Confidence = 0.9
	out.Decisions = []schema.Decision{{Stage: "discovery", Selected: "system-dns-resolver", Reason: "Deterministic built-in resolver selected for hostname-to-address discovery.", Skipped: []schema.SkippedOption{{Option: "subdomain-enumerator", Reason: "Would broaden scope beyond DNS resolution."}, {Option: "port-scanner", Reason: "Port discovery belongs to service.enumerate."}}}}
	out.Assumptions = []string{"The configured DNS resolver returned an authoritative-enough answer for discovery."}
	out.VerificationRecommended = []string{"Resolve the hostname with a second authorized resolver.", "Compare addresses against the authorized asset inventory."}
	out.NextCapabilities = []string{"service.enumerate"}
	out.RelatedWorkflows = []string{"web-assessment"}
	out.PossibleFalsePositives = []string{"CDN or shared-hosting addresses may not be exclusively controlled by the target owner."}
	artifact, err := json.Marshal(out.Assets)
	if err != nil {
		return emptyResult(), fmt.Errorf("encode normalized evidence: %w", err)
	}
	ev, err := d.Evidence.Put(r.RunID, "dns-assets", "application/json", artifact)
	if err != nil {
		return emptyResult(), fmt.Errorf("store evidence: %w", err)
	}
	ev.Metadata = map[string]string{"target": target, "schema": "cybot://schemas/asset"}
	out.Evidence = append(out.Evidence, ev)
	return out, nil
}

func validateHostname(target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if strings.ContainsAny(target, "/: ") || strings.HasPrefix(target, ".") || strings.HasSuffix(target, ".") {
		return fmt.Errorf("target must be a hostname without scheme, port, path, or trailing dot")
	}
	if len(target) > 253 {
		return fmt.Errorf("target hostname exceeds 253 characters")
	}
	for _, label := range strings.Split(target, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("target contains an invalid DNS label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return fmt.Errorf("target contains an invalid hostname character")
			}
		}
	}
	return nil
}

func emptyResult() schema.Result {
	return schema.Result{Assets: []schema.Asset{}, Services: []schema.Service{}, Endpoints: []schema.Endpoint{}, Findings: []schema.Finding{}, Evidence: []schema.Evidence{}, Errors: []schema.RunError{}, Decisions: []schema.Decision{}, Assumptions: []string{}, VerificationRecommended: []string{}, NextCapabilities: []string{}, RelatedWorkflows: []string{}, PossibleFalsePositives: []string{}}
}
func jsonRaw(s string) []byte { return []byte(s) }
func RegisterBuiltins(r *Registry) error {
	capabilities := []Capability{
		AssetDiscover{},
		external("code.audit", "Code Audit", "code-security", []string{"gosec", "semgrep"}, []string{"report.generate"},
			toolStep{ID: "semgrep", Required: true, Args: semgrepArgs}, toolStep{ID: "gosec", Args: gosecArgs}),
		external("dns.analyse", "DNS Analysis", "discovery", []string{"dnsx"}, []string{"service.enumerate"}, toolStep{ID: "dnsx", Required: true, Args: dnsxArgs}),
		external("service.enumerate", "Service Enumeration", "discovery", []string{"naabu"}, []string{"web.map", "port.scan"}, toolStep{ID: "naabu", Required: true, Args: naabuArgs}),
		external("web.map", "Web Mapping", "web-security", []string{"httpx", "katana"}, []string{"web.scan", "dir.bruteforce"}, toolStep{ID: "httpx", Required: true, Args: httpxArgs}, toolStep{ID: "katana", Args: katanaArgs}),
		external("web.scan", "Web Vulnerability Scan", "web-security", []string{"nuclei"}, []string{"report.generate", "vuln.scan"}, toolStep{ID: "nuclei", Required: true, Args: nucleiArgs}),
		external("web.content.discover", "Web Content Discovery", "web-security", []string{"ffuf"}, []string{"web.scan", "dir.bruteforce"}, toolStep{ID: "ffuf", Required: true, Args: ffufArgs}),
		external("secret.scan", "Secret Scan", "code-security", []string{"gitleaks", "trufflehog"}, []string{"report.generate"}, toolStep{ID: "gitleaks", Required: true, Args: gitleaksArgs, AcceptExitCodes: []int{1}}, toolStep{ID: "trufflehog", Args: trufflehogArgs}),
		external("dependency.scan", "Dependency Scan", "supply-chain", []string{"trivy", "grype"}, []string{"report.generate"}, toolStep{ID: "trivy", Required: true, Args: trivyFilesystemArgs}, toolStep{ID: "grype", Args: grypeArgs}),
		external("container.scan", "Container Scan", "supply-chain", []string{"trivy", "grype"}, []string{"report.generate"}, toolStep{ID: "trivy", Required: true, Args: trivyImageArgs}, toolStep{ID: "grype", Args: grypeArgs}),
		external("sbom.generate", "SBOM Generation", "supply-chain", []string{"syft"}, []string{"dependency.scan"}, toolStep{ID: "syft", Required: true, Args: syftArgs}),
		external("cloud.review", "Cloud Configuration Review", "cloud-security", []string{"trivy"}, []string{"report.generate"}, toolStep{ID: "trivy", Required: true, Args: trivyConfigArgs}),
		external("api.audit", "API Audit", "api-security", []string{"httpx", "nuclei"}, []string{"report.generate"}, toolStep{ID: "httpx", Required: true, Args: httpxArgs}, toolStep{ID: "nuclei", Required: true, Args: nucleiAPIArgs}),
		external("js.analyse", "JavaScript Analysis", "web-security", []string{"semgrep"}, []string{"secret.scan", "js.extract"}, toolStep{ID: "semgrep", Required: true, Args: semgrepArgs}),
		external("port.scan", "Port Scan", "offensive-recon", []string{"nmap", "naabu"}, []string{"service.enumerate", "web.map", "vuln.scan"}, toolStep{ID: "nmap", Args: nmapArgs}, toolStep{ID: "naabu", Args: naabuArgs}),
		external("tech.fingerprint", "Technology Fingerprint", "offensive-recon", []string{"whatweb", "httpx"}, []string{"web.map", "cms.detect", "waf.detect"}, toolStep{ID: "whatweb", Args: whatwebArgs}, toolStep{ID: "httpx", Args: httpxArgs}),
		external("waf.detect", "WAF Detection", "offensive-recon", []string{"wafw00f"}, []string{"web.scan", "vuln.scan"}, toolStep{ID: "wafw00f", Args: wafw00fArgs}),
		external("dir.bruteforce", "Directory Brute Force", "offensive-recon", []string{"gobuster", "ffuf"}, []string{"web.scan", "web.content.discover"}, toolStep{ID: "gobuster", Args: gobusterArgs}, toolStep{ID: "ffuf", Args: ffufArgs}),
		external("tls.audit", "TLS Audit", "offensive-recon", []string{"testssl"}, []string{"vuln.scan", "report.generate"}, toolStep{ID: "testssl", Args: testsslArgs}),
		external("vuln.scan", "Vulnerability Scan", "offensive-assessment", []string{"nuclei", "nikto"}, []string{"report.generate", "sql.inject", "xss.detect"}, toolStep{ID: "nuclei", Args: nucleiArgs}, toolStep{ID: "nikto", Args: niktoArgs}),
		external("sql.inject", "SQL Injection Test", "offensive-assessment", []string{"sqlmap"}, []string{"report.generate"}, toolStep{ID: "sqlmap", Args: sqlmapArgs}),
		external("dns.enum", "DNS Enumeration", "offensive-recon", []string{"subfinder", "amass", "massdns", "dnsrecon"}, []string{"dns.analyse", "service.enumerate", "port.scan"}, toolStep{ID: "subfinder", Args: subfinderArgs}, toolStep{ID: "amass"}, toolStep{ID: "dnsrecon", Args: dnsreconArgs}),
		external("cors.audit", "CORS Audit", "web-security", []string{"corscanner"}, []string{"web.scan", "report.generate"}, toolStep{ID: "corscanner", Args: corscannerArgs}),
		external("cloud.enum", "Cloud Enumeration", "offensive-recon", []string{"cloud_enum"}, []string{"cloud.review", "asset.discover"}, toolStep{ID: "cloud_enum", Args: cloudEnumArgs}),
		external("cms.detect", "CMS Detection", "offensive-recon", []string{"cmseek", "whatweb", "wpscan"}, []string{"tech.fingerprint", "vuln.scan"}, toolStep{ID: "cmseek", Args: cmseekArgs}, toolStep{ID: "wpscan", Args: wpscanArgs}),
		external("xss.detect", "XSS Detection", "offensive-assessment", []string{"xsstrike"}, []string{"report.generate"}, toolStep{ID: "xsstrike", Args: xsstrikeArgs}),
		external("js.extract", "JS Endpoint Extraction", "offensive-recon", []string{"jsluice", "linkfinder"}, []string{"js.analyse", "secret.scan", "web.map"}, toolStep{ID: "jsluice", Required: true, Args: jsluiceArgs}, toolStep{ID: "linkfinder", Required: true, Args: linkfinderArgs}),
		external("pattern.detect", "Pattern Detection", "offensive-recon", []string{"gf", "anew"}, []string{"web.map", "js.extract"}, toolStep{ID: "gf", Required: true, Args: gfArgs}, toolStep{ID: "anew", Required: true, Args: anewArgs, StdinFromPrevious: true}),
		external("password.bruteforce", "Password Brute Force", "offensive-exploitation", []string{"hydra"}, []string{"credential.test", "lateral.move"}, toolStep{ID: "hydra", Args: hydraArgs}),
		external("hash.crack", "Hash Cracking", "offensive-exploitation", []string{"hashcat", "john"}, []string{"credential.test", "report.generate"}, toolStep{ID: "hashcat", Args: hashcatArgs}, toolStep{ID: "john", Args: johnArgs}),
		external("email.harvest", "Email Harvesting", "offensive-osint", []string{"theharvester"}, []string{"personnel.osint", "phishing.campaign"}, toolStep{ID: "theharvester", Args: theharvesterArgs}),
		external("personnel.osint", "Personnel OSINT", "offensive-osint", []string{"sherlock", "metagoofil", "theharvester"}, []string{"social.engineer", "phishing.campaign"}, toolStep{ID: "sherlock", Args: sherlockArgs}, toolStep{ID: "theharvester", Args: theharvesterArgs}),
		external("credential.dump", "Credential Dumping", "offensive-exploitation", []string{"impacket", "netexec"}, []string{"hash.crack", "credential.extract"}, toolStep{ID: "impacket", Args: impacketArgs}, toolStep{ID: "netexec", Args: netexecArgs}),
		external("lateral.move", "Lateral Movement", "offensive-exploitation", []string{"netexec", "impacket"}, []string{"credential.dump", "privilege.escalation"}, toolStep{ID: "netexec", Args: netexecArgs}, toolStep{ID: "impacket", Args: impacketArgs}),
		external("active-directory.attack", "Active Directory Attack", "offensive-exploitation", []string{"impacket", "bloodhound", "netexec"}, []string{"credential.dump", "lateral.move", "privilege.escalation"}, toolStep{ID: "impacket", Args: impacketArgs}, toolStep{ID: "bloodhound", Args: bloodhoundArgs}, toolStep{ID: "netexec", Args: netexecArgs}),
		external("privilege.escalation", "Privilege Escalation", "offensive-exploitation", []string{"bloodhound"}, []string{"credential.dump", "lateral.move"}, toolStep{ID: "bloodhound", Args: bloodhoundArgs}),
		external("payload.generate", "Payload Generation", "offensive-exploitation", []string{"msfvenom"}, []string{"phishing.campaign", "c2.setup"}, toolStep{ID: "msfvenom", Args: msfvenomArgs}),
		external("phishing.campaign", "Phishing Campaign", "offensive-social-engineering", []string{"gophish", "evilginx"}, []string{"credential.harvest", "c2.setup"}, toolStep{ID: "gophish", Args: gophishArgs}, toolStep{ID: "evilginx", Args: evilginxArgs}),
		external("mitm.assess", "MITM Assessment", "offensive-exploitation", []string{"bettercap"}, []string{"credential.sniff", "network.attack"}, toolStep{ID: "bettercap", Args: bettercapArgs}),
		external("social.engineer", "Social Engineering", "offensive-osint", []string{"sherlock", "gophish"}, []string{"phishing.campaign", "personnel.osint"}, toolStep{ID: "sherlock", Args: sherlockArgs}, toolStep{ID: "gophish", Args: gophishArgs}),
		external("credential.harvest", "Credential Harvesting", "offensive-exploitation", []string{"evilginx", "pcredz"}, []string{"credential.test", "lateral.move"}, toolStep{ID: "evilginx", Args: evilginxArgs}, toolStep{ID: "pcredz", Args: pcredzArgs}),
		external("c2.setup", "C2 Infrastructure Setup", "offensive-exploitation", []string{"dnschef", "msfvenom"}, []string{"phishing.campaign", "lateral.move"}, toolStep{ID: "dnschef", Args: dnschefArgs}, toolStep{ID: "msfvenom", Args: msfvenomArgs}),
		external("c2.operate", "C2 Operations", "offensive-c2", []string{"sliver", "havoc", "merlin", "mythic", "covenant"}, []string{"post.recon", "lateral.move", "credential.dump"}, toolStep{ID: "sliver", Args: sliverArgs}, toolStep{ID: "merlin", Args: merlinArgs}, toolStep{ID: "mythic", Args: mythicArgs}),
		external("c2.sliver", "Sliver C2", "offensive-c2", []string{"sliver"}, []string{"payload.generate", "post.recon", "credential.dump", "lateral.move"}, toolStep{ID: "sliver", Args: sliverArgs}),
		external("c2.havoc", "Havoc C2", "offensive-c2", []string{"havoc"}, []string{"payload.generate", "lateral.move", "privilege.escalation"}, toolStep{ID: "havoc", Args: havocArgs}),
		external("c2.merlin", "Merlin C2", "offensive-c2", []string{"merlin"}, []string{"payload.generate", "post.recon"}, toolStep{ID: "merlin", Args: merlinArgs}),
		external("c2.mythic", "Mythic C2", "offensive-c2", []string{"mythic"}, []string{"payload.generate", "credential.dump", "lateral.move"}, toolStep{ID: "mythic", Args: mythicArgs}),
		external("c2.covenant", "Covenant C2", "offensive-c2", []string{"covenant"}, []string{"payload.generate", "lateral.move", "credential.dump"}, toolStep{ID: "covenant", Args: covenantArgs}),
		external("post.mimikatz", "Mimikatz Post-Exploitation", "offensive-post-exploitation", []string{"mimikatz"}, []string{"credential.dump", "post.kerberos", "privilege.escalation"}, toolStep{ID: "mimikatz", Args: mimikatzArgs}),
		external("post.adcs", "AD CS Exploitation", "offensive-post-exploitation", []string{"certipy"}, []string{"privilege.escalation", "credential.dump", "active-directory.attack"}, toolStep{ID: "certipy", Args: certipyArgs}),
		external("post.kerberoast", "Kerberoasting Attack", "offensive-post-exploitation", []string{"rubeus"}, []string{"hash.crack", "credential.dump", "privilege.escalation"}, toolStep{ID: "rubeus", Args: rubeusArgs}),
		external("post.recon", "Post-Exploitation Recon", "offensive-post-exploitation", []string{"winpeas", "linpeas", "seatbelt", "sharpview", "sharphound", "sharpup"}, []string{"privilege.escalation", "lateral.move", "credential.dump"}, toolStep{ID: "linpeas", Args: linpeasArgs}, toolStep{ID: "winpeas", Args: winpeasArgs}, toolStep{ID: "seatbelt", Args: seatbeltArgs}, toolStep{ID: "sharpview", Args: sharpviewArgs}, toolStep{ID: "sharphound", Args: sharphoundArgs}, toolStep{ID: "sharpup", Args: sharpupArgs}),
		external("post.exploit", "Post-Exploitation Operations", "offensive-post-exploitation", []string{"metasploit", "powersploit"}, []string{"credential.dump", "lateral.move", "privilege.escalation", "post.recon"}, toolStep{ID: "metasploit", Args: metasploitArgs}, toolStep{ID: "powersploit", Args: powersploitArgs}),
		external("post.persistence", "Persistence Installation", "offensive-post-exploitation", []string{"sharppersist"}, []string{"c2.operate", "lateral.move"}, toolStep{ID: "sharppersist", Args: sharppersistArgs}),
		external("post.kerberos", "Kerberos Ticket Attacks", "offensive-post-exploitation", []string{"kekeo", "rubeus"}, []string{"privilege.escalation", "credential.dump", "lateral.move"}, toolStep{ID: "kekeo", Args: kekeoArgs}, toolStep{ID: "rubeus", Args: rubeusArgs}),
		external("exploit.framework", "Metasploit Framework", "offensive-exploitation", []string{"metasploit"}, []string{"exploit.execute", "post.exploit", "payload.generate", "lateral.move", "credential.dump"}, toolStep{ID: "metasploit", Args: metasploitArgs}),
		external("exploit.execute", "Exploit Execution", "offensive-exploitation", []string{"metasploit"}, []string{"post.exploit", "credential.dump", "lateral.move", "privilege.escalation"}, toolStep{ID: "metasploit", Args: metasploitArgs}),
		external("pivot.tunnel", "Pivot Tunneling", "offensive-post-exploitation", []string{"chisel"}, []string{"lateral.move", "port.forward", "post.recon"}, toolStep{ID: "chisel", Args: chiselArgs}),
		external("port.forward", "Port Forwarding", "offensive-post-exploitation", []string{"chisel"}, []string{"pivot.tunnel", "lateral.move"}, toolStep{ID: "chisel", Args: chiselArgs}),
		external("smb.test", "SMB Security Testing", "offensive-exploitation", []string{"crackmapexec", "impacket", "netexec", "enum4linux", "smbmap"}, []string{"lateral.move", "credential.dump", "active-directory.attack"}, toolStep{ID: "crackmapexec", Args: crackmapexecArgs}, toolStep{ID: "impacket", Args: impacketArgs}, toolStep{ID: "netexec", Args: netexecArgs}, toolStep{ID: "enum4linux", Args: enum4linuxArgs}, toolStep{ID: "smbmap", Args: smbmapArgs}),
		external("persist.install", "Persistence Deployment", "offensive-post-exploitation", []string{"sharppersist"}, []string{"c2.operate", "post.exploit"}, toolStep{ID: "sharppersist", Args: sharppersistArgs}),
		external("exploit.search", "Exploit-DB Search", "offensive-recon", []string{"searchsploit"}, []string{"exploit.execute", "vuln.scan", "cve.lookup"}, toolStep{ID: "searchsploit", Args: searchsploitArgs}),
		reportCapability{definition: capabilityDefinition("report.generate", "Report Generation", "reporting", []string{}, []string{})},
		ValidateFinding{},
		ClassifyEndpoint{},
		CVELookup{},
		MitreMap{},
		ZAPBaseline{},
	}
	for _, c := range capabilities {
		if err := r.Register(c); err != nil {
			return err
		}
	}
	return RegisterBrowserCapabilities(r)
}

func external(id, title, category string, tools, next []string, steps ...toolStep) Capability {
	return externalCapability{definition: capabilityDefinition(id, title, category, tools, next), steps: steps}
}

func capabilityDefinition(id, title, category string, tools, next []string) schema.CapabilityDefinition {
	choices := []schema.ToolChoice{}
	for _, tool := range tools {
		choices = append(choices, schema.ToolChoice{ToolID: tool, SelectedWhen: "the adapter is registered, installed, and compatible with the validated input", SkipWhen: "any selection precondition fails", Reason: "Configured adapter for this capability stage; review its output contract and declared version."})
	}
	return schema.CapabilityDefinition{ID: id, Title: title, Version: "1.0.0", Category: category, Stability: "stable", Documentation: schema.Documentation{Description: "Deterministic " + title + " capability using configured adapters and schema validation.", Purpose: "Provide a stable, schema-first operation so agents never invent raw tool commands.", Arguments: []schema.Argument{{Name: "target", Type: "string", Required: true, Description: "Policy-authorized target matching the capability input schema."}}, Examples: []schema.Example{{Description: "Inspect the deterministic plan", Command: "cybot capability plan " + id + " --target TARGET"}, {Description: "Execute after confirming authorization", Command: "cybot run " + id + " --target TARGET --approve"}}, ExpectedOutput: "A normalized cybot.result with evidence, decisions, confidence, verification, and next actions.", OutputSchema: "cybot://schemas/result", Limitations: []string{"Tool findings require contextual verification.", "Network capabilities depend on target and upstream availability."}, RequiredPermissions: []string{"Explicit target authorization", "Capability approval under active policy"}, RelatedCommands: []string{"cybot capability plan " + id, "cybot tool doctor", "cybot schema show result"}, CommonMistakes: []string{"Substituting a raw tool command", "Treating a scanner match as confirmed exploitability"}, BestPractices: []string{"Inspect the plan first", "Use pinned tool and ruleset versions", "Verify high-impact findings independently"}}, InputSchema: jsonRaw(`{"type":"object","additionalProperties":false,"required":["target"],"properties":{"target":{"type":"string","minLength":1}}}`), OutputSchema: jsonschemas.Must("result"), Workflow: []schema.DecisionNode{{ID: "validate", Action: "Validate strict input and policy scope", Condition: "input matches schema and policy permits target", OnSuccess: "select"}, {ID: "select", Action: "Select configured tool adapters", Condition: "adapter availability checks pass", OnSuccess: "execute", OnFailure: "stop"}, {ID: "execute", Action: "Execute with bounded concurrency, rate, timeout, and retries", Condition: "active policy permits execution or records an advisory", OnSuccess: "normalize"}, {ID: "normalize", Action: "Parse, deduplicate, and merge into cybot.result", Condition: "tool output matches adapter contract", OnSuccess: "verify"}, {ID: "verify", Action: "Validate result schema and attach evidence", Condition: "normalization completed", OnSuccess: "return"}, {ID: "return", Action: "Return actionable result", Condition: "verification completed", Terminal: true}}, ToolChoices: choices, Assumptions: []string{"The target is authorized and stable for the run.", "Declared tool versions are metadata; verify installed versions separately."}, VerificationSteps: []string{"Validate output against cybot://schemas/result.", "Corroborate high-impact findings with an independent capability."}, RelatedCapabilities: next, NextCapabilities: next}
}

type ClassifyEndpoint struct{}

func (ClassifyEndpoint) ID() string { return "classify.endpoint" }
func (ClassifyEndpoint) Definition() schema.CapabilityDefinition {
	return schema.CapabilityDefinition{
		ID: "classify.endpoint", Title: "Endpoint Classification", Version: "1.0.0", Category: "routing", Stability: "stable",
		Documentation: schema.Documentation{
			Description:         "Classify a URL or endpoint against the vulnerability pattern library and return matched capabilities.",
			Purpose:             "Bridge recon output to hunt capabilities by pattern-matching URLs against curated vulnerability class signatures.",
			Arguments:           []schema.Argument{{Name: "target", Type: "string", Required: true, Description: "URL or endpoint path to classify."}},
			Examples:            []schema.Example{{Description: "Classify an endpoint", Command: "cybot run classify.endpoint --target 'https://api.target.com/v1/users/42?next=https://evil.com' --approve"}},
			ExpectedOutput:      "A cybot.result with routing decisions, observations and suggested capabilities; no vulnerability findings.",
			OutputSchema:        "cybot://schemas/result",
			Limitations:         []string{"URL substring matching supplies investigation leads only.", "Context-dependent vulnerabilities (business logic) cannot be detected from URL alone."},
			RequiredPermissions: []string{"Read access to the URL to classify."},
			RelatedCommands:     []string{"cybot capability search", "cybot capability plan"},
			CommonMistakes:      []string{"Assuming a classified URL is exploitable without testing."},
			BestPractices:       []string{"Classify first, then execute the recommended capability.", "Review all matches before selecting a hunt path."},
		},
		InputSchema:  jsonRaw(`{"type":"object","additionalProperties":false,"required":["target"],"properties":{"target":{"type":"string","minLength":1,"description":"URL or endpoint path to classify"}}}`),
		OutputSchema: jsonschemas.Must("result"),
		Workflow: []schema.DecisionNode{
			{ID: "parse", Action: "Parse URL into components", Condition: "URL is well-formed", OnSuccess: "pattern-match", OnFailure: "fail"},
			{ID: "pattern-match", Action: "Match URL components against vulnerability pattern triggers", Condition: "Pattern library is loaded", OnSuccess: "rank", OnFailure: "return-empty"},
			{ID: "rank", Action: "Rank matches by confidence", Condition: "At least one pattern matched", OnSuccess: "return"},
		},
		ToolChoices:       []schema.ToolChoice{},
		Assumptions:       []string{"The URL is a valid target endpoint.", "The pattern library is current and curated."},
		VerificationSteps: []string{"Execute the highest-ranked capability plan first.", "Review capability help for matched patterns."},
		NextCapabilities:  []string{},
	}
}

func (c ClassifyEndpoint) Run(ctx context.Context, req schema.RunRequest, d Dependencies) (schema.Result, error) {
	url := strings.TrimSpace(req.Target)
	if url == "" {
		return emptyResult(), fmt.Errorf("target URL is required")
	}
	result := emptyResult()
	lower := strings.ToLower(url)
	if !strings.Contains(lower, "://") {
		lower = "https://" + lower
	}
	patterns := []struct{ pattern, id, cap string }{
		{`redirect=`, "ssrf", "web.scan"},
		{`url=`, "ssrf", "web.scan"},
		{`callback=`, "ssrf", "web.scan"},
		{`search=`, "xss", "xss.detect"},
		{`query=`, "xss", "xss.detect"},
		{`q=`, "xss", "xss.detect"},
		{`user_id=`, "idor", "web.scan"},
		{`id=`, "sqli", "sql.inject"},
		{`order=`, "sqli", "sql.inject"},
		{`/oauth/`, "oauth", "web.scan"},
		{`/graphql`, "graphql", "web.scan"},
		{`/upload`, "file-upload", "web.scan"},
		{`cmd=`, "rce", "vuln.scan"},
		{`exec=`, "rce", "vuln.scan"},
		{`access-control-allow`, "cors", "cors.audit"},
		{`__schema`, "graphql", "web.scan"},
	}
	matched := 0
	for _, p := range patterns {
		if strings.Contains(lower, p.pattern) {
			result.Decisions = append(result.Decisions, schema.Decision{Stage: "url-pattern", Selected: p.id, Reason: fmt.Sprintf("URL contains '%s'", p.pattern)})
			result.Observations = append(result.Observations, "Investigation candidate: "+p.id+"; URL text alone does not establish a vulnerability.")
			result.NextCapabilities = append(result.NextCapabilities, p.cap)
			matched++
		}
	}
	if matched == 0 {
		for _, kw := range []string{"api", ".json", "login", "signup", "reset", ".js", "config", "admin", "token"} {
			if strings.Contains(lower, kw) {
				result.Decisions = append(result.Decisions, schema.Decision{Stage: "keyword-match", Selected: "api-misconfig", Reason: fmt.Sprintf("URL contains keyword '%s'", kw)})
				result.Observations = append(result.Observations, "Investigation candidate: api.audit; keyword matching does not establish a misconfiguration.")
				result.NextCapabilities = append(result.NextCapabilities, "api.audit")
				matched++
				break
			}
		}
	}
	result.Summary = fmt.Sprintf("Classified endpoint: %d investigation candidate(s); no vulnerability assessment performed.", matched)
	result.Confidence = 0
	result.NextCapabilities = unique(result.NextCapabilities, func(value string) string { return value })
	result.Warnings = []string{"Routing candidates are unverified leads, not vulnerability findings."}
	result.VerificationRecommended = []string{"Run cybot capability plan for each candidate capability", "Verify any vulnerability with authorized testing and supporting evidence"}
	return result, nil
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func BuiltinTools() []schema.Tool {
	d := AssetDiscover{}.Definition().Documentation
	d.Description = "The Go system DNS resolver used internally by asset.discover."
	d.Purpose = "Provide hostname-to-address resolution as one deterministic stage selected by a capability."
	d.Arguments = []schema.Argument{{Name: "hostname", Type: "string", Required: true, Description: "Validated hostname supplied by asset.discover."}}
	d.Examples = []schema.Example{{Description: "Use through its owning capability", Command: "cybot asset discover example.com --approve"}}
	d.RelatedCommands = []string{"cybot capability help asset.discover", "cybot tool help system-dns-resolver"}
	return []schema.Tool{{ID: "system-dns-resolver", Title: "System DNS Resolver", Description: d.Description, Purpose: d.Purpose, Version: "go-runtime", Kind: "native", SupportedOS: []string{"darwin", "linux", "windows"}, InputSchema: jsonRaw(`{"type":"object","additionalProperties":false,"required":["hostname"],"properties":{"hostname":{"type":"string","format":"hostname"}}}`), OutputSchema: jsonRaw(`{"type":"array","items":{"oneOf":[{"type":"string","format":"ipv4"},{"type":"string","format":"ipv6"}]}}`), Documentation: d, SourceURL: "https://pkg.go.dev/net#Resolver", License: "BSD-3-Clause", Capabilities: []string{"asset.discover"}, DefaultArgs: []string{}, OutputFormat: "normalized-json", Parser: "cybot.system-dns.v1", Risk: "dns-network", RequiresNetwork: true}}
}
