package capability

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/s41r4j/cybot/internal/evidence"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/s41r4j/cybot/pkg/schema"
)

type toolParser func([]byte, schema.RunRequest) (schema.Result, error)

var parsers = map[string]toolParser{
	"subfinder":     parseAssets,
	"amass":         parseAssets,
	"dnsx":          parseAssets,
	"nmap":          parseNmap,
	"naabu":         parseNaabu,
	"httpx":         parseEndpoints,
	"katana":        parseEndpoints,
	"ffuf":          parseEndpoints,
	"nuclei":        parseNuclei,
	"nikto":         parseJSONPassthrough,
	"gitleaks":      parseGitleaks,
	"trufflehog":    parseTruffleHog,
	"gosec":         parseGosec,
	"semgrep":       parseSemgrep,
	"trivy":         parseTrivy,
	"syft":          parseSBOM,
	"grype":         parseGrype,
	"whatweb":       parseWhatWeb,
	"wafw00f":       parseTextLines,
	"gobuster":      parseTextLines,
	"testssl":       parseTestSSL,
	"dirsearch":     parseEndpoints,
	"sqlmap":        parseSQLMap,
	"xsstrike":      parseTextLines,
	"cloud_enum":    parseTextLines,
	"linkfinder":    parseTextLines,
	"jsluice":       parseJSLuice,
	"massdns":       parseTextLines,
	"corscanner":    parseCORS,
	"cmseek":        parseJSONPassthrough,
	"waybackurls":   parseTextLines,
	"gf":            parseTextLines,
	"anew":          parseTextLines,
	"hydra":         parseTextLines,
	"hashcat":       parseTextLines,
	"john":          parseTextLines,
	"theharvester":  parseJSONPassthrough,
	"bettercap":     parseJSONPassthrough,
	"pcredz":        parseJSONPassthrough,
	"msfvenom":      parseTextLines,
	"impacket":      parseTextLines,
	"bloodhound":    parseJSONPassthrough,
	"dnschef":       parseTextLines,
	"netexec":       parseTextLines,
	"gophish":       parseJSONPassthrough,
	"sherlock":      parseTextLines,
	"shodan":        parseJSONPassthrough,
	"swaks":         parseTextLines,
	"amass-enum":    parseAssets,
	"knockpy":       parseJSONPassthrough,
	"metagoofil":    parseTextLines,
	"evilginx":      parseTextLines,
	"sliver":        parseJSONPassthrough,
	"havoc":         parseJSONPassthrough,
	"merlin":        parseJSONPassthrough,
	"mythic":        parseJSONPassthrough,
	"mimikatz":      parseTextLines,
	"certipy":       parseTextLines,
	"responder":     parseTextLines,
	"rubeus":        parseJSONPassthrough,
	"sharphound":    parseJSONPassthrough,
	"winpeas":       parseTextLines,
	"linpeas":       parseTextLines,
	"seatbelt":      parseJSONPassthrough,
	"sharpview":     parseJSONPassthrough,
	"sharppersist":  parseTextLines,
	"covenant":      parseJSONPassthrough,
	"crackmapexec":  parseTextLines,
	"metasploit":    parseJSONPassthrough,
	"powersploit":   parseTextLines,
	"kekeo":         parseTextLines,
	"sharpup":       parseJSONPassthrough,
	"chisel":        parseTextLines,
	"searchsploit":  parseTextLines,
	"enum4linux":    parseTextLines,
	"wpscan":        parseWPScan,
	"dnsrecon":      parseTextLines,
	"smbmap":        parseTextLines,
	"cloudfox":      parseTextLines,
	"pacu":          parseTextLines,
	"arjun":         parseTextLines,
	"agent-browser": parseBrowserBatchJSON,
	"zap":           parseZAPBaselineJSON,
}

func parseTool(tool string, data []byte, req schema.RunRequest) (schema.Result, error) {
	p, ok := parsers[tool]
	if !ok {
		return emptyResult(), fmt.Errorf("no locked parser for tool %q", tool)
	}
	if err := validateReportShape(tool, data); err != nil {
		return emptyResult(), err
	}
	result, err := p(data, req)
	if err == nil {
		applyReportDiagnostics(tool, data, &result)
	}
	return result, err
}

func parseBrowserBatchJSON(data []byte, req schema.RunRequest) (schema.Result, error) {
	return parseBrowserBatch("browse", data, req)
}

func parseZAPBaselineJSON(data []byte, req schema.RunRequest) (schema.Result, error) {
	return parseZAPBaseline(data, req)
}

func decodeDocuments(data []byte) ([]map[string]any, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return []map[string]any{}, nil
	}
	if data[0] == '[' {
		var out []map[string]any
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	if data[0] == '{' {
		var one map[string]any
		if json.Unmarshal(data, &one) == nil {
			return []map[string]any{one}, nil
		}
	}
	out := []map[string]any{}
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for s.Scan() {
		line := bytes.TrimSpace(s.Bytes())
		if len(line) == 0 {
			continue
		}
		var item map[string]any
		if err := json.Unmarshal(line, &item); err != nil {
			return nil, fmt.Errorf("invalid JSONL record %d: %w", len(out)+1, err)
		}
		out = append(out, item)
	}
	return out, s.Err()
}

func parseAssets(data []byte, req schema.RunRequest) (schema.Result, error) {
	docs, err := decodeDocuments(data)
	if err != nil {
		return emptyResult(), err
	}
	result := emptyResult()
	seen := map[string]bool{}
	add := func(value, kind, source string, confidence float64) {
		value = strings.TrimSpace(value)
		if value == "" || seen[kind+"\x00"+value] {
			return
		}
		seen[kind+"\x00"+value] = true
		result.Assets = append(result.Assets, schema.Asset{Value: value, Type: kind, Source: source, Confidence: confidence})
	}
	for _, d := range docs {
		for _, key := range []string{"host", "name", "domain", "input"} {
			if v := text(d[key]); v != "" {
				add(v, "hostname", sourceName(d, "discovery"), .85)
				break
			}
		}
		for _, key := range []string{"a", "aaaa", "ips"} {
			for _, ip := range texts(d[key]) {
				kind := "ipv4"
				if strings.Contains(ip, ":") {
					kind = "ipv6"
				}
				add(ip, kind, sourceName(d, "dns"), .9)
			}
		}
		if addresses, ok := d["addresses"].([]any); ok {
			for _, raw := range addresses {
				if address, ok := raw.(map[string]any); ok {
					ip := text(address["ip"])
					kind := "ipv4"
					if strings.Contains(ip, ":") {
						kind = "ipv6"
					}
					add(ip, kind, "amass", .85)
				}
			}
		}
	}
	sort.Slice(result.Assets, func(i, j int) bool {
		if result.Assets[i].Type == result.Assets[j].Type {
			return result.Assets[i].Value < result.Assets[j].Value
		}
		return result.Assets[i].Type < result.Assets[j].Type
	})
	return result, nil
}

func parseNaabu(data []byte, _ schema.RunRequest) (schema.Result, error) {
	docs, err := decodeDocuments(data)
	if err != nil {
		return emptyResult(), err
	}
	result := emptyResult()
	seen := map[string]bool{}
	for _, d := range docs {
		host := firstText(d, "host", "ip")
		port := number(d["port"])
		if host == "" || port < 1 || port > 65535 {
			continue
		}
		key := fmt.Sprintf("%s:%d", host, port)
		if seen[key] {
			continue
		}
		seen[key] = true
		protocol := firstText(d, "protocol", "type")
		if protocol == "" {
			protocol = "tcp"
		}
		result.Services = append(result.Services, schema.Service{Host: host, Port: port, Protocol: strings.ToLower(protocol), Confidence: .9})
	}
	sort.Slice(result.Services, func(i, j int) bool {
		if result.Services[i].Host == result.Services[j].Host {
			return result.Services[i].Port < result.Services[j].Port
		}
		return result.Services[i].Host < result.Services[j].Host
	})
	return result, nil
}

func parseEndpoints(data []byte, req schema.RunRequest) (schema.Result, error) {
	docs, err := decodeDocuments(data)
	if err != nil {
		return emptyResult(), err
	}
	result := emptyResult()
	seen := map[string]bool{}
	for _, d := range docs {
		rawURL := firstText(d, "url", "endpoint", "matched-at")
		if rawURL == "" {
			if request, ok := d["request"].(map[string]any); ok {
				rawURL = firstText(request, "endpoint", "url")
			}
		}
		if rawURL == "" {
			return emptyResult(), fmt.Errorf("endpoint record lacks a URL")
		}
		if u, e := url.Parse(rawURL); e != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		if seen[rawURL] {
			continue
		}
		seen[rawURL] = true
		tech := texts(d["tech"])
		if len(tech) == 0 {
			tech = texts(d["technologies"])
		}
		sort.Strings(tech)
		result.Endpoints = append(result.Endpoints, schema.Endpoint{URL: rawURL, Method: strings.ToUpper(firstText(d, "method")), Status: firstNumber(d, "status_code", "status"), Technology: tech})
	}
	sort.Slice(result.Endpoints, func(i, j int) bool { return result.Endpoints[i].URL < result.Endpoints[j].URL })
	return result, nil
}

func parseNuclei(data []byte, _ schema.RunRequest) (schema.Result, error) {
	docs, err := decodeDocuments(data)
	if err != nil {
		return emptyResult(), err
	}
	result := emptyResult()
	for _, d := range docs {
		info, _ := d["info"].(map[string]any)
		id := firstText(d, "template-id", "template_id")
		title := firstText(info, "name")
		if title == "" {
			title = id
		}
		if id == "" && title == "" {
			continue
		}
		description := firstText(info, "description")
		matched := firstText(d, "matched-at", "matched")
		if matched != "" {
			description = strings.TrimSpace(description + " Matched at " + matched + ".")
		}
		result.Findings = append(result.Findings, finding("nuclei", id+matched, title, description, firstText(info, "severity"), .85))
	}
	sortFindings(&result)
	return result, nil
}

func parseGitleaks(data []byte, _ schema.RunRequest) (schema.Result, error) {
	docs, err := decodeDocuments(data)
	if err != nil {
		return emptyResult(), err
	}
	result := emptyResult()
	for _, d := range docs {
		rule := firstText(d, "RuleID", "rule_id")
		file := firstText(d, "File", "file")
		line := firstNumber(d, "StartLine", "start_line")
		if rule == "" {
			continue
		}
		desc := firstText(d, "Description", "description")
		location := fmt.Sprintf("%s:%d", file, line)
		result.Findings = append(result.Findings, finding("gitleaks", rule+location, "Potential secret: "+rule, strings.TrimSpace(desc+" Location: "+location+". Secret material was redacted."), "high", .8))
	}
	sortFindings(&result)
	return result, nil
}

func parseTruffleHog(data []byte, _ schema.RunRequest) (schema.Result, error) {
	docs, err := decodeDocuments(data)
	if err != nil {
		return emptyResult(), err
	}
	result := emptyResult()
	for _, d := range docs {
		detector := firstText(d, "DetectorName", "detector_name")
		if detector == "" {
			continue
		}
		verified, _ := d["Verified"].(bool)
		confidence := .75
		severity := "high"
		if verified {
			confidence = .98
			severity = "critical"
		}
		desc := "Potential secret detected; raw and decoded secret values were not retained in the normalized finding."
		// SourceID identifies an ingestion job, not an individual secret. Hash
		// the complete value and location so distinct secrets cannot collapse.
		location, err := json.Marshal(d["SourceMetadata"])
		if err != nil {
			return result, err
		}
		key := detector + "\x00" + text(d["Raw"]) + "\x00" + text(d["RawV2"]) + "\x00" + string(location)
		result.Findings = append(result.Findings, finding("trufflehog", key, "Potential secret: "+detector, desc, severity, confidence))
	}
	sortFindings(&result)
	return result, nil
}

func parseGosec(data []byte, _ schema.RunRequest) (schema.Result, error) {
	var root map[string]any
	if len(bytes.TrimSpace(data)) == 0 {
		return emptyResult(), nil
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return emptyResult(), err
	}
	result := emptyResult()
	for _, raw := range array(root["Issues"]) {
		d, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		rule := firstText(d, "rule_id", "RuleID")
		if rule == "" {
			continue
		}
		loc := firstText(d, "file") + ":" + firstText(d, "line")
		result.Findings = append(result.Findings, finding("gosec", rule+loc, rule+": "+firstText(d, "details"), "Location: "+loc+".", firstText(d, "severity"), confidence(firstText(d, "confidence"))))
	}
	sortFindings(&result)
	return result, nil
}

func parseSemgrep(data []byte, _ schema.RunRequest) (schema.Result, error) {
	var root map[string]any
	if len(bytes.TrimSpace(data)) == 0 {
		return emptyResult(), nil
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return emptyResult(), err
	}
	result := emptyResult()
	for _, raw := range array(root["results"]) {
		d, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		extra, _ := d["extra"].(map[string]any)
		start, _ := d["start"].(map[string]any)
		check := firstText(d, "check_id")
		if check == "" {
			continue
		}
		loc := fmt.Sprintf("%s:%d", firstText(d, "path"), number(start["line"]))
		result.Findings = append(result.Findings, finding("semgrep", check+loc, check, firstText(extra, "message")+" Location: "+loc+".", firstText(extra, "severity"), .8))
	}
	sortFindings(&result)
	return result, nil
}

func parseTrivy(data []byte, _ schema.RunRequest) (schema.Result, error) {
	var root map[string]any
	if len(bytes.TrimSpace(data)) == 0 {
		return emptyResult(), nil
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return emptyResult(), err
	}
	result := emptyResult()
	for _, rr := range array(root["Results"]) {
		r, ok := rr.(map[string]any)
		if !ok {
			continue
		}
		target := firstText(r, "Target")
		for _, raw := range array(r["Vulnerabilities"]) {
			d, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			id := firstText(d, "VulnerabilityID")
			if id == "" {
				continue
			}
			title := firstText(d, "Title")
			if title == "" {
				title = id
			}
			desc := firstText(d, "Description") + " Package: " + firstText(d, "PkgName") + " " + firstText(d, "InstalledVersion") + ". Target: " + target + "."
			result.Findings = append(result.Findings, finding("trivy", id+target+firstText(d, "PkgName"), title, strings.TrimSpace(desc), firstText(d, "Severity"), .9))
		}
		for _, raw := range append(array(r["Misconfigurations"]), array(r["Secrets"])...) {
			d, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			id := firstText(d, "ID", "RuleID")
			if id == "" {
				continue
			}
			title := firstText(d, "Title", "Category")
			if title == "" {
				title = id
			}
			desc := firstText(d, "Description", "Message") + " Target: " + target + ". Sensitive values were not retained."
			result.Findings = append(result.Findings, finding("trivy", id+target, title, strings.TrimSpace(desc), firstText(d, "Severity"), .85))
		}
	}
	sortFindings(&result)
	return result, nil
}

func parseSBOM(data []byte, _ schema.RunRequest) (schema.Result, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return emptyResult(), fmt.Errorf("SBOM output is empty")
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return emptyResult(), err
	}
	if _, cyclonedx := root["bomFormat"]; !cyclonedx {
		if _, syft := root["artifacts"]; !syft {
			return emptyResult(), fmt.Errorf("output is neither CycloneDX nor Syft JSON")
		}
	}
	return emptyResult(), nil
}

func parseGrype(data []byte, _ schema.RunRequest) (schema.Result, error) {
	var root map[string]any
	if len(bytes.TrimSpace(data)) == 0 {
		return emptyResult(), nil
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return emptyResult(), err
	}
	result := emptyResult()
	for _, raw := range array(root["matches"]) {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		v, _ := m["vulnerability"].(map[string]any)
		a, _ := m["artifact"].(map[string]any)
		id := firstText(v, "id")
		if id == "" {
			continue
		}
		desc := firstText(v, "description") + " Package: " + firstText(a, "name") + " " + firstText(a, "version") + "."
		result.Findings = append(result.Findings, finding("grype", id+firstText(a, "name")+firstText(a, "version"), id+" in "+firstText(a, "name"), strings.TrimSpace(desc), firstText(v, "severity"), .9))
	}
	sortFindings(&result)
	return result, nil
}

func finding(tool, key, title, description, sev string, conf float64) schema.Finding {
	sum := sha256.Sum256([]byte(tool + "\x00" + key))
	return schema.Finding{ID: tool + ":" + hex.EncodeToString(sum[:8]), Title: strings.TrimSpace(title), Description: strings.TrimSpace(description), Severity: severity(sev), Confidence: conf, EvidenceIDs: []string{}}
}
func severity(v string) schema.Severity {
	switch strings.ToLower(v) {
	case "critical", "error":
		return schema.SeverityCritical
	case "high", "warning", "warn":
		return schema.SeverityHigh
	case "medium", "moderate":
		return schema.SeverityMedium
	case "low":
		return schema.SeverityLow
	default:
		return schema.SeverityInfo
	}
}
func confidence(v string) float64 {
	switch strings.ToLower(v) {
	case "high":
		return .9
	case "medium":
		return .75
	case "low":
		return .55
	default:
		return .7
	}
}
func sortFindings(r *schema.Result) {
	sort.Slice(r.Findings, func(i, j int) bool { return r.Findings[i].ID < r.Findings[j].ID })
}
func sourceName(d map[string]any, fallback string) string {
	if v := firstText(d, "source"); v != "" {
		return v
	}
	return fallback
}
func firstText(d map[string]any, keys ...string) string {
	for _, k := range keys {
		if v := text(d[k]); v != "" {
			return v
		}
	}
	return ""
}
func firstNumber(d map[string]any, keys ...string) int {
	for _, k := range keys {
		if v := number(d[k]); v != 0 {
			return v
		}
	}
	return 0
}
func text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return ""
	}
}
func number(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case json.Number:
		n, _ := strconv.Atoi(x.String())
		return n
	case string:
		n, _ := strconv.Atoi(x)
		return n
	default:
		return 0
	}
}
func array(v any) []any {
	if x, ok := v.([]any); ok {
		return x
	}
	return []any{}
}
func texts(v any) []string {
	out := []string{}
	for _, x := range array(v) {
		if s := text(x); s != "" {
			out = append(out, s)
		}
	}
	if s := text(v); s != "" {
		out = append(out, s)
	}
	return out
}

func parseWhatWeb(data []byte, req schema.RunRequest) (schema.Result, error) {
	var docs []map[string]any
	if err := json.Unmarshal(data, &docs); err != nil {
		var single map[string]any
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return emptyResult(), fmt.Errorf("whatweb: %w", err)
		}
		docs = []map[string]any{single}
	}
	r := emptyResult()
	for _, doc := range docs {
		target := text(doc["target"])
		platform := text(doc["platform"])
		if target == "" {
			return emptyResult(), fmt.Errorf("whatweb: report record lacks target")
		}
		if target != "" || platform != "" {
			techs := []string{}
			if platform != "" {
				techs = append(techs, platform)
			}
			for _, t := range texts(doc["plugins"]) {
				if t != "" {
					techs = append(techs, t)
				}
			}
			r.Endpoints = append(r.Endpoints, schema.Endpoint{URL: target, Technology: techs})
		}
	}
	r.Summary = fmt.Sprintf("Fingerprinted %d target(s).", len(r.Endpoints))
	r.Confidence = 0.75
	return r, nil
}

func parseTextLines(data []byte, req schema.RunRequest) (schema.Result, error) {
	r := emptyResult()
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			r.Observations = append(r.Observations, evidence.DefaultHygieneRules.SanitizeText(line))
		}
	}
	if err := scanner.Err(); err != nil {
		return r, fmt.Errorf("read tool output: %w", err)
	}
	r.Status = "partial"
	r.Summary = fmt.Sprintf("Retained %d unstructured observation(s); findings were not verified.", len(r.Observations))
	r.Warnings = []string{"This adapter retains unstructured output and cannot establish whether the target has vulnerabilities."}
	r.Confidence = 0.5
	return r, nil
}

func parseTestSSL(data []byte, req schema.RunRequest) (schema.Result, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return emptyResult(), fmt.Errorf("testssl: %w", err)
	}
	if _, ok := doc["scanResult"].([]any); !ok {
		return emptyResult(), fmt.Errorf("testssl: missing scanResult array")
	}
	r := emptyResult()
	for _, scan := range array(doc["scanResult"]) {
		if m, ok := scan.(map[string]any); ok {
			id := text(m["id"])
			finding := text(m["finding"])
			severity := text(m["severity"])
			if id != "" && finding != "" {
				sev := schema.SeverityInfo
				switch strings.ToUpper(severity) {
				case "CRITICAL":
					sev = schema.SeverityCritical
				case "HIGH":
					sev = schema.SeverityHigh
				case "MEDIUM":
					sev = schema.SeverityMedium
				case "LOW":
					sev = schema.SeverityLow
				}
				h := sha256.Sum256([]byte("testssl" + id))
				r.Findings = append(r.Findings, schema.Finding{
					ID: hex.EncodeToString(h[:])[:8], Title: id,
					Description: finding, Severity: sev, Confidence: 0.9,
				})
			}
		}
	}
	r.Summary = fmt.Sprintf("TLS audit completed with %d finding(s).", len(r.Findings))
	r.Confidence = 0.85
	return r, nil
}

func parseSQLMap(data []byte, req schema.RunRequest) (schema.Result, error) {
	// Only a completed parameter block is positive evidence. Words in progress,
	// negative, and error messages are not findings.
	positive := regexp.MustCompile(`(?ms)^Parameter:\s*[^\r\n]+\r?\n\s+Type:\s*[^\r\n]+\r?\n\s+Title:\s*[^\r\n]+\r?\n\s+Payload:\s*[^\r\n]+`)
	blocks := positive.FindAllString(string(data), -1)
	r := emptyResult()
	for _, block := range blocks {
		r.Findings = append(r.Findings, finding("sqlmap", req.Target+block, "SQL injection reported", "A completed SQLMap parameter block reports an injection. Review the redacted evidence and impact before assigning final severity.", "high", .85))
	}
	if len(blocks) == 0 && !strings.Contains(strings.ToLower(string(data)), "all tested parameters do not appear to be injectable") {
		return parseTextLines(data, req)
	}
	r.Summary = fmt.Sprintf("SQLMap report contains %d confirmed parameter block(s).", len(blocks))
	r.Confidence = .75
	return r, nil
}

func parseJSLuice(data []byte, req schema.RunRequest) (schema.Result, error) {
	var docs []map[string]any
	if err := json.Unmarshal(data, &docs); err != nil {
		var single map[string]any
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return parseTextLines(data, req)
		}
		docs = []map[string]any{single}
	}
	r := emptyResult()
	for _, doc := range docs {
		if urlStr := text(doc["url"]); urlStr != "" {
			r.Endpoints = append(r.Endpoints, schema.Endpoint{URL: urlStr, Technology: []string{"javascript"}})
		}
		if secretStr := text(doc["secret"]); secretStr != "" {
			r.Findings = append(r.Findings, schema.Finding{
				ID:    "js-secret-" + secretFingerprint(secretStr),
				Title: "JavaScript Secret Detected", Description: "JSLuice detected a potential secret in JS.",
				Severity: schema.SeverityMedium, Confidence: 0.6,
			})
		}
	}
	if len(r.Endpoints) == 0 && len(r.Findings) == 0 {
		return parseTextLines(data, req)
	}
	r.Summary = fmt.Sprintf("JSLuice extracted %d endpoint(s) and %d finding(s).", len(r.Endpoints), len(r.Findings))
	r.Confidence = 0.65
	return r, nil
}

func parseCORS(data []byte, req schema.RunRequest) (schema.Result, error) {
	// Never infer a clean result or a vulnerability from a keyword alone.
	r := emptyResult()
	negative := regexp.MustCompile(`(?i)\b(?:not vulnerable|not misconfigured|no (?:cors )?(?:vulnerabilities|misconfigurations)(?: were)? (?:found|detected))\b`)
	positive := regexp.MustCompile(`(?i)^\s*(?:https?://\S+|target)\s+is\s+(?:potentially\s+)?(?:vulnerable|misconfigured)\b`)
	sawNegative, sawPositive := false, false
	for _, line := range strings.Split(string(data), "\n") {
		if negative.MatchString(line) {
			sawNegative = true
			continue
		}
		if positive.MatchString(line) {
			sawPositive = true
		}
	}
	if sawPositive {
		r.Findings = append(r.Findings, finding("corscanner", req.Target, "Potential CORS misconfiguration", "The scanner explicitly reported a potentially vulnerable target; verify the response headers and credential behavior.", "medium", .7))
	} else if !sawNegative {
		return parseTextLines(data, req)
	}
	r.Summary = fmt.Sprintf("CORS report contains %d potential finding(s).", len(r.Findings))
	r.Confidence = .7
	return r, nil
}

func parseWPScan(data []byte, req schema.RunRequest) (schema.Result, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return emptyResult(), fmt.Errorf("wpscan: %w", err)
	}
	if root == nil {
		return emptyResult(), fmt.Errorf("wpscan: missing report")
	}
	if message := firstText(root, "scan_aborted", "error"); message != "" {
		return emptyResult(), fmt.Errorf("wpscan: %s", message)
	}
	target := firstText(root, "target_url")
	if target == "" {
		return emptyResult(), fmt.Errorf("wpscan: missing target_url")
	}
	r := emptyResult()
	addVulnerabilities := func(component string, value any) error {
		obj, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		raw, exists := obj["vulnerabilities"]
		if !exists || raw == nil {
			return nil
		}
		vulnerabilities, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("wpscan: invalid vulnerability list")
		}
		for _, item := range vulnerabilities {
			v, ok := item.(map[string]any)
			if !ok || firstText(v, "title") == "" {
				return fmt.Errorf("wpscan: malformed vulnerability record")
			}
			title := firstText(v, "title")
			r.Findings = append(r.Findings, finding("wpscan", target+component+title, title,
				"WPScan reports a known issue affecting "+component+" at "+target+". Verify the installed version and applicability.", "info", .7))
		}
		return nil
	}
	for _, key := range []string{"version", "main_theme"} {
		if err := addVulnerabilities(key, root[key]); err != nil {
			return emptyResult(), err
		}
	}
	for _, group := range []string{"plugins", "themes"} {
		for name, value := range object(root[group]) {
			if err := addVulnerabilities(group+":"+name, value); err != nil {
				return emptyResult(), err
			}
		}
	}
	r.Endpoints = append(r.Endpoints, schema.Endpoint{URL: target, Technology: []string{"wordpress"}})
	if number(object(root["vuln_api"])["requests_done_during_scan"]) == 0 {
		r.Status = "partial"
		r.Warnings = append(r.Warnings, "Vulnerability API coverage was not confirmed; an empty finding list does not establish that WordPress is free of known issues.")
	}
	sortFindings(&r)
	r.Summary = fmt.Sprintf("WPScan reported %d version-associated issue(s); verify applicability and severity.", len(r.Findings))
	r.Confidence = .7
	return r, nil
}

func object(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func parseJSONPassthrough(data []byte, req schema.RunRequest) (schema.Result, error) {
	if !json.Valid(data) {
		return parseTextLines(data, req)
	}
	sanitized, err := evidence.DefaultHygieneRules.SanitizeJSON(data)
	if err != nil {
		return emptyResult(), err
	}
	r := emptyResult()
	r.Observations = []string{string(sanitized)}
	r.Status = "partial"
	r.Summary = "Retained structured tool output for manual review; no findings were inferred."
	r.Warnings = []string{"This adapter has no tool-specific finding normalization; review the retained observation."}
	r.Confidence = .5
	return r, nil
}

func secretFingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
