package capability

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/pkg/schema"
)

func tlsEndpoint(target string) (string, int, error) {
	host, port := target, 443
	if net.ParseIP(target) == nil && strings.Contains(target, ":") {
		var raw string
		var err error
		host, raw, err = net.SplitHostPort(target)
		if err != nil || raw == "" || len(raw) > 5 {
			return "", 0, fmt.Errorf("TLS target must be a hostname/IP with an optional TCP port; bracket IPv6 ports")
		}
		if strings.HasPrefix(target, "[") && (net.ParseIP(host) == nil || !strings.Contains(host, ":")) {
			return "", 0, fmt.Errorf("TLS brackets are reserved for IPv6 addresses")
		}
		for _, c := range raw {
			if c < '0' || c > '9' {
				return "", 0, fmt.Errorf("TLS target requires a numeric TCP port")
			}
		}
		port, err = strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("TLS target TCP port is outside 1–65535")
		}
	}
	if net.ParseIP(host) == nil {
		if err := validateHostname(host); err != nil {
			return "", 0, err
		}
	}
	return host, port, nil
}

type tlsCheck struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	CVE      string `json:"cve,omitempty"`
	CWE      string `json:"cwe,omitempty"`
	Hint     string `json:"hint,omitempty"`
}

func tlsChecks(req schema.RunRequest) (string, error) {
	data := bytes.TrimSpace(req.Input)
	if len(data) == 0 {
		return "full", nil
	}
	var input struct {
		Target json.RawMessage `json:"target,omitempty"`
		Checks json.RawMessage `json:"checks,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if len(data) > 4096 || data[0] != '{' || decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		return "", fmt.Errorf("TLS input must be one bounded object containing target and optional checks")
	}
	if len(input.Target) != 0 {
		var target string
		if json.Unmarshal(input.Target, &target) != nil || target != req.Target {
			return "", fmt.Errorf("TLS input cannot change the requested target")
		}
	}
	if len(input.Checks) == 0 {
		return "full", nil
	}
	var checks string
	if json.Unmarshal(input.Checks, &checks) != nil || checks != "full" && checks != "protocols" {
		return "", fmt.Errorf("TLS checks must be full or protocols")
	}
	return checks, nil
}

func (c externalCapability) ValidateRequest(req schema.RunRequest) error {
	if c.ID() != "tls.audit" {
		return nil
	}
	if _, _, err := tlsEndpoint(req.Target); err != nil {
		return err
	}
	_, err := tlsChecks(req)
	return err
}

func parseTestSSL(data []byte, req schema.RunRequest) (schema.Result, error) {
	r := emptyResult()
	var wrapper struct {
		Schema    int             `json:"schema"`
		Engine    string          `json:"engine"`
		Version   string          `json:"version"`
		Target    string          `json:"target"`
		Checks    string          `json:"checks"`
		Completed bool            `json:"completed"`
		ExitCode  *int            `json:"exit_code"`
		Report    json.RawMessage `json:"report"`
		Error     string          `json:"error"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if len(data) > 16*1024*1024 || decoder.Decode(&wrapper) != nil || decoder.Decode(new(any)) != io.EOF {
		return r, fmt.Errorf("testssl: missing bounded structured report")
	}
	if wrapper.Schema != 1 || wrapper.Engine != "testssl" || wrapper.Version != "3.2.1" || wrapper.ExitCode == nil || wrapper.Target != strings.TrimSpace(req.Target) || wrapper.Checks != "full" && wrapper.Checks != "protocols" {
		return r, fmt.Errorf("testssl: unsupported or differently scoped report")
	}
	expected, err := tlsChecks(req)
	if err != nil || wrapper.Checks != expected {
		return r, fmt.Errorf("testssl: report does not match the requested TLS check scope")
	}
	host, port, err := tlsEndpoint(wrapper.Target)
	if err != nil {
		return r, err
	}
	incomplete := func(detail string) {
		r.Status = "partial"
		r.Errors = append(r.Errors, schema.RunError{Tool: "testssl", Code: "TLS_ASSESSMENT_INCOMPLETE", Message: detail})
	}
	if !wrapper.Completed || *wrapper.ExitCode != 0 || wrapper.Error != "" {
		incomplete("TestSSL did not establish a completed operation.")
	}
	var report map[string]json.RawMessage
	if json.Unmarshal(wrapper.Report, &report) != nil || report == nil {
		if r.Status == "partial" {
			return r, nil
		}
		return r, fmt.Errorf("testssl: engine report is missing")
	}
	var version string
	if json.Unmarshal(report["version"], &version) != nil || len(strings.Fields(version)) == 0 || strings.Fields(version)[0] != wrapper.Version {
		if r.Status == "partial" {
			return r, nil
		}
		return emptyResult(), fmt.Errorf("testssl: engine version differs from its adapter")
	}
	var duration *float64
	if json.Unmarshal(report["scanTime"], &duration) != nil || duration == nil || *duration < 0 {
		incomplete("TestSSL scan footer is missing or reports interruption.")
	}
	var scans []map[string]json.RawMessage
	if json.Unmarshal(report["scanResult"], &scans) != nil || scans == nil || len(scans) > 1 {
		return emptyResult(), fmt.Errorf("testssl: expected one scoped TLS endpoint")
	}
	if len(scans) == 0 {
		incomplete("TestSSL did not test a TLS endpoint.")
		return r, nil
	}
	var actualHost, actualIP, actualPort string
	scan := scans[0]
	if json.Unmarshal(scan["targetHost"], &actualHost) != nil || json.Unmarshal(scan["ip"], &actualIP) != nil || json.Unmarshal(scan["port"], &actualPort) != nil || net.ParseIP(actualIP) == nil {
		return emptyResult(), fmt.Errorf("testssl: endpoint identity is incomplete")
	}
	p, err := strconv.Atoi(actualPort)
	sameHost := strings.EqualFold(host, actualHost)
	if ip := net.ParseIP(host); ip != nil {
		sameHost = ip.Equal(net.ParseIP(actualHost)) && ip.Equal(net.ParseIP(actualIP))
	}
	if err != nil || p != port || !sameHost {
		return emptyResult(), fmt.Errorf("testssl: report describes a different TLS endpoint")
	}
	sections := []string{"pretest", "protocols", "grease", "ciphers", "serverPreferences", "fs", "serverDefaults", "headerResponse", "vulnerabilities", "cipherTests", "browserSimulations", "rating"}
	known := map[string]bool{"targetHost": true, "ip": true, "port": true, "rDNS": true, "service": true, "hostname": true}
	checks, seen := 0, map[string]bool{}
	consume := func(raw json.RawMessage, section string, client bool) {
		var rows []json.RawMessage
		if json.Unmarshal(raw, &rows) != nil || rows == nil || len(rows) > 10000 {
			incomplete("TestSSL returned an invalid check section.")
			return
		}
		for _, row := range rows {
			var check tlsCheck
			decoder := json.NewDecoder(bytes.NewReader(row))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&check) != nil || check.ID == "" || len(check.ID) > 256 || check.Finding == "" || len(check.Finding) > 16384 || len(check.Hint) > 16384 || len(check.CVE) > 4096 || len(check.CWE) > 1024 {
				incomplete("TestSSL returned an invalid check record.")
				continue
			}
			identity := section + "/" + check.ID
			if seen[identity] {
				incomplete("TestSSL repeated a check identity.")
				continue
			}
			seen[identity] = true
			text := evidence.DefaultHygieneRules.SanitizeText(check.ID + ": " + check.Finding)
			if client {
				r.Warnings = append(r.Warnings, text)
				// GOST cipher-engine support is outside protocol negotiation.
				if wrapper.Checks != "protocols" || check.ID != "engine_problem" || check.Severity != "WARN" || !strings.HasPrefix(check.Finding, "No engine or GOST support via engine with your ") {
					incomplete("The scanner reported a client-side limitation.")
				}
				continue
			}
			checks++
			severity := map[string]schema.Severity{"LOW": schema.SeverityLow, "MEDIUM": schema.SeverityMedium, "HIGH": schema.SeverityHigh, "CRITICAL": schema.SeverityCritical}[check.Severity]
			if severity != "" {
				digest := sha256.Sum256([]byte(net.JoinHostPort(host, strconv.Itoa(port)) + "\x00" + identity))
				r.Findings = append(r.Findings, schema.Finding{ID: hex.EncodeToString(digest[:])[:16], Title: check.ID, Description: text + ". Review deployment context and supporting handshake evidence before assigning impact.", Severity: severity, Confidence: .9, EvidenceIDs: []string{}})
			} else if check.Severity == "OK" || check.Severity == "INFO" || check.Severity == "WARN" {
				r.Observations = append(r.Observations, text)
				if check.Severity == "WARN" {
					r.Warnings = append(r.Warnings, text)
				}
			} else {
				incomplete("TestSSL returned a fatal or unsupported check severity.")
				checks--
			}
		}
	}
	for key, raw := range report {
		if strings.HasPrefix(key, "clientProblem") {
			consume(raw, key, true)
		} else if key != "version" && key != "openssl" && key != "startTime" && key != "scanResult" && key != "scanTime" {
			incomplete("TestSSL returned an unsupported report section.")
		}
	}
	for _, section := range sections {
		known[section] = true
		if raw, ok := scan[section]; ok {
			consume(raw, section, false)
		}
	}
	required := []string{"protocols"}
	if wrapper.Checks == "full" {
		required = append(required, "ciphers", "serverPreferences", "serverDefaults", "vulnerabilities")
	}
	for _, section := range required {
		var rows []json.RawMessage
		if json.Unmarshal(scan[section], &rows) != nil || len(rows) == 0 {
			incomplete("TestSSL did not complete requested check group: " + section)
		}
	}
	for key := range scan {
		if !known[key] {
			incomplete("TestSSL returned an unsupported target section.")
		}
	}
	if checks == 0 {
		incomplete("TestSSL returned no completed check records.")
	}
	if checks > 0 {
		r.Services = append(r.Services, schema.Service{Host: actualIP, Port: port, Protocol: "tcp", Technology: "TLS", Confidence: .9})
	}
	r.Observations = append(r.Observations, "TLS assessment covers one selected address; additional DNS addresses and external revocation services are not assessed.")
	r.Summary = fmt.Sprintf("TestSSL normalized %d check(s) for one TLS endpoint, retaining %d finding(s).", checks, len(r.Findings))
	if r.Status != "partial" {
		r.Confidence = .9
	}
	return r, nil
}
