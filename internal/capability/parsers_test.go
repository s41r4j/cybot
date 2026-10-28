package capability

import (
	"encoding/json"
	"testing"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestLockedParsersAcceptFixtures(t *testing.T) {
	tests := []struct {
		tool  string
		data  string
		count func(schema.Result) int
	}{
		{"subfinder", `{"host":"api.example.com","source":"crtsh"}`, func(r schema.Result) int { return len(r.Assets) }},
		{"amass", `{"name":"api.example.com","addresses":[{"ip":"192.0.2.10"}]}`, func(r schema.Result) int { return len(r.Assets) }},
		{"dnsx", `{"host":"api.example.com","a":["192.0.2.10"],"aaaa":["2001:db8::10"]}`, func(r schema.Result) int { return len(r.Assets) }},
		{"naabu", `{"host":"192.0.2.10","port":443,"protocol":"tcp"}`, func(r schema.Result) int { return len(r.Services) }},
		{"httpx", `{"url":"https://example.com","status_code":200,"tech":["nginx"]}`, func(r schema.Result) int { return len(r.Endpoints) }},
		{"katana", `{"request":{"endpoint":"https://example.com/login"},"method":"GET"}`, func(r schema.Result) int { return len(r.Endpoints) }},
		{"ffuf", `{"url":"https://example.com/admin","status":403}`, func(r schema.Result) int { return len(r.Endpoints) }},
		{"nuclei", `{"template-id":"tls-version","matched-at":"https://example.com","info":{"name":"Old TLS","severity":"medium","description":"Legacy protocol"}}`, func(r schema.Result) int { return len(r.Findings) }},
		{"gitleaks", `[{"RuleID":"generic-api-key","Description":"key","File":"app.js","StartLine":7,"Secret":"do-not-retain"}]`, func(r schema.Result) int { return len(r.Findings) }},
		{"trufflehog", `{"DetectorName":"AWS","Verified":true,"SourceID":1,"Raw":"do-not-retain"}`, func(r schema.Result) int { return len(r.Findings) }},
		{"gosec", `{"Issues":[{"rule_id":"G401","details":"weak crypto","file":"main.go","line":"8","severity":"HIGH","confidence":"HIGH"}]}`, func(r schema.Result) int { return len(r.Findings) }},
		{"semgrep", `{"results":[{"check_id":"cybot.eval","path":"app.js","start":{"line":3},"extra":{"message":"eval used","severity":"ERROR"}}]}`, func(r schema.Result) int { return len(r.Findings) }},
		{"trivy", `{"Results":[{"Target":"app","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-1","PkgName":"lib","InstalledVersion":"1","Title":"issue","Description":"details","Severity":"HIGH"}]}]}`, func(r schema.Result) int { return len(r.Findings) }},
		{"syft", `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`, func(r schema.Result) int { return 1 }},
		{"grype", `{"matches":[{"vulnerability":{"id":"CVE-2026-2","severity":"Critical","description":"details"},"artifact":{"name":"lib","version":"1"}}]}`, func(r schema.Result) int { return len(r.Findings) }},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			r, err := parseTool(tt.tool, []byte(tt.data), schema.RunRequest{Target: "https://example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if got := tt.count(r); got < 1 {
				t.Fatalf("fixture was not normalized: %#v", r)
			}
		})
	}
}

func TestEveryRegisteredExternalToolHasParser(t *testing.T) {
	r := NewRegistry()
	if err := RegisterBuiltins(r); err != nil {
		t.Fatal(err)
	}
	for _, capability := range r.List() {
		for _, choice := range capability.Definition().ToolChoices {
			if choice.ToolID == "system-dns-resolver" || choice.ToolID == "subdomain-enumerator" {
				continue
			}
			if _, ok := parsers[choice.ToolID]; !ok {
				t.Errorf("%s uses %s without parser", capability.ID(), choice.ToolID)
			}
		}
	}
}

func TestMalformedOutputFailsClosed(t *testing.T) {
	for _, tool := range []string{"dnsx", "naabu", "httpx", "nuclei", "gitleaks", "trufflehog", "gosec", "semgrep", "trivy", "syft", "grype"} {
		if _, err := parseTool(tool, []byte(`not-json`), schema.RunRequest{}); err == nil {
			t.Errorf("%s accepted malformed output", tool)
		}
	}
}

func TestSecretEvidenceIsRedacted(t *testing.T) {
	for _, tool := range []string{"gitleaks", "trufflehog", "trivy"} {
		input := []byte(`{"Secret":"sensitive","Raw":"sensitive","Match":"sensitive","nested":{"rawV2":"sensitive"}}`)
		out, _, err := evidenceOutput(tool, input)
		if err != nil {
			t.Fatal(err)
		}
		if json.Valid(out) == false {
			t.Fatalf("%s produced invalid JSON", tool)
		}
		if string(out) == string(input) || containsSensitive(string(out)) {
			t.Fatalf("%s retained secret evidence: %s", tool, out)
		}
	}
}

func containsSensitive(v string) bool {
	return len(v) > 0 && (json.Valid([]byte(v)) && stringContains(v, "sensitive"))
}
func stringContains(v, sub string) bool {
	for i := 0; i+len(sub) <= len(v); i++ {
		if v[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
