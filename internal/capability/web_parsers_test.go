package capability

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestWebFingerprintContractsPreserveCandidatesWithoutInventingFindings(t *testing.T) {
	whatweb := `[{"target":"https://user:synthetic-password@fixture.invalid/?token=synthetic-marker","http_status":200,"plugins":{"PHP":{"version":["8.2.0"]},"Title":{"string":["A page title"]},"IP":{"string":["127.0.0.1"]}}}]`
	r, err := parseWhatWeb([]byte(whatweb), schema.RunRequest{})
	if err != nil || len(r.Endpoints) != 1 || r.Endpoints[0].Status != 200 || len(r.Endpoints[0].Technology) != 1 || r.Endpoints[0].Technology[0] != "PHP/8.2.0" || len(r.Findings) != 0 {
		t.Fatalf("plugin map was lost or invented findings: %+v %v", r, err)
	}
	encoded, _ := json.Marshal(r)
	if strings.Contains(string(encoded), "synthetic-password") || strings.Contains(string(encoded), "synthetic-marker") {
		t.Fatal("URL credentials escaped fingerprint normalization")
	}
	waf := `[{"url":"https://fixture.invalid/","detected":true,"firewall":"Cloudflare","manufacturer":"Cloudflare Inc."},{"url":"https://fixture.invalid/","detected":true,"firewall":"Generic","manufacturer":"Unknown"},{"url":"https://fixture.invalid/","detected":false,"firewall":"None","manufacturer":"None"}]`
	r, err = parseWafw00f([]byte(waf), schema.RunRequest{})
	if err != nil || len(r.Endpoints) != 1 || len(r.Endpoints[0].Technology) != 2 || len(r.Findings) != 0 {
		t.Fatalf("multiple WAF signatures were dropped: %+v %v", r, err)
	}
	negative := `[{"url":"https://fixture.invalid/","detected":false,"firewall":"None","manufacturer":"None"}]`
	r, err = parseWafw00f([]byte(negative), schema.RunRequest{})
	if err != nil || len(r.Endpoints) != 1 || len(r.Endpoints[0].Technology) != 0 || len(r.Findings) != 0 {
		t.Fatalf("explicit negative WAF result invented a match: %+v %v", r, err)
	}
}

func TestWebFingerprintRejectsEmptyAndMalformedResponseReports(t *testing.T) {
	for _, test := range []struct{ tool, report string }{
		{"whatweb", `[]`}, {"whatweb", `{}`}, {"whatweb", `[{"target":"https://fixture.invalid/","http_status":0,"plugins":{}}]`},
		{"whatweb", `[{"target":"https://fixture.invalid/","http_status":200,"plugins":["invented-shape"]}]`},
		{"wafw00f", `[]`}, {"wafw00f", `[{}]`}, {"wafw00f", `[{"url":"https://fixture.invalid/","firewall":"None","manufacturer":"None"}]`},
		{"wafw00f", `[{"url":"https://fixture.invalid/","detected":false,"firewall":"Cloudflare","manufacturer":"Cloudflare Inc."}]`},
	} {
		if _, err := parseTool(test.tool, []byte(test.report), schema.RunRequest{}); err == nil {
			t.Fatalf("%s accepted an incomplete response: %s", test.tool, test.report)
		}
	}
}

func TestGobusterExpandedRecordContract(t *testing.T) {
	r, err := parseGobuster([]byte("https://fixture.invalid/admin (Status: 200) [Size: 12]\nhttps://fixture.invalid/private (Status: 403) [Size: 0]\n"), schema.RunRequest{})
	if err != nil || len(r.Endpoints) != 2 || r.Endpoints[1].Status != 403 || len(r.Findings) != 0 {
		t.Fatalf("HTTP discovery records were lost: %+v %v", r, err)
	}
	if r, err := parseGobuster(nil, schema.RunRequest{}); err != nil || len(r.Endpoints) != 0 || len(r.Findings) != 0 {
		t.Fatal("a completed no-match stream was not accepted", err)
	}
	for _, data := range []string{"[ERROR] request failed", "Gobuster help text", "admin (Status: 200)", "https://fixture.invalid/ (Status: 0)", strings.Repeat("x", 65537)} {
		if _, err := parseGobuster([]byte(data), schema.RunRequest{}); err == nil {
			t.Fatal("non-result output became a successful content scan")
		}
	}
}
