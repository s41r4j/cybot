package capability

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/pkg/schema"
)

func tlsFixture() map[string]any {
	// Shape and protocol identifiers from a real Debian TestSSL 3.2.1 run.
	return map[string]any{"schema": 1, "engine": "testssl", "version": "3.2.1", "target": "fixture.invalid:8443", "checks": "protocols", "completed": true, "exit_code": 0, "error": "",
		"report": map[string]any{"version": "3.2.1", "scanTime": 18, "scanResult": []any{map[string]any{"targetHost": "fixture.invalid", "ip": "127.0.0.1", "port": "8443", "service": "HTTP", "protocols": []any{
			map[string]any{"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
			map[string]any{"id": "TLS1_1", "severity": "LOW", "finding": "offered (deprecated)"},
			map[string]any{"id": "TLS1_2", "severity": "OK", "finding": "offered"},
			map[string]any{"id": "TLS1_3", "severity": "INFO", "finding": "not offered + downgraded to weaker protocol"},
		}}}}}
}

func decodeTLSFixture(t *testing.T, doc map[string]any) (schema.Result, error) {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{"checks": doc["checks"]})
	return parseTestSSL(data, schema.RunRequest{Target: "fixture.invalid:8443", Input: input})
}

func TestTLSRequestCheckScopeIsValidatedBeforeExecution(t *testing.T) {
	c := liveCapability(t, "tls.audit")
	for _, input := range []string{`null`, `{"checks":null}`, `{"checks":"--proxy"}`, `{"checks":""}`, `{"target":"elsewhere.invalid"}`, `{"unexpected":true}`, `{} {}`} {
		if err := c.ValidateRequest(schema.RunRequest{Target: "fixture.invalid:8443", Input: json.RawMessage(input)}); err == nil {
			t.Fatal("invalid TLS scope accepted", input)
		}
		if _, err := c.Run(context.Background(), schema.RunRequest{Target: "fixture.invalid:8443", Input: json.RawMessage(input)}, Dependencies{}); err == nil {
			t.Fatal("TLS execution accepted invalid input before dependency lookup", input)
		}
	}
	data, _ := json.Marshal(tlsFixture())
	if _, err := parseTestSSL(data, schema.RunRequest{Target: "fixture.invalid:8443"}); err == nil {
		t.Fatal("protocol report satisfied a requested full scan")
	}
}

func TestTLSFullScanCannotBeSatisfiedByOnlyProtocolGroups(t *testing.T) {
	doc := tlsFixture()
	doc["checks"] = "full"
	r, err := decodeTLSFixture(t, doc)
	if err != nil || r.Status != "partial" || len(r.Errors) == 0 || len(r.Findings) != 2 {
		t.Fatalf("missing full-scan groups were accepted or erased matches: %+v %v", r, err)
	}
}

func TestTLSNestedProtocolFindingsAndCleanObservations(t *testing.T) {
	doc := tlsFixture()
	r, err := decodeTLSFixture(t, doc)
	if err != nil || r.Status == "partial" || len(r.Findings) != 2 || len(r.Observations) < 2 || len(r.Services) != 1 || r.Services[0].Port != 8443 {
		t.Fatalf("real nested protocol report was not normalized: %+v %v", r, err)
	}
	for _, f := range r.Findings {
		if f.Severity != schema.SeverityLow || !strings.Contains(f.Title, "TLS1") {
			t.Fatalf("OK/INFO records became vulnerabilities: %+v", f)
		}
	}
	scan := doc["report"].(map[string]any)["scanResult"].([]any)[0].(map[string]any)
	scan["protocols"] = []any{map[string]any{"id": "TLS1_2", "severity": "OK", "finding": "offered"}}
	r, err = decodeTLSFixture(t, doc)
	if err != nil || r.Status == "partial" || len(r.Findings) != 0 {
		t.Fatalf("clean protocol observations created a vulnerability: %+v %v", r, err)
	}
}

func TestTLSFailuresRetainValidatedFindingsWithoutCleanAssurance(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(d map[string]any) { d["completed"] = false; d["exit_code"] = 1 },
		func(d map[string]any) { d["report"].(map[string]any)["scanTime"] = "Scan interrupted" },
		func(d map[string]any) { d["report"].(map[string]any)["scanTime"] = nil },
		func(d map[string]any) { d["report"].(map[string]any)["unhandledChecks"] = []any{} },
	} {
		doc := tlsFixture()
		mutate(doc)
		r, err := decodeTLSFixture(t, doc)
		if err != nil || len(r.Findings) != 2 || r.Status != "partial" || len(r.Errors) == 0 || r.Confidence != 0 {
			t.Fatalf("partial TLS report lost matches or became clean: %+v %v", r, err)
		}
	}
	doc := tlsFixture()
	doc["completed"], doc["exit_code"], doc["report"] = false, 1, nil
	r, err := decodeTLSFixture(t, doc)
	if err != nil || r.Status != "partial" || len(r.Errors) == 0 || len(r.Findings) != 0 {
		t.Fatalf("missing failed-engine report looked clean: %+v %v", r, err)
	}
}

func TestTLSReportCannotChangeEndpointOrEngineVersion(t *testing.T) {
	for key, value := range map[string]string{"targetHost": "elsewhere.invalid", "ip": "not-an-address", "port": "443"} {
		doc := tlsFixture()
		doc["report"].(map[string]any)["scanResult"].([]any)[0].(map[string]any)[key] = value
		if _, err := decodeTLSFixture(t, doc); err == nil {
			t.Fatal("foreign/incomplete endpoint was accepted", key)
		}
	}
	doc := tlsFixture()
	doc["report"].(map[string]any)["version"] = "3.2.0"
	if _, err := decodeTLSFixture(t, doc); err == nil {
		t.Fatal("unvalidated engine version was accepted")
	}
}

func TestTLSClientLimitationsRemainExplicit(t *testing.T) {
	doc := tlsFixture()
	doc["report"].(map[string]any)["clientProblem1"] = []any{map[string]any{"id": "engine_problem", "severity": "WARN", "finding": "No engine or GOST support via engine with your /fixture/openssl"}}
	r, err := decodeTLSFixture(t, doc)
	if err != nil || r.Status == "partial" || len(r.Warnings) == 0 {
		t.Fatalf("protocol-only GOST limitation was not explained: %+v %v", r, err)
	}
	doc["checks"] = "full"
	r, err = decodeTLSFixture(t, doc)
	if err != nil || r.Status != "partial" || len(r.Errors) == 0 || len(r.Findings) != 2 {
		t.Fatalf("full TLS scan hid a missing cipher engine: %+v %v", r, err)
	}
}

func TestTLSTargetPortsRemainBoundedData(t *testing.T) {
	for _, valid := range []string{"fixture.invalid", "fixture.invalid:8443", "127.0.0.1:443", "::1", "[::1]:8443"} {
		if _, _, err := tlsEndpoint(valid); err != nil {
			t.Fatal("valid endpoint rejected", valid, err)
		}
	}
	for _, invalid := range []string{"--proxy=elsewhere", "fixture.invalid:0", "fixture.invalid:65536", "fixture.invalid:+443", "fixture.invalid:443/path", "https://fixture.invalid", "[::1]", "[fixture.invalid]:443", "[127.0.0.1]:443", "fe80::1%lo0", "fixture.invalid\n--file"} {
		if _, _, err := tlsEndpoint(invalid); err == nil {
			t.Fatal("unsafe/malformed TLS target accepted", invalid)
		}
	}
}
