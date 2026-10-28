package capability

import (
	"strings"
	"testing"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestParseZAPBaseline(t *testing.T) {
	fixture := []byte(`{
  "site": [{
    "name": "https://example.com",
    "alerts": [
      {"alert":"SQL Injection","riskdesc":"High","riskcode":"3","confidence":"3","desc":"SQL injection found.","solution":"Use parameterized queries.","instances":[{"uri":"https://example.com/search?id=1","method":"GET"}]},
      {"alert":"XSS","riskdesc":"Medium","riskcode":"2","confidence":"2","desc":"Reflected XSS.","instances":[{"uri":"https://example.com/q?x=1"}]},
      {"alert":"Info Disclosure","riskdesc":"Low","riskcode":"1","confidence":"1","desc":"Banner.","instances":[{"uri":"https://example.com/"}]}
    ]
  }]
}`)
	r, err := parseZAPBaseline(fixture, schema.RunRequest{Target: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(r.Findings))
	}
	sev := map[string]schema.Severity{}
	for _, f := range r.Findings {
		sev[f.Title] = f.Severity
		if !strings.Contains(f.Description, "Affected:") {
			t.Errorf("finding %q missing affected URI", f.Title)
		}
	}
	if sev["SQL Injection"] != schema.SeverityHigh || sev["XSS"] != schema.SeverityMedium || sev["Info Disclosure"] != schema.SeverityLow {
		t.Errorf("unexpected severity mapping: %#v", sev)
	}
}

func TestParseZAPBaselineEmpty(t *testing.T) {
	r, err := parseZAPBaseline([]byte(`{"site":[]}`), schema.RunRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("expected no findings for clean scan, got %d", len(r.Findings))
	}
}

func TestZAPArgsAreDeterministic(t *testing.T) {
	args := zapBaselineArgs("https://example.com")
	want := []string{"-t", "https://example.com", "-J", "cybot-report.json", "-m", "1", "-T", "5", "--autooff"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("unexpected zap args: %v", args)
	}
}

func TestZAPSpecCollectsReportAndAcceptsAlertExits(t *testing.T) {
	spec := executionSpecZAP(Dependencies{}, schema.Tool{Binary: "zap-baseline.py"}, "https://example.test/?a=one&b=two")
	if spec.Entrypoint != "sh" || !spec.Network || len(spec.AcceptExitCodes) != 2 || spec.AcceptExitCodes[0] != 1 || spec.AcceptExitCodes[1] != 2 {
		t.Fatalf("wrong ZAP execution contract: %#v", spec)
	}
	if !strings.Contains(spec.Args[1], `"$@" >&2`) || !strings.Contains(spec.Args[1], "cat /zap/wrk/cybot-report.json") {
		t.Fatal("progress stdout mixes with report")
	}
	found := false
	for _, arg := range spec.Args {
		if arg == "https://example.test/?a=one&b=two" {
			found = true
		}
	}
	if !found {
		t.Fatal("target was interpolated into shell source")
	}
}
