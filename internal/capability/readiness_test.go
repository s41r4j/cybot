package capability

import (
	"context"
	"errors"
	"testing"

	"github.com/s41r4j/cybot/catalog"
	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/pkg/schema"
)

type readinessRunner struct {
	installed map[string]bool
	calls     int
}

func (r *readinessRunner) Health(_ context.Context, tool schema.Tool) error {
	r.calls++
	if r.installed[tool.ID] {
		return nil
	}
	return errors.New("fixture: executable missing")
}
func (*readinessRunner) Run(context.Context, execution.Spec) (execution.Output, error) {
	panic("readiness must not execute tools")
}

func TestReadinessCoversCatalogWithoutScanning(t *testing.T) {
	caps := NewRegistry()
	if err := RegisterBuiltins(caps); err != nil {
		t.Fatal(err)
	}
	tools := registry.NewTools()
	all, err := catalog.Tools()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range append(all, BuiltinTools()...) {
		if err := tools.Upsert(tool); err != nil {
			t.Fatal(err)
		}
	}
	runner := &readinessRunner{installed: map[string]bool{"httpx": true, "nuclei": true, "ffuf": true}}
	report := InspectReadiness(context.Background(), caps, tools, runner)
	if len(report.Tools) != 84 || len(report.Capabilities) != 71 {
		t.Fatalf("audit lost entries: %d/%d", len(report.Tools), len(report.Capabilities))
	}
	if runner.calls != 83 {
		t.Fatalf("health checks repeated or built-in checked: %d", runner.calls)
	}
	expected := map[string]string{"web.map": "partial", "web.scan": "ready-to-test", "api.audit": "ready-to-test", "code.audit": "unavailable", "exploit.execute": "not-implemented", "pattern.detect": "not-implemented", "classify.endpoint": "built-in"}
	for _, c := range report.Capabilities {
		if want, ok := expected[c.ID]; ok && c.Status != want {
			t.Errorf("%s = %s, want %s", c.ID, c.Status, want)
		}
	}
}

func TestIncompleteAdaptersCannotReportSuccessfulExecution(t *testing.T) {
	tools := registry.NewTools()
	for id := range incompleteAdapters {
		t.Run(id, func(t *testing.T) {
			if err := tools.Upsert(schema.Tool{ID: id, Kind: "native", Binary: id}); err != nil {
				t.Fatal(err)
			}
			c := external("fixture", "Fixture", "test", []string{id}, nil, toolStep{ID: id})
			r, err := c.Run(context.Background(), schema.RunRequest{Target: "fixture"}, Dependencies{Tools: tools, Runner: &readinessRunner{}, Evidence: evidence.New(t.TempDir())})
			if err == nil || len(r.Errors) != 1 || r.Errors[0].Code != "ADAPTER_NOT_IMPLEMENTED" || len(r.Evidence) != 0 {
				t.Fatalf("stub falsely completed: %+v %v", r, err)
			}
		})
	}
}

func TestStructuredParsersRejectWrongReportShapes(t *testing.T) {
	for _, tool := range []string{"subfinder", "dnsx", "naabu", "httpx", "katana", "ffuf", "nuclei", "gitleaks", "trufflehog", "gosec", "semgrep", "grype", "trivy", "wpscan"} {
		t.Run(tool, func(t *testing.T) {
			for _, bad := range []string{`{}`, `{"error":"permission denied"}`, `null`} {
				if _, err := parseTool(tool, []byte(bad), schema.RunRequest{Target: "https://fixture.test"}); err == nil {
					t.Errorf("accepted %s as a clean result", bad)
				}
			}
		})
	}
	for tool, report := range map[string]string{"gosec": `{"Issues":[]}`, "semgrep": `{"results":[]}`, "grype": `{"matches":[]}`, "trivy": `{"SchemaVersion":2}`, "gitleaks": `[]`, "nuclei": ""} {
		if _, err := parseTool(tool, []byte(report), schema.RunRequest{}); err != nil {
			t.Errorf("valid empty %s: %v", tool, err)
		}
	}
}

func TestWPScanDoesNotInferFindingsFromWords(t *testing.T) {
	clean := `{"target_url":"https://fixture.test/","version":{"number":"6.8","vulnerabilities":[]},"message":"WordPress: no vulnerabilities","vuln_api":{"requests_done_during_scan":2}}`
	r, err := parseWPScan([]byte(clean), schema.RunRequest{})
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("negative message created finding: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
	vulnerable := `{"target_url":"https://fixture.test/","plugins":{"demo":{"vulnerabilities":[{"title":"Fixture known issue","fixed_in":"2.0"}]}},"vuln_api":{"requests_done_during_scan":1}}`
	r, err = parseWPScan([]byte(vulnerable), schema.RunRequest{})
	if err != nil || len(r.Findings) != 1 || r.Findings[0].Severity != schema.SeverityInfo {
		t.Fatalf("explicit issue lost or severity invented: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
	r, err = parseWPScan([]byte(`{"target_url":"https://fixture.test/","vuln_api":{"error":"missing token"}}`), schema.RunRequest{})
	if err != nil || r.Status != "partial" || len(r.Findings) != 0 {
		t.Fatalf("missing API coverage falsely clean: %+v %v", r, err)
	}
}

func TestAllParserErrorReportsFailOrRemainPartial(t *testing.T) {
	for tool := range parsers {
		t.Run(tool, func(t *testing.T) {
			result, err := parseTool(tool, []byte(`{"error":"fixture: dependency unavailable"}`), schema.RunRequest{Target: "https://fixture.test"})
			if err == nil && (result.Status != "partial" || len(result.Findings) > 0 || len(result.Endpoints) > 0 || len(result.Assets) > 0) {
				t.Fatalf("error report became successful data: %+v", result)
			}
		})
	}
}

func TestEveryExternalCapabilityFailsWithoutDependencies(t *testing.T) {
	caps := NewRegistry()
	if err := RegisterBuiltins(caps); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for _, registered := range caps.List() {
		c, ok := registered.(externalCapability)
		if !ok {
			continue
		}
		t.Run(c.ID(), func(t *testing.T) {
			target := ""
			for _, candidate := range []string{directory, "https://fixture.test", "fixture.test", "fixture"} {
				if validateCapabilityTarget(c.ID(), candidate) == nil {
					target = candidate
					break
				}
			}
			if target == "" {
				t.Fatal("no valid fixture target")
			}
			result, err := c.Run(context.Background(), schema.RunRequest{Target: target}, Dependencies{Tools: registry.NewTools(), Runner: &readinessRunner{}, Evidence: evidence.New(t.TempDir())})
			if err == nil || len(result.Evidence) > 0 || len(result.Errors) == 0 {
				t.Fatalf("missing dependencies silently succeeded: %+v %v", result, err)
			}
		})
	}
}
