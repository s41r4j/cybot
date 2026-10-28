package capability

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/catalog"
	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/pkg/schema"
)

func TestReportDiagnosticsPreserveFindingsAndFailures(t *testing.T) {
	for tool, data := range map[string]string{
		"semgrep": `{"results":[{"check_id":"test","path":"a.js","extra":{"severity":"WARNING"}}],"errors":[{"message":"partial parse"}],"paths":{"scanned":[]}}`,
		"gosec":   `{"Issues":[],"Golang errors":{"a.go":[{"error":"parse failed"}]},"Stats":{"files":0}}`,
		"grype":   `{"matches":[],"errors":["database incomplete"]}`,
		"trivy":   `{"SchemaVersion":2,"Results":[],"errors":["fixture"]}`,
	} {
		t.Run(tool, func(t *testing.T) {
			r, err := parseTool(tool, []byte(data), schema.RunRequest{})
			if err != nil || r.Status != "partial" || len(r.Errors) == 0 {
				t.Fatalf("diagnostics lost: %+v %v", r, err)
			}
			if tool == "semgrep" && len(r.Findings) != 1 {
				t.Fatal("partial coverage discarded genuine findings")
			}
		})
	}
	r, err := parseTool("semgrep", []byte(`{"results":[],"errors":[],"paths":{"scanned":["a.js"]}}`), schema.RunRequest{})
	if err != nil || r.Status == "partial" || len(r.Errors) != 0 {
		t.Fatalf("clean covered report rejected: %+v %v", r, err)
	}
}

func TestClassificationNeverInventsSecurityFindings(t *testing.T) {
	for _, target := range []string{"https://fixture.invalid/?id=1", "https://fixture.invalid/api/login", "https://fixture.invalid/?user_id=1&query=hello"} {
		r, err := (ClassifyEndpoint{}).Run(context.Background(), schema.RunRequest{Target: target}, Dependencies{})
		if err != nil || len(r.Findings) != 0 || len(r.Observations) == 0 || len(r.NextCapabilities) == 0 || r.Confidence != 0 {
			t.Fatalf("routing became a security assessment: %+v %v", r, err)
		}
	}
}

func TestRemoteApprovalCannotRunInterfaceOrLocalOperations(t *testing.T) {
	for tool, builder := range map[string]func(string, schema.RunRequest) []string{"bettercap": bettercapArgs, "mimikatz": mimikatzArgs, "linpeas": linpeasArgs, "winpeas": winpeasArgs, "seatbelt": seatbeltArgs, "sharpup": sharpupArgs} {
		t.Run(tool, func(t *testing.T) {
			tools := registry.NewTools()
			_ = tools.Register(schema.Tool{ID: tool, Kind: "native", Binary: "fixture"})
			runner := &fixtureRunner{outputs: map[string][]byte{tool: []byte("fixture")}}
			c := external("fixture", "Fixture", "test", []string{tool}, nil, toolStep{ID: tool, Required: true, Args: builder})
			r, err := c.Run(context.Background(), schema.RunRequest{Target: "fixture.invalid", Approved: true}, Dependencies{Tools: tools, Runner: runner})
			if err == nil || len(runner.specs) != 0 || len(r.Errors) != 1 || r.Errors[0].Code != "RESOURCE_SCOPE_REQUIRED" {
				t.Fatalf("remote approval escaped scope: %+v %v", r, err)
			}
		})
	}
	if err := validateStepScope("bettercap", schema.RunRequest{Target: "interface://eth0"}); err == nil {
		t.Fatal("interface scan did not require approval")
	}
	if err := validateStepScope("bettercap", schema.RunRequest{Target: "interface://eth0", Approved: true}); err != nil {
		t.Fatal(err)
	}
	args := strings.Join(bettercapArgs("interface://en0", schema.RunRequest{}), " ")
	if !strings.Contains(args, "-iface en0 ") {
		t.Fatal(args)
	}
	host, _ := os.Hostname()
	if err := validateStepScope("linpeas", schema.RunRequest{Target: "local://" + host, Approved: true}); err != nil {
		t.Fatal(err)
	}
	if err := validateStepScope("linpeas", schema.RunRequest{Target: "local://different.invalid", Approved: true}); err == nil {
		t.Fatal("accepted a different machine")
	}
}

func TestFindingReviewRequiresEvidenceAndExplicitAssertions(t *testing.T) {
	c := ValidateFinding{}
	r, err := c.Run(context.Background(), schema.RunRequest{Target: "GET http://fixture.invalid/request in scope leaked PII data confirmed", Input: json.RawMessage(`{}`)}, Dependencies{})
	if err != nil || !strings.HasPrefix(r.Summary, "UNVERIFIED") || r.Status != "partial" || r.Confidence != 0 {
		t.Fatalf("prose passed review: %+v %v", r, err)
	}
	store := evidence.New(t.TempDir())
	ev, err := store.Put("source", "fixture", "text/plain", []byte("synthetic demonstration"))
	if err != nil {
		t.Fatal(err)
	}
	deps := Dependencies{Evidence: store, LoadResult: func(context.Context, string) (schema.Result, error) {
		return schema.Result{Status: "completed", Findings: []schema.Finding{{ID: "finding", EvidenceIDs: []string{ev.ID}}}, Evidence: []schema.Evidence{ev}}, nil
	}}
	input := validationInput{SourceRunID: "source", FindingID: "finding", Checks: map[string]string{}}
	for _, q := range validationQuestions {
		input.Checks[q.id] = "pass"
	}
	inputJSON, _ := json.Marshal(input)
	req := schema.RunRequest{Target: "review", Input: inputJSON}
	r, err = c.Run(context.Background(), req, deps)
	if err != nil || r.Status != "completed" || !strings.HasPrefix(r.Summary, "CHECKLIST_PASS") {
		t.Fatalf("valid review failed: %+v %v", r, err)
	}
	input.Checks["in_scope"] = "fail"
	req.Input, _ = json.Marshal(input)
	r, err = c.Run(context.Background(), req, deps)
	if err != nil || !strings.HasPrefix(r.Summary, "KILL") {
		t.Fatalf("scope failure must kill regardless of other passes: %+v %v", r, err)
	}
	if err := os.WriteFile(ev.Path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Run(context.Background(), req, deps); err == nil {
		t.Fatal("tampered evidence passed")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	ev.Path = outside
	if err := store.Verify(ev); err == nil {
		t.Fatal("verified evidence outside the store")
	}
}

func TestFullCatalogCoverageRetainsEveryEntryAndNoFalseCertification(t *testing.T) {
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
	report := CatalogCoverage(caps, tools)
	if len(report.Tools) != 84 || len(report.Capabilities) != 71 || report.ReleaseReady {
		t.Fatalf("incomplete or falsely certified inventory: %d/%d", len(report.Tools), len(report.Capabilities))
	}
	for _, row := range report.Tools {
		if row.Validation != "not-certified" || len(row.Blockers) == 0 {
			t.Fatalf("unvalidated tool marked ready: %+v", row)
		}
	}
}
