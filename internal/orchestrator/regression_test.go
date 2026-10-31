package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/internal/capability"
	"github.com/s41r4j/cybot/internal/memory"
	"github.com/s41r4j/cybot/internal/policy"
	"github.com/s41r4j/cybot/pkg/schema"
	jsonschemas "github.com/s41r4j/cybot/schemas"
)

type stubCapability struct {
	calls   int
	failure error
}

func (c *stubCapability) ID() string { return "fixture.run" }
func (c *stubCapability) Definition() schema.CapabilityDefinition {
	return schema.CapabilityDefinition{ID: c.ID()}
}
func (c *stubCapability) Run(context.Context, schema.RunRequest, capability.Dependencies) (schema.Result, error) {
	c.calls++
	return schema.Result{Summary: "fixture", Endpoints: []schema.Endpoint{{URL: "https://example.test/?token=FAKE_SENTINEL"}}}, c.failure
}

type failingAudit struct{}

func (failingAudit) Write(context.Context, schema.AuditEvent) error {
	return errors.New("fixture audit failure")
}
func testCore(t *testing.T, mode string) (*Orchestrator, *stubCapability) {
	t.Helper()
	store, err := memory.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	caps := capability.NewRegistry()
	stub := &stubCapability{}
	if err := caps.Register(stub); err != nil {
		t.Fatal(err)
	}
	return &Orchestrator{Capabilities: caps, Memory: store, Policy: policy.New(policy.Config{AllowedCapabilities: []string{"different"}, EnforcementMode: mode})}, stub
}
func TestWarningOnlyRunPersistsAdvisoryAndMemory(t *testing.T) {
	o, stub := testCore(t, "suggestive")
	o.Audit = failingAudit{}
	r, err := o.Run(context.Background(), schema.RunRequest{Capability: "fixture.run", Target: "example.test", Input: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if stub.calls != 1 || r.Status != "completed" {
		t.Fatalf("advisory blocked run: %#v", r)
	}
	if len(r.Warnings) < 2 || !strings.Contains(strings.Join(r.Warnings, " "), "policy advisory") || !strings.Contains(strings.Join(r.Warnings, " "), "Audit write failed") {
		t.Fatalf("missing diagnostics: %v", r.Warnings)
	}
	if strings.Contains(r.Endpoints[0].URL, "FAKE_SENTINEL") {
		t.Fatal("result leaked URL token")
	}
	if err := jsonschemas.Validate("result", r); err != nil {
		t.Fatal(err)
	}
	saved, err := o.Memory.Result(context.Background(), r.RunID)
	if err != nil || len(saved.Warnings) == 0 {
		t.Fatalf("warning not saved: %v", err)
	}
	recalled, err := o.Memory.EngagementMemory(context.Background(), "example.test")
	if err != nil || len(recalled) != 1 || recalled[0].Capability != "fixture.run" {
		t.Fatalf("memory not updated: %#v %v", recalled, err)
	}
}
func TestExplicitStrictModeDeniesBeforeExecution(t *testing.T) {
	o, stub := testCore(t, "strict")
	r, err := o.Run(context.Background(), schema.RunRequest{Capability: "fixture.run", Target: "example.test", Input: json.RawMessage(`{}`)})
	if err == nil || stub.calls != 0 || r.RunID != "" {
		t.Fatal("strict denial did not stop execution")
	}
}
func TestPersistenceFailureDoesNotHideCapabilityFailure(t *testing.T) {
	o, stub := testCore(t, "suggestive")
	original := errors.New("fixture execution failed")
	stub.failure = original
	if err := o.Memory.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := o.Run(context.Background(), schema.RunRequest{Capability: "fixture.run", Target: "example.test", Input: json.RawMessage(`{}`)})
	if !errors.Is(err, original) || !strings.Contains(err.Error(), "save result") {
		t.Fatalf("failure lost: %v", err)
	}
	found := false
	for _, e := range r.Errors {
		if e.Code == "PERSISTENCE_FAILED" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing persistence diagnostic")
	}
}

func TestFailureDoesNotPromoteUnknownConfidence(t *testing.T) {
	o, stub := testCore(t, "suggestive")
	stub.failure = errors.New("scanner failed")
	r, err := o.Run(context.Background(), schema.RunRequest{Capability: "fixture.run", Target: "example.test", Input: json.RawMessage(`{}`)})
	if err == nil || r.Status != "failed" || r.Confidence != 0 {
		t.Fatalf("failure became confident result: %+v %v", r, err)
	}
	saved, err := o.Memory.Result(context.Background(), r.RunID)
	if err != nil || saved.Confidence != 0 || saved.Status != "failed" {
		t.Fatalf("failure confidence was not persisted: %+v %v", saved, err)
	}
}
func TestPlanRejectsInvalidTargetWithoutClaimingHealth(t *testing.T) {
	o, _ := testCore(t, "suggestive")
	if err := capability.RegisterBuiltins(o.Capabilities); err != nil {
		t.Fatal(err)
	}
	// A metadata registry is enough to plan; no executable should run.
	o.Dependencies.Tools = newPlanTools(t)
	for _, tc := range []struct {
		id, target string
		executable bool
	}{
		{"web.scan", "not-a-url", false}, {"web.scan", "https://example.test", true},
		{"code.audit", filepath.Join(t.TempDir(), "missing"), false}, {"code.audit", t.TempDir(), true},
	} {
		p, err := o.Plan(schema.RunRequest{Capability: tc.id, Target: tc.target, Input: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		if p.Executable != tc.executable || p.ToolAvailability != "not-checked" {
			t.Fatalf("incorrect readiness for %s %s", tc.id, tc.target)
		}
	}
}
