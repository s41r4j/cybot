package orchestrator

import (
	"encoding/json"
	"testing"

	"github.com/s41r4j/cybot/catalog"
	"github.com/s41r4j/cybot/internal/capability"
	"github.com/s41r4j/cybot/internal/policy"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/pkg/schema"
	jsonschemas "github.com/s41r4j/cybot/schemas"
)

func TestEveryCapabilityProducesSchemaValidPlan(t *testing.T) {
	tools := registry.NewTools()
	curated, err := catalog.Tools()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range curated {
		if err := tools.Register(tool); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range capability.BuiltinTools() {
		_ = tools.Upsert(tool)
	}
	caps := capability.NewRegistry()
	if err := capability.RegisterBuiltins(caps); err != nil {
		t.Fatal(err)
	}
	o := Orchestrator{Capabilities: caps, Policy: policy.New(policy.Config{AllowedCapabilities: []string{"*"}}), Dependencies: capability.Dependencies{Tools: tools}}
	for _, c := range caps.List() {
		plan, err := o.Plan(schema.RunRequest{Capability: c.ID(), Target: "example.com", Input: json.RawMessage(`{}`), Approved: true})
		if err != nil {
			t.Fatalf("%s: %v", c.ID(), err)
		}
		if err := jsonschemas.Validate("execution-plan", plan); err != nil {
			t.Errorf("%s: %v", c.ID(), err)
		}
		if plan.ToolAvailability != "not-checked" {
			t.Errorf("%s claims untested tool availability", c.ID())
		}
		if plan.DeterministicKey == "" || plan.ExpectedSchema != "cybot://schemas/result" {
			t.Errorf("%s plan is incomplete", c.ID())
		}
	}
}

func newPlanTools(t *testing.T) *registry.ToolRegistry {
	t.Helper()
	r := registry.NewTools()
	items, err := catalog.Tools()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range items {
		if err := r.Register(tool); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func TestBrowserActionApprovalSurvivesAdvisoryPlanning(t *testing.T) {
	caps := capability.NewRegistry()
	if err := capability.RegisterBuiltins(caps); err != nil {
		t.Fatal(err)
	}
	o := Orchestrator{Capabilities: caps, Policy: policy.New(policy.Config{AllowedCapabilities: []string{"different"}, EnforcementMode: "suggestive"}), Dependencies: capability.Dependencies{Tools: newPlanTools(t)}}
	req := schema.RunRequest{Capability: "web.automate", Target: "https://fixture.invalid", Input: json.RawMessage(`{"actions":[{"action":"click","selector":"#fixture"}]}`)}
	p, err := o.Plan(req)
	if err != nil || p.Executable || !p.RequiresApproval {
		t.Fatalf("advisory mode bypassed browser action approval: %+v %v", p, err)
	}
	req.Approved = true
	p, err = o.Plan(req)
	if err != nil || !p.Executable {
		t.Fatalf("approved valid interaction cannot be planned: %+v %v", p, err)
	}
	req.Input = json.RawMessage(`{"actions":[{"action":"eval","selector":"arbitrary-code"}]}`)
	p, err = o.Plan(req)
	if err != nil || p.Executable {
		t.Fatalf("unsupported browser code became executable: %+v %v", p, err)
	}
}
