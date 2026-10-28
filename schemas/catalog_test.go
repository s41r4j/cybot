package schemas

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/s41r4j/cybot/pkg/schema"
	"github.com/google/uuid"
)

func TestAllEmbeddedSchemasAreValidJSON(t *testing.T) {
	names := Names()
	if len(names) < 9 {
		t.Fatalf("schema catalog too small: %v", names)
	}
	for _, name := range names {
		b, err := Get(name)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(b) {
			t.Errorf("%s is invalid JSON", name)
		}
	}
}

func TestCanonicalSchemasValidateRuntimeValues(t *testing.T) {
	request := schema.RunRequest{Capability: "web.content.discover", Target: "https://example.com", Input: json.RawMessage(`{}`), Approved: true}
	if err := Validate("run-request", request); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	result := schema.Result{RunID: uuid.NewString(), Capability: "web.content.discover", Target: "https://example.com", Status: "completed", Summary: "empty fixture", Confidence: 1, Assets: []schema.Asset{}, Services: []schema.Service{}, Endpoints: []schema.Endpoint{}, Findings: []schema.Finding{}, Evidence: []schema.Evidence{}, Errors: []schema.RunError{}, Decisions: []schema.Decision{}, Assumptions: []string{}, VerificationRecommended: []string{}, NextCapabilities: []string{}, RelatedWorkflows: []string{}, PossibleFalsePositives: []string{}, StartedAt: now, FinishedAt: now}
	if err := Validate("result", result); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeValidationRejectsUnknownFields(t *testing.T) {
	value := map[string]any{"capability": "asset.discover", "input": map[string]any{}, "approved": true, "unexpected": true}
	if err := Validate("run-request", value); err == nil {
		t.Fatal("accepted unknown request field")
	}
}
