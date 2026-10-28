package capability

import (
	"encoding/json"
	"testing"
)

func TestBuiltinDefinitionsAreCompleteAndDeterministic(t *testing.T) {
	r := NewRegistry()
	if err := RegisterBuiltins(r); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.List() {
		d := c.Definition()
		if d.ID == "" || d.Title == "" || d.Documentation.Purpose == "" {
			t.Fatalf("incomplete definition: %#v", d)
		}
		if len(d.Workflow) == 0 || len(d.Documentation.Examples) == 0 {
			t.Fatalf("%s lacks workflow or examples", d.ID)
		}
		if !json.Valid(d.InputSchema) || !json.Valid(d.OutputSchema) {
			t.Fatalf("%s contains invalid schema JSON", d.ID)
		}
	}
	got := r.List()
	for i := 1; i < len(got); i++ {
		if got[i-1].ID() > got[i].ID() {
			t.Fatalf("registry order is not deterministic")
		}
	}
}

func TestHostnameValidationIsStrict(t *testing.T) {
	for _, v := range []string{"example.com", "api-1.example.com"} {
		if err := validateHostname(v); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
	for _, v := range []string{"", "https://example.com", "example.com/path", "example.com:443", "bad..example", "-bad.example", "example.com."} {
		if err := validateHostname(v); err == nil {
			t.Errorf("accepted invalid hostname %q", v)
		}
	}
}
