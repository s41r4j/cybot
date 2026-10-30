package capability

import (
	"context"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/pkg/schema"
)

func TestBrowserCapabilitiesPlanAndExecute(t *testing.T) {
	r := NewRegistry()
	if err := RegisterBuiltins(r); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"web.browse", "web.automate", "web.har"} {
		c, ok := r.Get(id)
		if !ok {
			t.Fatalf("missing capability %s", id)
		}
		if c.Definition().Stability != "experimental" {
			t.Errorf("%s stability=%s", id, c.Definition().Stability)
		}
	}
}

func TestBrowserCapabilityRunsBatchFixture(t *testing.T) {
	tools := registry.NewTools()
	if err := tools.Register(schema.Tool{ID: "agent-browser", Version: "0.34.0", Kind: "native", Binary: "agent-browser", Parser: "agent-browser.batch.v1"}); err != nil {
		t.Fatal(err)
	}
	fixture := []byte(`[
  {"command":["open","https://example.com"],"success":true,"result":{"url":"https://example.com/"}},
  {"command":["snapshot","-i","-c"],"success":true,"result":{"snapshot":"- link Home [url=https://example.com/home, ref=@e1]\n- button Submit [ref=@e2]\n- link About [url=https://example.com/about, ref=@e3]","origin":"https://example.com/"}},
  {"command":["network","requests","--json"],"success":true,"result":{"requests":[{"url":"https://example.com/api/data","method":"GET","status":200,"resourceType":"xhr"},{"url":"https://example.com/app.js","method":"GET","status":200,"resourceType":"script"}]}}
]`)
	runner := &fixtureRunner{outputs: map[string][]byte{"agent-browser": fixture}}
	c := browserCapability{definition: browserDefinition("web.browse", "Web Browse (Rendered DOM)", "web-security", "d", "p"), mode: "browse"}
	result, err := c.Run(context.Background(), schema.RunRequest{RunID: "browser-run", Target: "https://example.com"}, Dependencies{
		Tools: tools, Runner: runner, Evidence: evidence.New(t.TempDir()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Endpoints) != 5 {
		t.Fatalf("expected 5 endpoints (origin + snapshot links + requests), got %d: %#v", len(result.Endpoints), result.Endpoints)
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("expected 1 evidence artifact, got %d", len(result.Evidence))
	}
	found := map[string]bool{}
	for _, e := range result.Endpoints {
		found[e.URL] = true
	}
	for _, want := range []string{"https://example.com/home", "https://example.com/about", "https://example.com/api/data", "https://example.com/"} {
		if !found[want] {
			t.Errorf("missing endpoint %s", want)
		}
	}
}

func TestBrowserHarExtractsRequests(t *testing.T) {
	tools := registry.NewTools()
	if err := tools.Register(schema.Tool{ID: "agent-browser", Version: "0.34.0", Kind: "native", Binary: "agent-browser"}); err != nil {
		t.Fatal(err)
	}
	fixture := []byte(`[
  {"command":["open","https://example.com"],"success":true,"result":{"url":"https://example.com/"}},
  {"command":["network","requests","--json"],"success":true,"result":{"requests":[{"url":"https://example.com/api/data","method":"POST","status":201,"resourceType":"fetch"}]}}
]`)
	runner := &fixtureRunner{outputs: map[string][]byte{"agent-browser": fixture}}
	c := browserCapability{definition: browserDefinition("web.har", "Web HAR Capture", "web-security", "d", "p"), mode: "har"}
	result, err := c.Run(context.Background(), schema.RunRequest{RunID: "har-run", Target: "https://example.com"}, Dependencies{
		Tools: tools, Runner: runner, Evidence: evidence.New(t.TempDir()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Endpoints) != 2 {
		t.Fatalf("unexpected har endpoints: %#v", result.Endpoints)
	}
	if result.Endpoints[0].Method != "POST" && result.Endpoints[1].Method != "POST" {
		t.Fatalf("expected a POST endpoint: %#v", result.Endpoints)
	}
	if result.Endpoints[0].Status != 201 && result.Endpoints[1].Status != 201 {
		t.Fatalf("expected a 201 endpoint: %#v", result.Endpoints)
	}
}

func TestBrowserTargetValidation(t *testing.T) {
	for _, bad := range []string{"", "example.com", "ftp://example.com", "https://user:pass@example.com/"} {
		if err := validateBrowserTarget(bad); err == nil {
			t.Errorf("expected validation error for %q", bad)
		}
	}
	for _, good := range []string{"https://example.com", "http://example.com/path"} {
		if err := validateBrowserTarget(good); err != nil {
			t.Errorf("unexpected error for %q: %v", good, err)
		}
	}
}

func TestBrowserArgsUseSingleBatchInvocation(t *testing.T) {
	for _, tc := range []struct{ mode, target string }{
		{"browse", "https://example.com"},
		{"automate", "https://example.com"},
		{"har", "https://example.com"},
	} {
		var args []string
		switch tc.mode {
		case "automate":
			args = browserAutomateArgs(tc.target, schema.RunRequest{})
		case "har":
			args = browserHarArgs(tc.target, schema.RunRequest{})
		default:
			args = browserBrowseArgs(tc.target, schema.RunRequest{})
		}
		if len(args) < 4 || args[0] != "--json" || args[1] != "batch" {
			t.Fatalf("unexpected args for %s: %v", tc.mode, args)
		}
		if !strings.Contains(strings.Join(args, " "), "open "+tc.target) {
			t.Fatalf("batch does not open the target: %v", args)
		}
	}
}

var _ execution.Spec
