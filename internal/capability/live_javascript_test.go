package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestLiveAnalysisJavaScriptExtraction(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_ANALYSIS") != "1" {
		t.Skip("requires the pinned JSLuice and LinkFinder engines")
	}
	d := liveDeps(t)
	path := filepath.Join(t.TempDir(), "app.js")
	content := []byte(`fetch("https://fixture.invalid/api");
fetch("https://fixture.invalid/api");
fetch("/relative/path?token=synthetic-marker");
fetch("https://user:synthetic-password@fixture.invalid/private?token=synthetic-marker");`)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	c := liveCapability(t, "js.extract")
	r, err := c.Run(context.Background(), liveRequest(path), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 2 || len(r.Endpoints) != 2 || len(r.Findings) != 0 || len(r.Observations) == 0 {
		t.Fatalf("real JavaScript extraction failed: %+v %v", r, err)
	}
	for _, endpoint := range r.Endpoints {
		if strings.Contains(endpoint.URL, "/relative/") {
			t.Fatal("relative path acquired an invented web origin")
		}
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, content) {
		t.Fatal("read-only extraction modified its source", err)
	}
	encoded, _ := json.Marshal(r)
	if bytes.Contains(encoded, []byte("synthetic-password")) || bytes.Contains(encoded, []byte("synthetic-marker")) {
		t.Fatal("URL credentials escaped into normalized JavaScript candidates")
	}
	for _, artifact := range r.Evidence {
		data, err := os.ReadFile(artifact.Path)
		if err != nil || bytes.Contains(data, []byte("synthetic-password")) || bytes.Contains(data, []byte("synthetic-marker")) {
			t.Fatal("URL credentials escaped into JavaScript evidence", err)
		}
	}
	validateFixtureResult(t, r)
	if err := os.WriteFile(path, []byte("const fixtureNumber = 42;\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err = c.Run(context.Background(), liveRequest(path), d)
	if err != nil || len(r.Errors) != 0 || len(r.Endpoints) != 0 || len(r.Findings) != 0 || len(r.Observations) != 0 || len(r.Evidence) != 2 {
		t.Fatalf("valid no-match JavaScript was mishandled: %+v %v", r, err)
	}
	broken := c
	broken.steps = append([]toolStep{}, c.steps...)
	broken.steps[1].Args = func(string, schema.RunRequest) []string {
		return linkfinderArgs(filepath.Join(t.TempDir(), "missing.js"), schema.RunRequest{})
	}
	r, err = broken.Run(context.Background(), liveRequest(path), d)
	if err == nil || len(r.Errors) == 0 || r.Errors[0].Code != "OUTPUT_CONTRACT_FAILED" {
		t.Fatalf("LinkFinder's zero-exit input failure was accepted: %+v %v", r, err)
	}
	if err := os.WriteFile(path, []byte("function invalid( {\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err = c.Run(context.Background(), liveRequest(path), d)
	if err == nil || len(r.Errors) == 0 || r.Errors[0].Code != "TOOL_REPORTED_ERRORS" {
		t.Fatalf("JavaScript parser errors became a clean extraction: %+v %v", r, err)
	}
	cases := []operationCase{
		passedCase("positive", "Both real engines extract absolute URL candidates and unresolved relative paths from one read-only file; output and evidence redact credentials."),
		passedCase("negative", "Valid JavaScript without URLs completes both stages with zero invented endpoints or findings."),
		passedCase("failure", "Invalid JavaScript and LinkFinder's zero-exit missing-file diagnostic fail explicitly."),
	}
	certifyOperation(t, "jsluice", "", cases)
	certifyOperation(t, "linkfinder", "js.extract", cases)
}
