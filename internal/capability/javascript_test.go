package capability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestJavaScriptExtractorsPreserveRelativeCandidatesWithoutInventingOrigins(t *testing.T) {
	for tool, data := range map[string]string{
		"jsluice": `{"url":"https://user:synthetic-password@fixture.invalid/api?token=synthetic-marker","method":"POST","type":"fetch"}
{"url":"/relative/api?token=synthetic-marker","method":"EXPR","type":"fetch"}`,
		"linkfinder": "https://user:synthetic-password@fixture.invalid/api?ok=1&amp;token=synthetic-marker\n/relative/api?token=synthetic-marker\n",
	} {
		r, err := parseTool(tool, []byte(data), schema.RunRequest{Target: "/source/app.js"})
		if err != nil || len(r.Endpoints) != 1 || len(r.Observations) != 1 || len(r.Findings) != 0 {
			t.Fatalf("candidate normalization failed (%s): %+v %v", tool, r, err)
		}
		if !strings.HasPrefix(r.Endpoints[0].URL, "https://fixture.invalid/api?") || !strings.Contains(r.Observations[0], "origin unresolved") {
			t.Fatal("relative source acquired an invented origin", r)
		}
		data, _ := json.Marshal(r)
		if strings.Contains(string(data), "synthetic-password") || strings.Contains(string(data), "synthetic-marker") || strings.Contains(r.Endpoints[0].URL, "&amp;") {
			t.Fatal("candidate credentials or HTML escaping survived normalization", string(data))
		}
		validateFixtureResult(t, r)
	}
}

func TestJavaScriptExtractionRejectsDiagnosticsAndUnexpectedModes(t *testing.T) {
	for tool, fixtures := range map[string][]string{
		"jsluice":    {`{"secret":"unselected-mode"}`, `{"url":"https://fixture.invalid"}`, `{"url":"https://fixture.invalid/white space","type":"fetch"}`},
		"linkfinder": {"Usage: python linkfinder.py [Options]\nError: invalid input\n", "Error:broken.js\n", "unrecognized-output\n"},
	} {
		for _, data := range fixtures {
			if _, err := parseTool(tool, []byte(data), schema.RunRequest{}); err == nil {
				t.Fatalf("unexpected %s output reported clean: %s", tool, data)
			}
		}
		if r, err := parseTool(tool, nil, schema.RunRequest{}); err != nil || len(r.Endpoints) != 0 || len(r.Findings) != 0 || r.Status == "partial" {
			t.Fatalf("valid no-match output rejected: %+v %v", r, err)
		}
	}
	dir := t.TempDir()
	if err := validateCapabilityTarget("js.extract", dir); err == nil {
		t.Fatal("directory was accepted as a single-file extraction")
	}
	path := filepath.Join(dir, "oversized.js")
	if err := os.WriteFile(path, make([]byte, (1<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateCapabilityTarget("js.extract", path); err == nil {
		t.Fatal("oversized parser input was accepted")
	}
}
