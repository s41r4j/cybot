package capability

import (
	"context"
	"encoding/json"
	"github.com/s41r4j/cybot/pkg/schema"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveAssessmentGitleaks(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_ASSESSMENT") != "1" {
		t.Skip("requires pinned assessment binaries")
	}
	d := liveDeps(t)
	dir := t.TempDir()
	// Deliberately invalid synthetic token: format coverage, never a real credential.
	sentinel := "ghp_" + "r7M4zN8pQ2vK9tL5wH3sF6dJ1xC0bA4eY8uR"
	path := filepath.Join(dir, "fixture.env")
	if err := os.WriteFile(path, []byte("GITHUB_TOKEN="+sentinel+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := liveCapability(t, "secret.scan")
	c.steps = c.steps[:1] // Gitleaks only; TruffleHog remains an optional corroborator.
	r, err := c.Run(context.Background(), liveRequest(dir), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) == 0 || len(r.Evidence) != 1 {
		t.Fatalf("synthetic secret not detected: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
	for _, ev := range r.Evidence {
		b, err := os.ReadFile(ev.Path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), sentinel) {
			t.Fatal("unredacted secret in evidence")
		}
	}
	if err := os.WriteFile(path, []byte("APP_NAME=local-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err = c.Run(context.Background(), liveRequest(dir), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) != 0 {
		t.Fatalf("clean fixture failed: %+v %v", r, err)
	}
}

func TestLiveAssessmentSyft(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_ASSESSMENT") != "1" {
		t.Skip("requires pinned assessment binaries")
	}
	t.Setenv("SYFT_CHECK_FOR_APP_UPDATE", "false")
	d := liveDeps(t)
	dir := t.TempDir()
	lock := `{"name":"cybot-fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"cybot-fixture","version":"1.0.0","dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := liveCapability(t, "sbom.generate").Run(context.Background(), liveRequest(dir), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 1 {
		t.Fatalf("SBOM failed: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
	data, err := os.ReadFile(r.Evidence[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Format     string `json:"bomFormat"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range report.Components {
		found = found || (c.Name == "lodash" && c.Version == "4.17.20")
	}
	if report.Format != "CycloneDX" || !found {
		t.Fatalf("fixture dependency missing from SBOM: %s", data)
	}
}

func TestLiveAssessmentNaabu(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_ASSESSMENT") != "1" {
		t.Skip("requires pinned assessment binaries")
	}
	d := liveDeps(t)
	server := fixtureHTTP(t)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := liveCapability(t, "service.enumerate")
	c.steps[0].Args = func(target string, r schema.RunRequest) []string {
		args := naabuArgs(target, r)
		for i := 0; i < len(args); i++ {
			if args[i] == "-top-ports" {
				args[i] = "-p"
				args[i+1] = u.Port()
			}
		}
		return args
	}
	r, err := c.Run(context.Background(), liveRequest(u.Hostname()), d)
	if err != nil || len(r.Errors) > 0 || len(r.Services) != 1 || r.Services[0].Host != u.Hostname() {
		t.Fatalf("local TCP service not discovered: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
}
