package capability

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/pkg/schema"
)

type operationCase struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Mode   string `json:"mode"`
	Detail string `json:"detail"`
}

// Called only after actual executions and assertions for all three cases pass.
// The host collector binds this report to its measured image and version probe.
func certifyOperation(t *testing.T, tool, capability string, cases []operationCase) {
	t.Helper()
	output, source := os.Getenv("CYBOT_VALIDATION_REPORTS"), os.Getenv("CYBOT_VALIDATION_SOURCE")
	if output == "" {
		return
	}
	if len(source) != 64 || t.Failed() {
		t.Fatal("cannot certify a failed operation or missing source fingerprint")
	}
	binary, err := exec.LookPath(tool)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ kind, id string }{{"tool", tool}, {"capability", capability}} {
		if item.id == "" {
			continue
		}
		report := map[string]any{"kind": item.kind, "id": item.id, "source_sha256": source,
			"binary_sha256": hex.EncodeToString(digest[:]), "platform": runtime.GOOS + "/" + runtime.GOARCH,
			"tool": tool, "cases": cases}
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		name := item.kind + "-" + strings.ReplaceAll(item.id, ".", "-") + ".json"
		if err := os.WriteFile(filepath.Join(output, name), encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func passedCase(kind, detail string) operationCase {
	return operationCase{Type: kind, Status: "passed", Mode: "real-operation", Detail: detail}
}

func requireToolFailure(t *testing.T, d Dependencies, toolID string, args []string) {
	t.Helper()
	tool, ok := d.Tools.Get(toolID)
	if !ok {
		t.Fatal("unregistered fixture tool", toolID)
	}
	_, err := d.Runner.Run(context.Background(), execution.Spec{Tool: tool, Args: args, Timeout: 15 * time.Second})
	if err == nil {
		t.Fatal("real tool did not reject invalid fixture input", toolID)
	}
}

func TestLiveAnalysisCertification(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_ANALYSIS") != "1" {
		t.Skip("requires network-isolated analysis image")
	}
	for _, scanner := range []string{"semgrep", "gosec"} {
		t.Run(scanner, func(t *testing.T) {
			d := liveDeps(t)
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixture.invalid/local\n\ngo 1.26.0\n"), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "main.go")
			write := func(code string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(code), 0600); err != nil {
					t.Fatal(err)
				}
			}
			write("package fixture\nimport \"crypto/tls\"\nvar Config = &tls.Config{InsecureSkipVerify: true}\n")
			args := semgrepArgs
			if scanner == "gosec" {
				args = gosecArgs
			}
			c := external("code.audit", "Fixture", "code-security", []string{scanner}, nil, toolStep{ID: scanner, Required: true, Args: args}).(externalCapability)
			r, err := c.Run(context.Background(), liveRequest(dir), d)
			if err != nil || len(r.Errors) != 0 || len(r.Findings) == 0 || len(r.Evidence) != 1 {
				t.Fatalf("insecure TLS fixture not detected: %+v %v", r, err)
			}
			validateFixtureResult(t, r)
			write("package fixture\nconst Name = \"clean local fixture\"\n")
			r, err = c.Run(context.Background(), liveRequest(dir), d)
			if err != nil || len(r.Errors) != 0 || len(r.Findings) != 0 || r.Status == "partial" {
				t.Fatalf("clean source was not scanned successfully: %+v %v", r, err)
			}
			// Execute the real scanner with an invalid rule/package and ensure
			// execution/normalization never turns the failure into a clean result.
			broken := c
			broken.steps = append([]toolStep{}, c.steps...)
			broken.steps[0].Args = func(target string, req schema.RunRequest) []string {
				if scanner == "semgrep" {
					return replaceArgument(args(target, req), "--config", filepath.Join(dir, "missing-rules.yaml"))
				}
				return args(filepath.Join(dir, "missing-package"), req)
			}
			r, err = broken.Run(context.Background(), liveRequest(dir), d)
			if err == nil && r.Status != "partial" && len(r.Errors) == 0 {
				t.Fatalf("scanner failure reported clean: %+v", r)
			}
			certifyOperation(t, scanner, "", []operationCase{
				passedCase("positive", "Insecure TLS Go fixture produces a normalized finding and evidence."),
				passedCase("negative", "Clean Go fixture is scanned with zero findings and no scanner errors."),
				passedCase("failure", "Real scanner rejects a missing rule/package; adapter preserves failure."),
			})
		})
	}
}

func TestGosecPackageScope(t *testing.T) {
	dir := t.TempDir()
	args := gosecArgs(dir, schema.RunRequest{})
	if args[len(args)-1] != filepath.Join(dir, "...") {
		t.Fatal("Gosec escaped its explicit package target", args)
	}
}

func TestLiveAnalysisCapabilities(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_ANALYSIS") != "1" {
		t.Skip("requires network-isolated analysis image")
	}
	for _, id := range []string{"js.analyse", "code.audit"} {
		t.Run(id, func(t *testing.T) {
			d := liveDeps(t)
			dir := t.TempDir()
			name, positive, negative := "app.js", "function run(input) { return eval(input); }\n", "function run(input) { return JSON.parse(input); }\n"
			if id == "code.audit" {
				name, positive, negative = "main.go", "package fixture\nimport \"crypto/tls\"\nvar Config = &tls.Config{InsecureSkipVerify: true}\n", "package fixture\nconst Name = \"clean fixture\"\n"
				if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixture.invalid/local\n\ngo 1.26.0\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(positive), 0600); err != nil {
				t.Fatal(err)
			}
			c := liveCapability(t, id)
			r, err := c.Run(context.Background(), liveRequest(dir), d)
			expected := 1
			if id == "code.audit" {
				expected = 2
			}
			if err != nil || len(r.Errors) != 0 || len(r.Findings) == 0 || len(r.Evidence) != expected {
				t.Fatalf("complete capability missed fixture: %+v %v", r, err)
			}
			if err := os.WriteFile(path, []byte(negative), 0600); err != nil {
				t.Fatal(err)
			}
			r, err = c.Run(context.Background(), liveRequest(dir), d)
			if err != nil || len(r.Errors) != 0 || len(r.Findings) != 0 || len(r.Evidence) != expected || r.Status == "partial" {
				t.Fatalf("complete capability rejected clean fixture: %+v %v", r, err)
			}
			broken := c
			broken.steps = append([]toolStep{}, c.steps...)
			broken.steps[0].Args = func(target string, req schema.RunRequest) []string {
				return replaceArgument(semgrepArgs(target, req), "--config", filepath.Join(dir, "missing-rules.yaml"))
			}
			r, err = broken.Run(context.Background(), liveRequest(dir), d)
			if err == nil && r.Status != "partial" && len(r.Errors) == 0 {
				t.Fatal("failed required scanner produced a clean capability result")
			}
			certifyOperation(t, "semgrep", id, []operationCase{
				passedCase("positive", "All capability adapters execute and detect the local vulnerable source fixture."),
				passedCase("negative", "All capability adapters scan clean source without findings or errors."),
				passedCase("failure", "A required scanner's missing rules fail the capability explicitly."),
			})
		})
	}
}

func TestLiveAnalysisSecrets(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_ANALYSIS") != "1" {
		t.Skip("requires isolated full secret-scanning profile")
	}
	d := liveDeps(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.env")
	// Invalid synthetic token, deliberately assembled to avoid representing a
	// static source-code credential. Network verification is disabled.
	sentinel := "ghp_" + "r7M4zN8pQ2vK9tL5wH3sF6dJ1xC0bA4eY8uR"
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("GITHUB_TOKEN=" + sentinel + "\n")
	c := liveCapability(t, "secret.scan")
	r, err := c.Run(context.Background(), liveRequest(dir), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 2 {
		t.Fatalf("full secret scan failed: %+v %v", r, err)
	}
	for _, tool := range []string{"gitleaks", "trufflehog"} {
		found := false
		for _, f := range r.Findings {
			found = found || strings.HasPrefix(f.ID, tool+":")
		}
		if !found {
			t.Fatal("scanner missed the synthetic token", tool)
		}
	}
	for _, ev := range r.Evidence {
		data, err := os.ReadFile(ev.Path)
		if err != nil || strings.Contains(string(data), sentinel) {
			t.Fatal("secret evidence was not redacted", err)
		}
	}
	write("APP_NAME=clean-local-fixture\n")
	r, err = c.Run(context.Background(), liveRequest(dir), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) != 0 || len(r.Evidence) != 2 {
		t.Fatalf("clean full secret scan failed: %+v %v", r, err)
	}
	requireToolFailure(t, d, "trufflehog", []string{"--cybot-invalid-fixture-option"})
	requireToolFailure(t, d, "gitleaks", gitleaksArgs(filepath.Join(dir, "missing-input"), schema.RunRequest{}))
	cases := []operationCase{
		passedCase("positive", "Gitleaks and TruffleHog both detect an invalid synthetic token; retained evidence is redacted."),
		passedCase("negative", "Both scanners inspect clean source with no findings or errors."),
		passedCase("failure", "Both real executables reject invalid configuration or missing input."),
	}
	certifyOperation(t, "gitleaks", "", cases)
	certifyOperation(t, "trufflehog", "secret.scan", cases)
}
