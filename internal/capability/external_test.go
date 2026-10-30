package capability

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/pkg/schema"
)

type fixtureRunner struct {
	outputs map[string][]byte
	specs   []execution.Spec
}

func TestVulnerabilityAdaptersAreOfflineAndUseBundledDatabases(t *testing.T) {
	req := schema.RunRequest{Capability: "dependency.scan", Target: t.TempDir()}
	trivy := strings.Join(trivyFilesystemArgs("/input", req), " ")
	for _, required := range []string{"--cache-dir /home/cybot/.cache/trivy", "--skip-db-update", "--offline-scan", "--disable-telemetry"} {
		if !strings.Contains(trivy, required) {
			t.Fatalf("trivy arguments missing %q: %s", required, trivy)
		}
	}
	grype := strings.Join(grypeArgs("/input", req), " ")
	if !strings.HasPrefix(grype, "dir:/input ") || !strings.Contains(grype, "-o json") {
		t.Fatalf("unexpected grype arguments: %s", grype)
	}
}

func TestContainerArchiveUsesTrivyInput(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(archive, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	req := schema.RunRequest{Capability: "container.scan", Target: archive}
	args := strings.Join(trivyImageArgs("/input", req), " ")
	if !strings.Contains(args, "--input /input") {
		t.Fatalf("local container archive was not passed as input: %s", args)
	}
	if err := validateCapabilityTarget("container.scan", archive); err != nil {
		t.Fatal(err)
	}
	if err := validateCapabilityTarget("container.scan", t.TempDir()); err == nil {
		t.Fatal("container directory should be rejected; an archive file is required")
	}
}

func TestContainerOCILayoutUsesImageSources(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"oci-layout": `{"imageLayoutVersion":"1.0.0"}`, "index.json": `{"schemaVersion":2,"manifests":[]}`} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateCapabilityTarget("container.scan", dir); err != nil {
		t.Fatal(err)
	}
	req := schema.RunRequest{Capability: "container.scan", Target: dir}
	if args := strings.Join(trivyImageArgs("/input", req), " "); !strings.Contains(args, "--input /input") {
		t.Fatal("OCI layout was treated as a registry image", args)
	}
	if args := grypeArgs("/input", req); args[0] != "oci-dir:/input" {
		t.Fatal("OCI layout was treated as an ordinary directory", args)
	}
}

func (f *fixtureRunner) Health(context.Context, schema.Tool) error { return nil }
func (f *fixtureRunner) Run(_ context.Context, s execution.Spec) (execution.Output, error) {
	f.specs = append(f.specs, s)
	if s.Tool.ID == "agent-browser" && len(s.Args) > 0 && s.Args[len(s.Args)-1] == "close" {
		return execution.Output{Stdout: []byte(`{"success":true,"data":{"closed":true}}`)}, nil
	}
	out, ok := f.outputs[s.Tool.ID]
	if !ok {
		return execution.Output{}, errors.New("missing fixture")
	}
	return execution.Output{Stdout: out, ExitCode: 0, Attempts: 1}, nil
}

func TestAllCapabilitiesDeclareTheirActualImplementation(t *testing.T) {
	r := NewRegistry()
	if err := RegisterBuiltins(r); err != nil {
		t.Fatal(err)
	}
	if got := len(r.List()); got != 71 {
		t.Fatalf("capability count=%d", got)
	}
	for _, c := range r.List() {
		if external, ok := c.(externalCapability); ok {
			d := external.Definition()
			if d.Validation != "not-certified" || d.Implementation == "" {
				t.Errorf("%s lacks support metadata", c.ID())
			}
			if d.Implementation != "adapter" && d.Stability == "stable" {
				t.Errorf("%s advertises an unfinished implementation as stable", c.ID())
			}
		}
		switch c.(type) {
		case AssetDiscover, externalCapability, reportCapability, ValidateFinding, ClassifyEndpoint, browserCapability, CVELookup, MitreMap, ZAPBaseline:
		default:
			t.Errorf("%s has an unexpected implementation type %T", c.ID(), c)
		}
	}
}

func TestExternalCapabilityRunsFixtureThroughReadOnlyMount(t *testing.T) {
	target := t.TempDir()
	tools := registry.NewTools()
	if err := tools.Register(schema.Tool{ID: "semgrep", Version: "1.172.0", Kind: "docker", Binary: "semgrep", DockerImage: "cybotainer:2026.08.9-arm64", Parser: "semgrep.v1"}); err != nil {
		t.Fatal(err)
	}
	runner := &fixtureRunner{outputs: map[string][]byte{"semgrep": []byte(`{"results":[{"check_id":"cybot.eval","path":"app.js","start":{"line":1},"extra":{"message":"eval","severity":"ERROR"}}]}`)}}
	c := external("js.analyse", "JavaScript Analysis", "web-security", []string{"semgrep"}, []string{"secret.scan"}, toolStep{ID: "semgrep", Required: true, Args: semgrepArgs})
	result, err := c.Run(context.Background(), schema.RunRequest{RunID: "run-fixture", Target: target}, Dependencies{Tools: tools, Runner: runner, Evidence: evidence.New(filepath.Join(t.TempDir(), "evidence")), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || len(result.Evidence) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(runner.specs) != 1 || len(runner.specs[0].Mounts) != 1 || !runner.specs[0].Mounts[0].ReadOnly {
		t.Fatalf("missing read-only mount: %#v", runner.specs)
	}
	if result.Findings[0].EvidenceIDs[0] != result.Evidence[0].ID {
		t.Fatal("finding is not linked to evidence")
	}
}

func TestCodeAuditFileDoesNotExpandGosecScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "single.go")
	if err := os.WriteFile(path, []byte("package fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tools := registry.NewTools()
	for _, id := range []string{"semgrep", "gosec"} {
		if err := tools.Register(schema.Tool{ID: id, Kind: "native", Binary: id, Version: "fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fixtureRunner{outputs: map[string][]byte{"semgrep": []byte(`{"results":[],"paths":{"scanned":["single.go"]},"errors":[]}`)}}
	c := liveCapability(t, "code.audit")
	r, err := c.Run(context.Background(), liveRequest(path), Dependencies{Tools: tools, Runner: runner, Evidence: evidence.New(t.TempDir())})
	if err != nil || r.Status != "partial" || len(r.Errors) != 1 || r.Errors[0].Code != "DIRECTORY_REQUIRED" {
		t.Fatalf("file scope limitation was not explicit: %+v %v", r, err)
	}
	if len(runner.specs) != 1 || runner.specs[0].Tool.ID != "semgrep" || runner.specs[0].Args[len(runner.specs[0].Args)-1] != path {
		t.Fatal("file request escaped to its parent package", runner.specs)
	}
}

func TestPatternPipelinePassesActualStageOutputWithoutWritingInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(path, []byte("https://fixture.invalid/a\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tools := registry.NewTools()
	for _, id := range []string{"gf", "anew"} {
		if err := tools.Register(schema.Tool{ID: id, Kind: "native", Binary: id, Version: "fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	runner := &fixtureRunner{outputs: map[string][]byte{"gf": []byte("https://fixture.invalid/a\nhttps://fixture.invalid/a\n"), "anew": []byte("https://fixture.invalid/a\n")}}
	r, err := liveCapability(t, "pattern.detect").Run(context.Background(), liveRequest(path), Dependencies{Tools: tools, Runner: runner, Evidence: evidence.New(t.TempDir())})
	if err != nil || len(runner.specs) != 2 || len(r.Endpoints) != 1 || len(r.Findings) != 0 {
		t.Fatalf("pattern pipeline contract failed: %+v %v", r, err)
	}
	if !bytes.Equal(runner.specs[1].Stdin, runner.outputs["gf"]) || len(runner.specs[0].Stdin) != 0 || strings.Join(runner.specs[1].Args, " ") != "-d" {
		t.Fatal("pipeline did not preserve the read-only streaming contract", runner.specs)
	}
}

func TestReportCapabilityLoadsNormalizedHistory(t *testing.T) {
	def := capabilityDefinition("report.generate", "Report Generation", "reporting", nil, nil)
	c := reportCapability{definition: def}
	store := evidence.New(filepath.Join(t.TempDir(), "evidence"))
	result, err := c.Run(context.Background(), schema.RunRequest{RunID: "report-run", Target: "source-run"}, Dependencies{Evidence: store, LoadResult: func(context.Context, string) (schema.Result, error) {
		return schema.Result{RunID: "source-run", Capability: "asset.discover", Status: "completed", Summary: "ok"}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Evidence) != 1 || result.Confidence != 1 {
		t.Fatalf("unexpected report result: %#v", result)
	}
	if _, err := os.Stat(result.Evidence[0].Path); err != nil {
		t.Fatal(err)
	}
}
