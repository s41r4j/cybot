package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/pkg/schema"
)

type observingLiveRunner struct {
	execution.Runner
	outputs map[string][]byte
}

func (r *observingLiveRunner) Run(ctx context.Context, spec execution.Spec) (execution.Output, error) {
	out, err := r.Runner.Run(ctx, spec)
	r.outputs[spec.Tool.ID] = append([]byte{}, out.Stdout...)
	return out, err
}

func TestLiveAnalysisPatterns(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_ANALYSIS") != "1" {
		t.Skip("requires pinned GF, bundled URL pattern and Anew")
	}
	d := liveDeps(t)
	observer := &observingLiveRunner{Runner: d.Runner, outputs: map[string][]byte{}}
	d.Runner = observer
	path := filepath.Join(t.TempDir(), "urls.txt")
	content := []byte("https://fixture.invalid/a\nhttps://fixture.invalid/a\nhttps://user:fixture-password@fixture.invalid/b?token=synthetic-marker\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	c := liveCapability(t, "pattern.detect")
	r, err := c.Run(context.Background(), liveRequest(path), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 2 || len(r.Endpoints) != 2 || len(r.Findings) != 0 {
		t.Fatalf("pattern pipeline failed: %+v %v", r, err)
	}
	if strings.Count(string(observer.outputs["gf"]), "https://fixture.invalid/a") != 2 || strings.Count(string(observer.outputs["anew"]), "https://fixture.invalid/a") != 1 {
		t.Fatal("real GF output was not deduplicated by real Anew")
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, content) {
		t.Fatal("read-only pipeline modified source input", err)
	}
	result, err := json.Marshal(r)
	if err != nil || bytes.Contains(result, []byte("fixture-password")) || bytes.Contains(result, []byte("synthetic-marker")) {
		t.Fatal("URL credentials escaped into normalized results", err)
	}
	validateFixtureResult(t, r)
	if err := os.WriteFile(path, []byte("no URL candidates here\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err = c.Run(context.Background(), liveRequest(path), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 2 || len(r.Endpoints) != 0 {
		t.Fatalf("no-match control failed: %+v %v", r, err)
	}
	broken := c
	broken.steps = append([]toolStep{}, c.steps...)
	broken.steps[0].Args = func(target string, _ schema.RunRequest) []string {
		return []string{"cybot-missing-fixture-pattern", target}
	}
	r, err = broken.Run(context.Background(), liveRequest(path), d)
	if err == nil || len(r.Errors) != 1 || r.Errors[0].Code != "TOOL_REPORTED_ERRORS" {
		t.Fatalf("GF's silent failure was treated as clean: %+v %v", r, err)
	}
	requireToolFailure(t, d, "anew", []string{"--cybot-invalid-fixture-option"})
	cases := []operationCase{
		passedCase("positive", "GF extracts URL candidates and Anew consumes/deduplicates its stream without modifying the source file."),
		passedCase("negative", "A local file without matches completes both stages with zero endpoints."),
		passedCase("failure", "Missing GF pattern is rejected despite its zero exit code; Anew rejects an invalid option."),
	}
	certifyOperation(t, "gf", "", cases)
	certifyOperation(t, "anew", "pattern.detect", cases)
}
