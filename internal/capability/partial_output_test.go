package capability

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/pkg/schema"
)

const partialNucleiMatch = `{"template-id":"local-marker","info":{"name":"Local marker","severity":"info"},"matched-at":"http://fixture.invalid/"}`

type failedOutputRunner struct {
	fixtureRunner
	failed string
}

func (r *failedOutputRunner) Run(ctx context.Context, spec execution.Spec) (execution.Output, error) {
	out, err := r.fixtureRunner.Run(ctx, spec)
	if spec.Tool.ID == r.failed {
		out.ExitCode = 1
		return out, errors.New("scanner timed out after emitting output")
	}
	return out, err
}

func TestFailedOutputRetainsOnlyValidatedRecords(t *testing.T) {
	for _, test := range []struct {
		name, output string
		findings     int
	}{
		{"complete-match", partialNucleiMatch, 1},
		{"truncated-tail", partialNucleiMatch + "\n" + `{"template-id":"unfinished`, 1},
		{"bad-middle-stops-recovery", partialNucleiMatch + "\nnot-json\n" + strings.ReplaceAll(partialNucleiMatch, "local-marker", "later-marker"), 1},
		{"truncated-array", "[" + partialNucleiMatch + ",", 0},
		{"wrong-contract", `{"version":"help"}`, 0},
		{"empty", "", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			tools := registry.NewTools()
			if err := tools.Register(schema.Tool{ID: "nuclei", Kind: "native", Binary: "nuclei", Version: "fixture"}); err != nil {
				t.Fatal(err)
			}
			runner := &failedOutputRunner{fixtureRunner: fixtureRunner{outputs: map[string][]byte{"nuclei": []byte(test.output)}}, failed: "nuclei"}
			result, err := liveCapability(t, "web.scan").Run(context.Background(), liveRequest("http://fixture.invalid"), Dependencies{Tools: tools, Runner: runner, Evidence: evidence.New(t.TempDir())})
			if err == nil || result.Status != "partial" || len(result.Errors) != 1 || len(result.Findings) != test.findings || !strings.Contains(result.Summary, "incomplete") {
				t.Fatalf("lost failure or invented output: %+v %v", result, err)
			}
			if len(result.Evidence) != test.findings {
				t.Fatalf("unexpected evidence: %+v", result.Evidence)
			}
			if test.findings == 0 {
				if result.Confidence != 0 {
					t.Fatal("failed empty scan has confidence", result.Confidence)
				}
				return
			}
			ev := result.Evidence[0]
			if ev.Metadata["execution_status"] != "failed" || ev.Metadata["coverage"] != "incomplete" || len(ev.Metadata["captured_sha256"]) != 64 || result.Findings[0].EvidenceIDs[0] != ev.ID {
				t.Fatal("incomplete evidence is not bound to finding", ev)
			}
			stored, err := os.ReadFile(ev.Path)
			if err != nil || strings.Contains(string(stored), "unfinished") || strings.Contains(string(stored), "not-json") {
				t.Fatalf("invalid tail was stored: %s %v", stored, err)
			}
		})
	}
}

func TestFailedOptionalStageCannotFeedPipeline(t *testing.T) {
	tools := registry.NewTools()
	for _, id := range []string{"gf", "anew"} {
		if err := tools.Register(schema.Tool{ID: id, Kind: "native", Binary: id, Version: "fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	runner := &failedOutputRunner{fixtureRunner: fixtureRunner{outputs: map[string][]byte{"gf": []byte("https://fixture.invalid/a\n"), "anew": nil}}, failed: "gf"}
	c := external("web.scan", "Fixture", "web-security", []string{"gf", "anew"}, nil, toolStep{ID: "gf"}, toolStep{ID: "anew", StdinFromPrevious: true}).(externalCapability)
	result, err := c.Run(context.Background(), liveRequest("http://fixture.invalid"), Dependencies{Tools: tools, Runner: runner, Evidence: evidence.New(t.TempDir())})
	if err == nil || len(runner.specs) != 1 || result.Status != "partial" || len(result.Errors) != 1 {
		t.Fatalf("failed stream reached next stage: %+v %v", result, err)
	}
}

func TestIndependentStageCanFinishAfterOptionalFailure(t *testing.T) {
	tools := registry.NewTools()
	for _, id := range []string{"nuclei", "httpx"} {
		if err := tools.Register(schema.Tool{ID: id, Kind: "native", Binary: id, Version: "fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	runner := &failedOutputRunner{fixtureRunner: fixtureRunner{outputs: map[string][]byte{"nuclei": []byte(partialNucleiMatch), "httpx": []byte(`{"url":"http://fixture.invalid/","status_code":200}`)}}, failed: "nuclei"}
	c := external("web.scan", "Fixture", "web-security", []string{"nuclei", "httpx"}, nil, toolStep{ID: "nuclei"}, toolStep{ID: "httpx", Required: true}).(externalCapability)
	r, err := c.Run(context.Background(), liveRequest("http://fixture.invalid"), Dependencies{Tools: tools, Runner: runner, Evidence: evidence.New(t.TempDir())})
	if err != nil || r.Status != "partial" || len(r.Findings) != 1 || len(r.Endpoints) != 1 || len(r.Evidence) != 2 || len(r.Errors) != 1 || !strings.Contains(r.Summary, "1 completed tool steps") {
		t.Fatalf("independent results or partial state lost: %+v %v", r, err)
	}
}

func TestRecoveredSecretOutputIsRedacted(t *testing.T) {
	secret := "synthetic-sensitive-value"
	output := []byte(`{"DetectorName":"Fixture","Raw":"` + secret + `","RawV2":"` + secret + `"}` + "\n" + `{"Raw":"incomplete-secret`)
	r, retained, ok := recoverFailedOutput("trufflehog", output, liveRequest(t.TempDir()))
	if !ok || len(r.Findings) != 1 {
		t.Fatal("valid secret match lost", r)
	}
	combined := emptyResult()
	if err := retainToolOutput(&combined, r, retained, output, "trufflehog", schema.Tool{Version: "fixture"}, liveRequest(t.TempDir()), Dependencies{Evidence: evidence.New(t.TempDir())}, "execution"); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(combined.Evidence[0].Path)
	if err != nil || strings.Contains(string(stored), secret) || strings.Contains(string(stored), "incomplete-secret") {
		t.Fatalf("unredacted partial evidence: %s %v", stored, err)
	}
}

func TestZeroExitMalformedTailRetainsEarlierFindingAsIncomplete(t *testing.T) {
	tools := registry.NewTools()
	if err := tools.Register(schema.Tool{ID: "nuclei", Kind: "native", Binary: "nuclei", Version: "fixture"}); err != nil {
		t.Fatal(err)
	}
	runner := &fixtureRunner{outputs: map[string][]byte{"nuclei": []byte(partialNucleiMatch + "\n" + `{"template-id":"truncated`)}}
	r, err := liveCapability(t, "web.scan").Run(context.Background(), liveRequest("http://fixture.invalid"), Dependencies{Tools: tools, Runner: runner, Evidence: evidence.New(t.TempDir())})
	if err == nil || r.Status != "partial" || len(r.Errors) != 1 || r.Errors[0].Code != "OUTPUT_CONTRACT_FAILED" || len(r.Findings) != 1 || len(r.Evidence) != 1 || r.Evidence[0].Metadata["execution_status"] != "completed" || r.Evidence[0].Metadata["failure_stage"] != "normalization" {
		t.Fatalf("normalization failure lost match or became clean: %+v %v", r, err)
	}
}
