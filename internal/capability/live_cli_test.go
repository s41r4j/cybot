package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s41r4j/cybot/pkg/schema"
)

type fixtureCLI struct{ config string }

func newFixtureCLI(t *testing.T) fixtureCLI {
	t.Helper()
	_ = liveDeps(t)
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	state, _ := json.Marshal(filepath.Join(dir, "state"))
	if err := os.WriteFile(config, []byte("data_dir: "+string(state)+"\npacks:\n  auto_update: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return fixtureCLI{config}
}

func (cli fixtureCLI) run(t *testing.T, id, target string, extra ...string) (schema.Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := append([]string{"--config", cli.config, "run", id, "--target", target, "--approve"}, extra...)
	command := exec.CommandContext(ctx, "cybot", args...)
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	output, err := command.Output()
	var result schema.Result
	if len(output) != 0 {
		if decodeErr := json.Unmarshal(output, &result); decodeErr != nil {
			t.Fatalf("installed CLI emitted invalid result: %s %v", output, decodeErr)
		}
	}
	if err == nil && (result.RunID == "" || len(result.Errors) != 0) {
		t.Fatalf("CLI silently returned an incomplete result: %+v %s", result, diagnostic.String())
	}
	return result, err
}

func TestLiveCoreIntelligenceCLI(t *testing.T) {
	for _, fixture := range []struct{ id, positive, negative, finding string }{
		{"cve.lookup", "CVE-2021-44228", "CVE-9999-99999999", "cve:cve-2021-44228"},
		{"mitre.map", "T1190", "T99999999", "mitre:t1190"},
	} {
		t.Run(fixture.id, func(t *testing.T) {
			cli := newFixtureCLI(t)
			positive, err := cli.run(t, fixture.id, fixture.positive)
			if err != nil || len(positive.Findings) != 1 || positive.Findings[0].ID != fixture.finding {
				t.Fatalf("curated lookup failed: %+v %v", positive, err)
			}
			negative, err := cli.run(t, fixture.id, fixture.negative)
			if err != nil || len(negative.Findings) != 0 || negative.Status != "completed" {
				t.Fatalf("unknown record produced a match: %+v %v", negative, err)
			}
			failed, err := cli.run(t, fixture.id, " ")
			if err == nil || failed.Status != "failed" {
				t.Fatalf("empty lookup was accepted: %+v %v", failed, err)
			}
			certifyCapability(t, "cybot", fixture.id, []operationCase{
				passedCase("positive", "Installed CLI returns the exact curated record requested by ID."),
				passedCase("negative", "An unknown record returns zero matches without inventing evidence."),
				passedCase("failure", "Blank lookup fails explicitly through the installed CLI and persisted result path."),
			})
		})
	}
}

func TestLiveCoreClassificationAndReportingCLI(t *testing.T) {
	cli := newFixtureCLI(t)
	positive, err := cli.run(t, "classify.endpoint", "https://fixture.invalid/?id=1")
	if err != nil || len(positive.Observations) == 0 || len(positive.Findings) != 0 || positive.Confidence != 0 {
		t.Fatalf("classification invented verification: %+v %v", positive, err)
	}
	negative, err := cli.run(t, "classify.endpoint", "https://fixture.invalid/")
	if err != nil || len(negative.Observations) != 0 || len(negative.Findings) != 0 || len(negative.NextCapabilities) != 0 {
		t.Fatalf("unmatched URL invented a candidate: %+v %v", negative, err)
	}
	if failed, err := cli.run(t, "classify.endpoint", " "); err == nil || failed.Status != "failed" {
		t.Fatalf("empty classification was accepted: %+v %v", failed, err)
	}
	certifyCapability(t, "cybot", "classify.endpoint", []operationCase{
		passedCase("positive", "URL triggers an investigation candidate with zero vulnerability findings and zero verification confidence."),
		passedCase("negative", "An unmatched URL returns no invented candidates, findings or next capabilities."),
		passedCase("failure", "Blank classification target fails through the installed CLI."),
	})
	report, err := cli.run(t, "report.generate", positive.RunID)
	if err != nil || len(report.Evidence) != 1 {
		t.Fatalf("stored result report failed: %+v %v", report, err)
	}
	data, err := os.ReadFile(report.Evidence[0].Path)
	sum := sha256.Sum256(data)
	var document schema.Report
	if err != nil || hex.EncodeToString(sum[:]) != report.Evidence[0].SHA256 || json.Unmarshal(data, &document) != nil || document.Result.RunID != positive.RunID {
		t.Fatal("report does not identify its persisted source and stored bytes", err)
	}
	if _, err := cli.run(t, "report.generate", "missing-fixture-run"); err == nil {
		t.Fatal("missing history was reported as a successful report")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(state, []byte("preserve this file"), 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "invalid.yaml")
	quoted, _ := json.Marshal(state)
	if err := os.WriteFile(config, []byte("data_dir: "+string(quoted)+"\npacks:\n  auto_update: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (fixtureCLI{config}).run(t, "report.generate", positive.RunID); err == nil {
		t.Fatal("unusable report storage was silently accepted")
	}
	certifyCapability(t, "cybot", "report.generate", []operationCase{
		passedCase("positive", "Installed CLI reports a persisted run; source ID and SHA-256 match the stored report bytes."),
		passedCase("negative", "A missing source run produces no fabricated report."),
		passedCase("failure", "Unusable storage fails explicitly through the installed CLI."),
	})
}

func TestLiveAnalysisFindingReviewCLI(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_ANALYSIS") != "1" {
		t.Skip("requires both installed secret scanners and CLI")
	}
	cli := newFixtureCLI(t)
	dir := t.TempDir()
	token := "ghp_" + "r7M4zN8pQ2vK9tL5wH3sF6dJ1xC0bA4eY8uR"
	if err := os.WriteFile(filepath.Join(dir, "fixture.env"), []byte("GITHUB_TOKEN="+token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := cli.run(t, "secret.scan", dir)
	if err != nil || source.Status != "completed" || len(source.Findings) == 0 || len(source.Findings[0].EvidenceIDs) == 0 {
		t.Fatalf("real stored source finding unavailable: %+v %v", source, err)
	}
	input := validationInput{SourceRunID: source.RunID, FindingID: source.Findings[0].ID, Checks: map[string]string{}}
	for _, question := range validationQuestions {
		input.Checks[question.id] = "pass"
	}
	path := filepath.Join(t.TempDir(), "review.json")
	review := func() (schema.Result, error) {
		data, _ := json.Marshal(input)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return cli.run(t, "validate.finding", "fixture-review", "--input-file", path)
	}
	result, err := review()
	if err != nil || result.Status != "completed" || !strings.HasPrefix(result.Summary, "CHECKLIST_PASS") || result.Confidence != 0 {
		t.Fatalf("evidence-backed operator checklist failed: %+v %v", result, err)
	}
	input.Checks["in_scope"] = "fail"
	result, err = review()
	if err != nil || result.Status != "partial" || !strings.HasPrefix(result.Summary, "KILL") {
		t.Fatalf("negative scope assertion was accepted: %+v %v", result, err)
	}
	input.Checks["in_scope"] = "pass"
	for _, artifact := range source.Evidence {
		if artifact.ID == source.Findings[0].EvidenceIDs[0] {
			if err := os.WriteFile(artifact.Path, []byte("tampered fixture bytes"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if result, err = review(); err == nil || result.Status != "failed" {
		t.Fatalf("tampered evidence was accepted: %+v %v", result, err)
	}
	certifyCapability(t, "cybot", "validate.finding", []operationCase{
		passedCase("positive", "Installed CLI reviews a real stored scanner finding with hash-verified evidence; assertions remain explicitly unverified independently."),
		passedCase("negative", "A failed scope assertion returns KILL and cannot complete the checklist."),
		passedCase("failure", "Tampering with actual stored scanner evidence prevents checklist acceptance."),
	})
}
