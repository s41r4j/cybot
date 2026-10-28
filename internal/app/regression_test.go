package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s41r4j/cybot/internal/memory"
	"github.com/s41r4j/cybot/pkg/schema"
	"github.com/spf13/cobra"
)

func executeFixture(t *testing.T, args ...string) ([]byte, string, error) {
	t.Helper()
	cmd := NewCommand("test")
	var out, errout bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errout)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.Bytes(), errout.String(), err
}
func TestScaffoldPreservesExistingNotes(t *testing.T) {
	base := t.TempDir()
	for attempt := 0; attempt < 2; attempt++ {
		out, _, err := executeFixture(t, "engagement", "scaffold", "example.test", "--base", base)
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 0 {
			if err := os.WriteFile(filepath.Join(base, "example.test", "scope.md"), []byte("MY SCOPE NOTES"), 0600); err != nil {
				t.Fatal(err)
			}
		} else {
			b, err := os.ReadFile(filepath.Join(base, "example.test", "scope.md"))
			if err != nil || string(b) != "MY SCOPE NOTES" {
				t.Fatal("scope notes overwritten")
			}
			var result schema.Engagement
			if err := json.Unmarshal(out, &result); err != nil {
				t.Fatal(err)
			}
			if len(result.Warnings) != 3 {
				t.Fatalf("existing files not reported: %v", result.Warnings)
			}
		}
	}
	if _, _, err := executeFixture(t, "engagement", "scaffold", "../escape", "--base", base); err == nil {
		t.Fatal("path escaped engagement base")
	}
}
func TestScaffoldDoesNotFollowEngagementSymlink(t *testing.T) {
	base, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, "example.test")); err != nil {
		t.Skip(err)
	}
	if _, _, err := executeFixture(t, "engagement", "scaffold", "example.test", "--base", base); err == nil {
		t.Fatal("followed symlink")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("wrote outside engagement base")
	}
}
func TestWarningOnlyCLIAndHistory(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(config, []byte(fmt.Sprintf("data_dir: %q\npolicy:\n  allowed_capabilities: [asset.discover]\n  enforcement_mode: suggestive\n", filepath.Join(dir, "state"))), 0600); err != nil {
		t.Fatal(err)
	}
	out, warnings, err := executeFixture(t, "--config", config, "run", "classify.endpoint", "--target", "https://example.test/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warnings, "policy advisory") {
		t.Fatal("warning invisible in CLI")
	}
	var r schema.Result
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	store, err := memory.Open(filepath.Join(dir, "state", "cybot.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	stored, err := store.Result(context.Background(), r.RunID)
	if err != nil || len(stored.Warnings) == 0 {
		t.Fatal("warning missing from history")
	}
	entries, err := store.EngagementMemory(context.Background(), r.Target)
	if err != nil || len(entries) != 1 {
		t.Fatal("CLI run missing from memory")
	}
}

var errBrokenOutput = errors.New("broken output")

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errBrokenOutput }
func TestRunOutputErrorsReachCaller(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(brokenWriter{})
	cmd.SetErr(brokenWriter{})
	for _, format := range []string{"json", "yaml", "markdown"} {
		err := writeRunResult(cmd, format, schema.Result{RunID: "fixture", Warnings: []string{"fixture"}}, nil)
		if !errors.Is(err, errBrokenOutput) {
			t.Fatalf("%s swallowed writer failure: %v", format, err)
		}
	}
}
func TestExportDoesNotClaimSuccessOnWriteFailure(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	path := "cybot-skills-codex-" + time.Now().Format("20060102") + ".md"
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	out, _, err := executeFixture(t, "export", "skills", "--agent", "codex")
	if err == nil || len(out) != 0 {
		t.Fatalf("claimed success after failed export: %v %s", err, out)
	}
}
func TestInvalidOutputFormatDoesNotCreateRunState(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	state := filepath.Join(dir, "state")
	if err := os.WriteFile(config, []byte(fmt.Sprintf("data_dir: %q\n", state)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeFixture(t, "--config", config, "--format", "invalid", "run", "classify.endpoint", "--target", "example.test"); err == nil {
		t.Fatal("invalid format accepted")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("operation started before output validation")
	}
}

func TestToolboxUsesBundledToolsAndKeepsZAPExternal(t *testing.T) {
	t.Setenv("CYBOT_TOOLBOX_INTERNAL", "1")
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(config, []byte(fmt.Sprintf("data_dir: %q\n", filepath.Join(dir, "state"))), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := newRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	defer r.store.Close()
	for _, id := range []string{"subfinder", "httpx", "trivy"} {
		tool, ok := r.tools.Get(id)
		if !ok || tool.Kind != "native" {
			t.Fatalf("%s no longer uses bundled binary", id)
		}
	}
	tool, ok := r.tools.Get("zap")
	if !ok || tool.Kind != "docker" {
		t.Fatal("ZAP incorrectly converted into bundled binary")
	}
}
