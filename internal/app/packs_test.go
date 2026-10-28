package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/internal/config"
	"github.com/s41r4j/cybot/internal/packs"
	"gopkg.in/yaml.v3"
)

func packCLI(t *testing.T, config string, args ...string) ([]byte, error) {
	t.Helper()
	t.Setenv("CYBOT_PACK_AUTO_UPDATE", "0")
	root := NewCommand("test")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"--config", config, "pack"}, args...))
	err := root.Execute()
	return out.Bytes(), err
}

func TestPackCLIInstallRenderRunAndExport(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	b, _ := yaml.Marshal(map[string]any{"data_dir": filepath.Join(dir, "state"), "packs": map[string]string{"update_interval": "12h"}})
	if err := os.WriteFile(cfg, b, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := packCLI(t, cfg, "install", packs.BuiltinRepository, "--bundled")
	if err != nil {
		t.Fatal(err)
	}
	var installed packs.Pack
	if err = json.Unmarshal(out, &installed); err != nil || installed.Active == "" {
		t.Fatalf("install %s %v", out, err)
	}
	out, err = packCLI(t, cfg, "plan", packs.BuiltinID)
	if err != nil {
		t.Fatal(err)
	}
	var plan packs.Plan
	if err = json.Unmarshal(out, &plan); err != nil || len(plan.Phases) != 14 {
		t.Fatalf("plan %s %v", out, err)
	}
	contextFile := filepath.Join(dir, "engagement.yaml")
	if err = os.WriteFile(contextFile, []byte("target: lab.example\nscope: Only lab.example; all sibling hosts excluded\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = packCLI(t, cfg, "render", packs.BuiltinID, "phase-00-recon", "--context", contextFile, "--strict"); err == nil {
		t.Fatal("strict render accepted unresolved upstream helpers")
	}
	output := filepath.Join(dir, "phase.md")
	if _, err = packCLI(t, cfg, "render", packs.BuiltinID, "phase-00-recon", "--context", contextFile, "--output", output); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(output)
	if err != nil || !bytes.Contains(content, []byte("lab.example")) {
		t.Fatal("missing rendered context", err)
	}
	if _, err = packCLI(t, cfg, "render", packs.BuiltinID, "phase-00-recon", "--output", output); err == nil {
		t.Fatal("overwrote existing output")
	}
	current, _ := os.ReadFile(output)
	if !bytes.Equal(current, content) {
		t.Fatal("existing output changed")
	}
	out, err = packCLI(t, cfg, "run", "start", packs.BuiltinID, "--context", contextFile)
	if err != nil {
		t.Fatal(err)
	}
	var run packs.Run
	if err = json.Unmarshal(out, &run); err != nil || run.Revision != installed.Active {
		t.Fatal("unpinned run", err)
	}
	out, err = packCLI(t, cfg, "run", "render", run.ID, "phase-00-recon")
	if err != nil || !bytes.Contains(out, []byte(installed.Active)) {
		t.Fatal("run render", err)
	}
	exported := filepath.Join(dir, "pack.json")
	if _, err = packCLI(t, cfg, "export", packs.BuiltinID, "--output", exported); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot struct {
		Revision packs.Revision `json:"revision"`
	}
	if err = json.Unmarshal(b, &snapshot); err != nil {
		t.Fatal(err)
	}
	if err = snapshot.Revision.Validate(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("MIT License")) {
		t.Fatal("export omitted upstream license")
	}
	// Windows reports compatibility mode bits; access control requires separate ACL validation.
	if info, err := os.Stat(exported); err != nil || (goruntime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatal("export permissions", err)
	}
	if err = withPacks(cfg, func(s *packs.Store, _ config.Config) error {
		_, e := s.Check(context.Background(), packs.BuiltinID, packs.GitHub{Get: func(context.Context, string) ([]byte, error) {
			return json.Marshal(map[string]string{"sha": installed.Active})
		}}, 0)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	out, err = packCLI(t, cfg, "check-updates", "--due")
	if err != nil || !bytes.Contains(out, []byte(`"skipped": true`)) {
		t.Fatalf("due check contacted network: %s %v", out, err)
	}
	out, err = packCLI(t, cfg, "update", "--due")
	if err != nil || !bytes.Contains(out, []byte(`"status": "skipped"`)) {
		t.Fatalf("update due: %s %v", out, err)
	}
	out, err = packCLI(t, cfg, "watch", "--once")
	if err != nil || !bytes.Contains(out, []byte(`"status":"skipped"`)) {
		t.Fatalf("watch once: %s %v", out, err)
	}
	if _, err = packCLI(t, cfg, "watch", "--interval", "0s"); err == nil {
		t.Fatal("watch accepted zero poll interval")
	}
}

func TestPackCLIRejectsInvalidOverridesAndContext(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	b, _ := yaml.Marshal(map[string]string{"data_dir": filepath.Join(dir, "state")})
	if err := os.WriteFile(cfg, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := packCLI(t, cfg, "install", packs.BuiltinRepository, "--bundled"); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "override.json")
	if err := os.WriteFile(f, []byte(`{"capabilities":["invented.raw-command"]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := packCLI(t, cfg, "override", packs.BuiltinID, "phase-00-recon", "--file", f); err == nil || !strings.Contains(err.Error(), "unknown mapped capability") {
		t.Fatal("accepted invalid mapping", err)
	}
	if err := os.WriteFile(f, []byte(`{"content":"local","execute":"arbitrary"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := packCLI(t, cfg, "override", packs.BuiltinID, "phase-00-recon", "--file", f); err == nil {
		t.Fatal("accepted unknown override fields")
	}
	if err := os.WriteFile(f, []byte("target: lab.example\n---\nscope: extra document\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := packCLI(t, cfg, "run", "start", packs.BuiltinID, "--context", f); err == nil {
		t.Fatal("accepted multiple context documents")
	}
}
