package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/internal/config"
	"github.com/s41r4j/cybot/internal/packs"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestStartupAutomaticallyUpdatesWithoutPollutingOutput(t *testing.T) {
	t.Setenv("CYBOT_PACK_AUTO_UPDATE", "")
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cybot.yaml")
	b, _ := yaml.Marshal(map[string]string{"data_dir": dir})
	if err := os.WriteFile(cfgPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	files := []packs.File{{Path: "LICENSE", Content: "MIT"}, {Path: "phases/phase-00-recon.md", Content: "# Old\n{{target}} {{scope}}"}}
	old, err := packs.NewRevision(packs.BuiltinRepository, strings.Repeat("a", 40), files)
	if err != nil {
		t.Fatal(err)
	}
	files = append([]packs.File{}, files...)
	files[1].Content = "# New\n{{target}} {{scope}}"
	newRevision, err := packs.NewRevision(packs.BuiltinRepository, strings.Repeat("b", 40), files)
	if err != nil {
		t.Fatal(err)
	}
	if err = withPacks(cfgPath, func(s *packs.Store, _ config.Config) error {
		_, e := s.Stage(context.Background(), old, "main")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	client := packs.GitHub{Get: func(_ context.Context, u string) ([]byte, error) {
		if strings.Contains(u, "/commits/") {
			return json.Marshal(map[string]string{"sha": newRevision.Commit})
		}
		if strings.Contains(u, "/git/trees/") {
			tree := []map[string]any{}
			for _, f := range newRevision.Files {
				tree = append(tree, map[string]any{"path": f.Path, "type": "blob", "mode": "100644", "size": len(f.Content), "sha": packs.GitBlobHash([]byte(f.Content))})
			}
			return json.Marshal(map[string]any{"tree": tree})
		}
		for _, f := range newRevision.Files {
			if strings.HasSuffix(u, "/"+newRevision.Commit+"/"+f.Path) {
				return []byte(f.Content), nil
			}
		}
		return nil, errors.New("unexpected request")
	}}
	cmd := &cobra.Command{Use: "capability"}
	var output, diagnostics bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&diagnostics)
	cmd.SetContext(context.Background())
	if err = autoUpdatePacksWith(cmd, cfgPath, client); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 0 || !strings.Contains(diagnostics.String(), "Updated prompt pack") {
		t.Fatalf("startup output: %s / %s", output.String(), diagnostics.String())
	}
	if err = withPacks(cfgPath, func(s *packs.Store, _ config.Config) error {
		p, e := s.Get(context.Background(), packs.BuiltinID)
		if e == nil && (p.Active != newRevision.Commit || p.Previous != old.Commit) {
			t.Fatal("startup didn't retain fallback", p)
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	// A due check must use the timestamp written by the successful update.
	noNetwork := packs.GitHub{Get: func(context.Context, string) ([]byte, error) {
		t.Fatal("fresh startup check fetched again")
		return nil, nil
	}}
	if err = autoUpdatePacksWith(cmd, cfgPath, noNetwork); err != nil {
		t.Fatal(err)
	}
}

func TestStartupFailureIsNonfatalAndOfflineSwitchWorks(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "cybot.yaml")
	b, _ := yaml.Marshal(map[string]string{"data_dir": dir})
	if err := os.WriteFile(cfg, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := withPacks(cfg, func(s *packs.Store, _ config.Config) error {
		r, e := packs.Bundled()
		if e != nil {
			return e
		}
		_, e = s.Stage(context.Background(), r, "main")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{Use: "capability"}
	var diagnostics bytes.Buffer
	cmd.SetErr(&diagnostics)
	cmd.SetContext(context.Background())
	t.Setenv("CYBOT_PACK_AUTO_UPDATE", "")
	if err := autoUpdatePacksWith(cmd, cfg, packs.GitHub{Get: func(context.Context, string) ([]byte, error) { return nil, errors.New("network unavailable") }}); err != nil {
		t.Fatal("maintenance prevented capability execution", err)
	}
	if !strings.Contains(diagnostics.String(), "using installed data") {
		t.Fatal("missing offline diagnostic")
	}
	t.Setenv("CYBOT_PACK_AUTO_UPDATE", "0")
	if err := autoUpdatePacksWith(cmd, cfg, packs.GitHub{Get: func(context.Context, string) ([]byte, error) { t.Fatal("offline switch fetched"); return nil, nil }}); err != nil {
		t.Fatal(err)
	}
}
