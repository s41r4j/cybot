package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExampleAndDefaultsLoad(t *testing.T) {
	c, err := Load("../../configs/cybot.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Policy.Timeout != 30*time.Minute || c.Policy.EnforcementMode != "suggestive" {
		t.Fatalf("unexpected example config: %#v", c)
	}
	if c.Packs.UpdateInterval != 24*time.Hour {
		t.Fatalf("unexpected pack update interval: %s", c.Packs.UpdateInterval)
	}
	if !c.Packs.AutoUpdate || c.Packs.UpdateTimeout != 45*time.Second {
		t.Fatal("pack auto-update defaults not enabled", c.Packs)
	}
	c, err = Load("")
	if err != nil || c.Policy.EnforcementMode != "suggestive" {
		t.Fatal("defaults changed")
	}
}
func TestExplicitBadConfigNeverFallsBack(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing config silently accepted")
	}
	for _, input := range []string{"policy:\n  enforcement_mode: typo\n", "policy:\n  timeout: 0s\n", "policy:\n  concurreny: 4\n", "data_dir: ''\n", "packs:\n  update_interval: 0s\n", "packs:\n  update_interval: invalid\n", "packs:\n  update_timeout: -1s\n"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted invalid config: %q", input)
		}
	}
}
