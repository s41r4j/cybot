package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanAndRunAcceptTheSameBoundedObjectInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	for _, data := range []string{`null`, `[]`, `{} {}`, strings.Repeat(" ", (1<<20)+1)} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCapabilityInput(path); err == nil {
			t.Fatal("invalid or oversized input accepted")
		}
	}
	data := `{"actions":[{"action":"click","selector":"#fixture"}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	actual, err := readCapabilityInput(path)
	if err != nil || string(actual) != data {
		t.Fatalf("plan/run input changed: %s %v", actual, err)
	}
	if _, err := readCapabilityInput(filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted as JSON input")
	}
	config, format := "", "json"
	if capabilityPlanCmd(&config, &format).Flags().Lookup("input-file") == nil || runCmd(&config, &format).Flags().Lookup("input-file") == nil {
		t.Fatal("plan and execution cannot use the same input file")
	}
}
