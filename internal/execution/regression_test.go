package execution

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestDockerCommandUsesImageSpecificEntrypoint(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "args")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$CYBOT_TEST_CAPTURE"
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CYBOT_TEST_CAPTURE", capture)
	for _, tc := range []struct {
		image, entrypoint string
		want              []string
		notWant           string
	}{
		{"cybotainer:fixture", "", []string{"cybotainer:fixture\nexec\nscanner"}, "--entrypoint"},
		{"registry/other:fixture", "", []string{"--entrypoint\nscanner\nregistry/other:fixture"}, "\nexec\n"},
		{"registry/zap:fixture", "sh", []string{"--entrypoint\nsh\nregistry/zap:fixture"}, "\nexec\n"},
	} {
		_, err := (LocalRunner{}).Run(context.Background(), Spec{Tool: schema.Tool{ID: "fixture", Kind: "docker", Binary: "scanner", DockerImage: tc.image}, Entrypoint: tc.entrypoint, Args: []string{"fixture"}, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(capture)
		if err != nil {
			t.Fatal(err)
		}
		args := string(b)
		for _, limit := range []string{"--memory\n2g", "--memory-swap\n2g", "--cpus\n1", "--pull\nnever", "--name\ncybot-toolbox-active", "--pids-limit\n256"} {
			if !strings.Contains(args, limit) {
				t.Fatalf("missing resource protection %s: %s", limit, args)
			}
		}
		for _, want := range tc.want {
			if !strings.Contains(args, want) {
				t.Fatalf("command mismatch: %s", args)
			}
		}
		if strings.Contains(args, tc.notWant) {
			t.Fatalf("wrong entrypoint contract: %s", args)
		}
	}
}
func TestExpectedFindingExitCodePreservesOutput(t *testing.T) {
	out, err := (LocalRunner{}).Run(context.Background(), Spec{Tool: schema.Tool{ID: "fixture", Kind: "native", Binary: "sh"}, Args: []string{"-c", `printf '{"site":[]}'; exit 2`}, AcceptExitCodes: []int{1, 2}, Timeout: time.Second})
	if err != nil || out.ExitCode != 2 || string(out.Stdout) != `{"site":[]}` {
		t.Fatalf("finding exit treated as process failure: %#v %v", out, err)
	}
}
