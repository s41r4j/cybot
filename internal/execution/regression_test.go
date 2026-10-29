package execution

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestMain(m *testing.M) {
	if os.Getenv("CYBOT_TEST_PROCESS") == "finding" {
		_, _ = os.Stdout.WriteString(`{"site":[]}`)
		os.Exit(2)
	}
	if os.Getenv("CYBOT_TEST_PROCESS") == "deadline" {
		time.Sleep(10 * time.Second)
		os.Exit(1)
	}
	if os.Getenv("CYBOT_TEST_PROCESS") == "docker" {
		if err := os.WriteFile(os.Getenv("CYBOT_TEST_CAPTURE"), []byte(strings.Join(os.Args[1:], "\n")+"\n"), 0600); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestDockerCommandUsesImageSpecificEntrypoint(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "args")
	// Copy the native test helper instead of relying on a Unix shebang. On
	// Windows a file named docker without .exe accidentally invoked real Docker.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	name := "docker"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, name), program, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("CYBOT_TEST_CAPTURE", capture)
	t.Setenv("CYBOT_TEST_PROCESS", "docker")
	t.Setenv("GORACE", os.Getenv("GORACE")+" atexit_sleep_ms=0")
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
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out, err := (LocalRunner{}).Run(context.Background(), Spec{Tool: schema.Tool{ID: "fixture", Kind: "native", Binary: executable}, EnvOverrides: []string{"CYBOT_TEST_PROCESS=finding", "GORACE=atexit_sleep_ms=0"}, AcceptExitCodes: []int{1, 2}, Timeout: 5 * time.Second})
	if err != nil || out.ExitCode != 2 || string(out.Stdout) != `{"site":[]}` {
		t.Fatalf("finding exit treated as process failure: %#v %v", out, err)
	}
}

func TestDeadlineCannotBecomeAnAcceptedFindingExit(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = (LocalRunner{}).Run(context.Background(), Spec{Tool: schema.Tool{ID: "fixture", Kind: "native", Binary: executable}, EnvOverrides: []string{"CYBOT_TEST_PROCESS=deadline", "GORACE=atexit_sleep_ms=0"}, AcceptExitCodes: []int{-1, 1, 2, 137}, Timeout: 100 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatal("interrupted scan was accepted as completed", err)
	}
}
