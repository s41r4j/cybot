package execution

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestOutputOverflowCancelsAndNeverReportsSuccess(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := (LocalRunner{}).Run(ctx, Spec{
		Tool:    schema.Tool{ID: "noisy-fixture", Kind: "native", Binary: executable},
		Args:    []string{"-test.run=^TestOutputFixture$"},
		Env:     append(os.Environ(), "CYBOT_OUTPUT_FIXTURE=1"),
		Timeout: 5 * time.Second, AcceptExitCodes: []int{1}, Retries: 2,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeded captured output limit") {
		t.Fatalf("overflow should fail explicitly: %v", err)
	}
	if len(out.Stdout) != 8<<20 || out.Attempts != 1 {
		t.Fatalf("unbounded output or retried noisy process: %d bytes, %d attempts", len(out.Stdout), out.Attempts)
	}
}

func TestOutputFixture(t *testing.T) {
	if os.Getenv("CYBOT_OUTPUT_FIXTURE") != "1" {
		return
	}
	block := []byte(strings.Repeat("x", 64*1024))
	for i := 0; i < 256; i++ {
		_, _ = os.Stdout.Write(block)
	}
	os.Exit(0)
}

func TestLimitedOutputAcceptsBoundaryAndCancelsOverflow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := limitedOutput{limit: 4, cancel: cancel}
	_, _ = out.Write([]byte("1234"))
	if ctx.Err() != nil {
		t.Fatal("exact boundary canceled")
	}
	n, err := out.Write([]byte("567"))
	if n != 3 || err != nil || ctx.Err() == nil || string(out.data) != "1234" {
		t.Fatal("incorrect overflow behavior")
	}
	_, _ = out.Write([]byte("more"))
	if len(out.data) != 4 {
		t.Fatal("overflow kept allocating")
	}
}

// Opt-in integration check; never pulls an image or uses an external target.
func TestDockerDeadlineRemovesOwnedContainer(t *testing.T) {
	image := os.Getenv("CYBOT_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("set CYBOT_TEST_DOCKER_IMAGE to a local toolbox image")
	}
	existing, err := exec.Command("docker", "ps", "-aq", "--filter", "name=^/cybot-toolbox-active$").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(existing)) != "" {
		t.Skip("another CYBOT operation is active")
	}
	_, err = (LocalRunner{}).Run(context.Background(), Spec{
		Tool: schema.Tool{ID: "deadline-fixture", Kind: "docker", Binary: "sh", DockerImage: image},
		Args: []string{"-c", "sleep 30"}, Timeout: 2 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("deadline not reported: %v", err)
	}
	remaining, err := exec.Command("docker", "ps", "-aq", "--filter", "name=^/cybot-toolbox-active$").Output()
	if err != nil || strings.TrimSpace(string(remaining)) != "" {
		t.Fatalf("owned container leaked: %s %v", remaining, err)
	}
}
