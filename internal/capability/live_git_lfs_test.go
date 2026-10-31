package capability

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Git LFS is a bundled analysis dependency, not a new catalog capability.
// Exercise actual object storage and retrieval without a remote or host config.
func TestLiveAnalysisGitLFS(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_ANALYSIS") != "1" {
		t.Skip("requires isolated installed analysis toolbox")
	}
	lfs, err := exec.LookPath("git-lfs")
	if err != nil {
		t.Fatal(err)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	home := t.TempDir()
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home,
		"XDG_CONFIG_HOME=" + home, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=false", "GIT_SSH_COMMAND=false", "LC_ALL=C"}
	run := func(binary string, input []byte, args ...string) ([]byte, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Dir, cmd.Env, cmd.Stdin = root, env, bytes.NewReader(input)
		var diagnostics bytes.Buffer
		cmd.Stderr = &diagnostics
		out, err := cmd.Output()
		if ctx.Err() != nil {
			t.Fatalf("offline Git LFS fixture timed out: %s", diagnostics.String())
		}
		return out, err
	}
	if _, err := run(git, nil, "init", "--template=", "."); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("CYBOT local Git LFS fixture\x00\n"), 1024)
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	pointer, err := run(lfs, payload, "clean", "--", "fixture.bin")
	expected := fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", digest, len(payload))
	if err != nil || string(pointer) != expected {
		t.Fatalf("clean did not produce the expected content-addressed pointer: %q %v", pointer, err)
	}
	stored, err := os.ReadFile(filepath.Join(root, ".git", "lfs", "objects", digest[:2], digest[2:4], digest))
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatalf("clean did not preserve the exact local object: %v", err)
	}
	restored, err := run(lfs, pointer, "smudge", "--", "fixture.bin")
	if err != nil || !bytes.Equal(restored, payload) {
		t.Fatalf("smudge failed the offline object round trip: %v", err)
	}
	if _, err := run(lfs, pointer, "pointer", "--check", "--strict", "--stdin"); err != nil {
		t.Fatalf("valid canonical pointer was rejected: %v", err)
	}
	plain := []byte("ordinary fixture content\n")
	unchanged, err := run(lfs, plain, "smudge", "--", "ordinary.txt")
	if err != nil || !bytes.Equal(unchanged, plain) {
		t.Fatalf("ordinary content changed: %q %v", unchanged, err)
	}
	if _, err := run(lfs, []byte("version https://git-lfs.github.com/spec/v1\noid sha256:invalid\nsize 1\n"), "pointer", "--check", "--strict", "--stdin"); err == nil {
		t.Fatal("malformed Git LFS pointer was accepted")
	}
}
