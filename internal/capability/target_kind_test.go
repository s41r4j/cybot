package capability

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoteTargetsNeverBecomeLocalMounts(t *testing.T) {
	for _, target := range []string{"https://fixture.invalid/a", "::1", "local://fixture-host", "interface://eth0"} {
		actual, host, container, mounts, err := executionTarget("web.scan", target, true)
		if err != nil || actual != target || host != "" || container != "" || len(mounts) != 0 {
			t.Fatalf("remote data became a path: %q %v", actual, err)
		}
	}
	// Matching an existing local path must not change a network operation's input.
	path := filepath.Join(t.TempDir(), "fixture.test")
	if err := os.WriteFile(path, []byte("private local data"), 0600); err != nil {
		t.Fatal(err)
	}
	actual, _, _, mounts, err := executionTarget("service.enumerate", path, true)
	if err != nil || actual != path || len(mounts) != 0 {
		t.Fatal("network target mounted local data", actual, mounts, err)
	}
	actual, _, container, mounts, err := executionTarget("secret.scan", path, true)
	if err != nil || actual != "/input" || container != "" || len(mounts) != 1 || !mounts[0].ReadOnly {
		t.Fatal("filesystem target lost its read-only mapping", actual, mounts, err)
	}
	ref := "registry.invalid/team/image:tag"
	actual, _, _, mounts, err = executionTarget("container.scan", ref, true)
	if err != nil || actual != ref || len(mounts) != 0 {
		t.Fatal("registry reference became filesystem input", actual, mounts, err)
	}
}
