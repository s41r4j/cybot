package execution

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Continue accepting writes after cancellation so a noisy child cannot block a
// pipe reader. The caller reports truncation as an error, never a valid result.
type limitedOutput struct {
	data     []byte
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (b *limitedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - len(b.data)
	if len(p) > remaining {
		b.data = append(b.data, p[:remaining]...)
		b.exceeded = true
		b.cancel()
	} else {
		b.data = append(b.data, p...)
	}
	return n, nil
}

// A killed docker client does not stop its container. Only remove the exact ID
// created by this invocation; a name conflict must never stop another run.
func removeOwnedContainer(dir string) {
	defer os.RemoveAll(dir)
	id, err := os.ReadFile(filepath.Join(dir, "id"))
	if err != nil {
		return
	}
	value := strings.TrimSpace(string(id))
	if len(value) != 64 || strings.Trim(value, "0123456789abcdef") != "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", value).Run()
}
