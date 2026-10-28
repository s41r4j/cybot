package execution

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/s41r4j/cybot/pkg/schema"
)

type Spec struct {
	Tool             schema.Tool
	Args             []string
	Env              []string
	WorkDir          string
	ContainerWorkDir string
	Entrypoint       string
	Mounts           []Mount
	Timeout          time.Duration
	Retries          int
	Network          bool
	AcceptExitCodes  []int
}

type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}
type Output struct {
	Stdout, Stderr []byte
	ExitCode       int
	Duration       time.Duration
	Attempts       int
}
type Runner interface {
	Run(context.Context, Spec) (Output, error)
	Health(context.Context, schema.Tool) error
}
type LocalRunner struct{}

type BoundedRunner struct {
	base      Runner
	semaphore chan struct{}
	maxRate   int
	mu        sync.Mutex
	next      time.Time
}

func NewBounded(base Runner, concurrency, maxRate int) *BoundedRunner {
	if concurrency < 1 {
		concurrency = 1
	}
	return &BoundedRunner{base: base, semaphore: make(chan struct{}, concurrency), maxRate: maxRate}
}
func (b *BoundedRunner) Health(ctx context.Context, t schema.Tool) error {
	return b.base.Health(ctx, t)
}
func (b *BoundedRunner) Run(ctx context.Context, s Spec) (Output, error) {
	select {
	case b.semaphore <- struct{}{}:
		defer func() { <-b.semaphore }()
	case <-ctx.Done():
		return Output{}, ctx.Err()
	}
	if err := b.waitRate(ctx); err != nil {
		return Output{}, err
	}
	return b.base.Run(ctx, s)
}
func (b *BoundedRunner) waitRate(ctx context.Context) error {
	if b.maxRate <= 0 {
		return nil
	}
	b.mu.Lock()
	now := time.Now()
	wait := time.Duration(0)
	if now.Before(b.next) {
		wait = b.next.Sub(now)
	}
	base := now
	if b.next.After(base) {
		base = b.next
	}
	b.next = base.Add(time.Second / time.Duration(b.maxRate))
	b.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (LocalRunner) Health(ctx context.Context, t schema.Tool) error {
	if t.Kind == "docker" {
		if _, e := exec.LookPath("docker"); e != nil {
			return fmt.Errorf("docker: %w", e)
		}
		if t.DockerImage == "" {
			return fmt.Errorf("tool %s has no Docker image", t.ID)
		}
		if err := exec.CommandContext(ctx, "docker", "image", "inspect", t.DockerImage).Run(); err != nil {
			return fmt.Errorf("inspect Docker image %s: %w", t.DockerImage, err)
		}
		if t.Binary == "" {
			return fmt.Errorf("tool %s has no binary", t.ID)
		}
		healthCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(healthCtx, "docker", "run", "--rm", "--pull", "never", "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.25", "--pids-limit", "32", "--log-driver", "none", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--entrypoint", "sh", t.DockerImage, "-c", `command -v -- "$1" >/dev/null`, "cybot-health", t.Binary)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("tool %s is missing from %s: %w: %s", t.Binary, t.DockerImage, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if len(t.SupportedOS) > 0 && !contains(t.SupportedOS, runtime.GOOS) {
		return fmt.Errorf("tool %s does not support %s", t.ID, runtime.GOOS)
	}
	if _, e := exec.LookPath(t.Binary); e != nil {
		return fmt.Errorf("%s: %w", t.Binary, e)
	}
	return nil
}
func (r LocalRunner) Run(ctx context.Context, s Spec) (Output, error) {
	if err := r.Health(ctx, s.Tool); err != nil {
		return Output{}, err
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	var last error
	var out Output
	for attempt := 1; attempt <= s.Retries+1; attempt++ {
		runctx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		var cmd *exec.Cmd
		var cidDir string
		if s.Tool.Kind == "docker" {
			var err error
			cidDir, err = os.MkdirTemp("", "cybot-container-")
			if err != nil {
				cancel()
				return Output{}, err
			}
			network := "none"
			if s.Network {
				network = "bridge"
			}
			args := []string{"run", "--rm", "--pull", "never", "--name", "cybot-toolbox-active", "--cidfile", filepath.Join(cidDir, "id"), "--label", "io.cybot.managed=true", "--memory", "2g", "--memory-swap", "2g", "--cpus", "1", "--pids-limit", "256", "--log-driver", "none", "--network", network, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/home/cybot/.cache:rw,noexec,nosuid,size=128m,uid=10001,gid=10001", "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m", "--tmpfs", "/home/cybot/.config:rw,noexec,nosuid,size=16m,uid=10001,gid=10001"}
			for _, wp := range s.Tool.WritablePaths {
				if wp == "" {
					continue
				}
				args = append(args, "--tmpfs", wp+":rw,noexec,nosuid,size=128m,mode=1777")
			}
			for _, mount := range s.Mounts {
				mode := "rw"
				if mount.ReadOnly {
					mode = "ro"
				}
				args = append(args, "--mount", fmt.Sprintf("type=bind,src=%s,dst=%s,%s", mount.Source, mount.Target, mode))
			}
			if s.ContainerWorkDir != "" {
				args = append(args, "--workdir", s.ContainerWorkDir)
			}
			if s.Entrypoint != "" {
				args = append(args, "--entrypoint", s.Entrypoint, s.Tool.DockerImage)
			} else if isToolboxImage(s.Tool.DockerImage) {
				args = append(args, s.Tool.DockerImage, "exec", s.Tool.Binary)
			} else {
				args = append(args, "--entrypoint", s.Tool.Binary, s.Tool.DockerImage)
			}
			args = append(args, s.Args...)
			cmd = exec.CommandContext(runctx, "docker", args...)
		} else {
			cmd = exec.CommandContext(runctx, s.Tool.Binary, s.Args...)
		}
		if s.Tool.Kind != "docker" {
			cmd.Dir = s.WorkDir
		}
		cmd.Env = s.Env
		stdout := limitedOutput{limit: 8 << 20, cancel: cancel}
		stderr := limitedOutput{limit: 1 << 20, cancel: cancel}
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		cmd.WaitDelay = 2 * time.Second
		err := cmd.Run()
		deadlineExceeded := runctx.Err() == context.DeadlineExceeded
		cancel()
		if cidDir != "" {
			removeOwnedContainer(cidDir)
		}
		out = Output{Stdout: stdout.data, Stderr: stderr.data, Duration: time.Since(start), Attempts: attempt}
		if stdout.exceeded || stderr.exceeded {
			return out, fmt.Errorf("tool %s exceeded captured output limit (stdout 8 MiB, stderr 1 MiB); incomplete output must not be parsed as success", s.Tool.ID)
		}
		if err == nil {
			return out, nil
		}
		last = err
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			out.ExitCode = exit.ExitCode()
			if containsInt(s.AcceptExitCodes, out.ExitCode) {
				return out, nil
			}
		}
		if deadlineExceeded {
			last = fmt.Errorf("tool %s timed out after %s", s.Tool.ID, timeout)
		}
		if attempt <= s.Retries {
			select {
			case <-ctx.Done():
				return out, ctx.Err()
			case <-time.After(time.Duration(attempt) * 100 * time.Millisecond):
			}
		}
	}
	return out, fmt.Errorf("tool %s failed after %d attempt(s): %w: %s", s.Tool.ID, out.Attempts, last, strings.TrimSpace(string(out.Stderr)))
}
func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// Toolbox images initialize their bundled caches through the exec subcommand.
func isToolboxImage(image string) bool {
	base := image[strings.LastIndex(image, "/")+1:]
	return strings.HasPrefix(base, "cybotainer:") || strings.HasPrefix(base, "cybotainer@") || strings.HasPrefix(base, "cybot-toolbox:") || strings.HasPrefix(base, "cybot-toolbox@")
}
