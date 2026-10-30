package capability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/pkg/schema"
)

// Use neither operator browser profiles nor the CLI's shared default daemon.
// Config and environment isolation also exclude auto-connect, cloud providers,
// plugins, proxies and certificate-verification overrides inherited from a host.
func runIsolatedBrowser(ctx context.Context, tool schema.Tool, target string, commands [][]string, d Dependencies) (out execution.Output, err error) {
	if tool.Kind != "native" {
		return out, fmt.Errorf("browser operations require the native CLI inside the browser profile")
	}
	base := os.TempDir()
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		base = "/tmp"
	}
	root, err := os.MkdirTemp(base, "cb-")
	if err != nil {
		return out, err
	}
	defer os.RemoveAll(root)
	for _, name := range []string{"home", "cache", "config", "s", "tmp"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			return out, err
		}
	}
	config := filepath.Join(root, "browser.json")
	if err := os.WriteFile(config, []byte("{}\n"), 0600); err != nil {
		return out, err
	}
	executable := os.Getenv("CYBOT_BROWSER_EXECUTABLE")
	if executable == "" {
		switch runtime.GOOS {
		case "darwin":
			executable = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		case "windows":
			executable = `C:\Program Files\Google\Chrome\Application\chrome.exe`
		default:
			executable = "/usr/bin/chromium"
		}
	}
	if !filepath.IsAbs(executable) || strings.ContainsAny(executable, "\x00\r\n") {
		return out, fmt.Errorf("CYBOT_BROWSER_EXECUTABLE must be an absolute executable path")
	}
	u, _ := url.Parse(target)
	session := "cb-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	prefix := []string{"--session", session, "--config", config, "--engine", "chrome", "--executable-path", executable, "--allowed-domains", u.Hostname(), "--headed", "false"}
	if os.Getenv("CYBOT_TOOLBOX_INTERNAL") == "1" {
		prefix = append(prefix, "--args", "--no-sandbox,--disable-dev-shm-usage")
	}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(root, "home"), "USERPROFILE=" + filepath.Join(root, "home"), "TMPDIR=" + filepath.Join(root, "tmp"), "TMP=" + filepath.Join(root, "tmp"), "TEMP=" + filepath.Join(root, "tmp"), "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "XDG_CACHE_HOME=" + filepath.Join(root, "cache"), "AGENT_BROWSER_SOCKET_DIR=" + filepath.Join(root, "s"), "LANG=C.UTF-8"}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
		defer cancel()
		closed, closeErr := d.Runner.Run(cleanupCtx, execution.Spec{Tool: tool, Args: append(append([]string{}, prefix...), "--json", "close"), Env: env, WorkDir: root, Timeout: 10 * time.Second, Retries: 0})
		var response struct {
			Success bool `json:"success"`
			Data    struct {
				Closed bool `json:"closed"`
			} `json:"data"`
		}
		if closeErr == nil && (json.Unmarshal(closed.Stdout, &response) != nil || !response.Success || !response.Data.Closed) {
			closeErr = errors.New("CLI did not confirm closure")
		}
		if closeErr != nil {
			err = errors.Join(err, fmt.Errorf("cleanup of owned browser session %s failed: %w", session, closeErr))
		}
	}()
	input, err := json.Marshal(commands)
	if err != nil {
		return out, err
	}
	return d.Runner.Run(ctx, execution.Spec{Tool: tool, Args: append(prefix, "--json", "batch", "--bail", "--omit-command"), Stdin: input, Env: env, WorkDir: root, Timeout: d.Timeout, Retries: 0, Network: true})
}
