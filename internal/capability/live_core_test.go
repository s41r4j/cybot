package capability

// These opt-in tests execute installed binaries against loopback fixtures only.
// The host launcher runs this test binary inside Docker with --network none.
import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s41r4j/cybot/catalog"
	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/pkg/schema"
)

func liveDeps(t *testing.T) Dependencies {
	t.Helper()
	if os.Getenv("CYBOT_LIVE_CORE") != "1" {
		t.Skip("requires isolated installed core toolbox")
	}
	tools := registry.NewTools()
	all, err := catalog.Tools()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range all {
		tool.Kind = "native"
		tool.DockerImage = ""
		if err := tools.Upsert(tool); err != nil {
			t.Fatal(err)
		}
	}
	return Dependencies{Tools: tools, Runner: execution.LocalRunner{}, Evidence: evidence.New(t.TempDir()), Timeout: 45 * time.Second}
}
func liveCapability(t *testing.T, id string) externalCapability {
	t.Helper()
	r := NewRegistry()
	if err := RegisterBuiltins(r); err != nil {
		t.Fatal(err)
	}
	c, _ := r.Get(id)
	return c.(externalCapability)
}
func liveRequest(target string) schema.RunRequest {
	return schema.RunRequest{RunID: "local-fixture", Target: target, Approved: true, Input: json.RawMessage(`{}`)}
}
func fixtureHTTP(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/about" && r.URL.Path != "/admin" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><title>CYBOT fixture</title><a href="/about">About</a>cybot-fixture-marker</html>`)
	}))
	t.Cleanup(server.Close)
	return server
}
func replaceArgument(args []string, key, value string) []string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == key {
			args[i+1] = value
			break
		}
	}
	return args
}

func TestLiveCoreWebMapping(t *testing.T) {
	d := liveDeps(t)
	server := fixtureHTTP(t)
	result, err := liveCapability(t, "web.map").Run(context.Background(), liveRequest(server.URL), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Errors) != 0 || len(result.Evidence) != 2 {
		t.Fatalf("incomplete mapping: %+v", result)
	}
	found := false
	for _, ep := range result.Endpoints {
		found = found || ep.URL == server.URL+"/about"
	}
	if !found {
		t.Fatalf("crawl missed link: %+v", result.Endpoints)
	}
	validateFixtureResult(t, result)
}
func TestLiveCoreFFUF(t *testing.T) {
	d := liveDeps(t)
	server := fixtureHTTP(t)
	words := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(words, []byte("admin\nmissing-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := liveCapability(t, "web.content.discover")
	// Substitute a two-entry fixture wordlist; production flags and parser remain.
	c.steps[0].Args = func(target string, r schema.RunRequest) []string {
		return replaceArgument(ffufArgs(target, r), "-w", words)
	}
	result, err := c.Run(context.Background(), liveRequest(server.URL), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Endpoints) != 1 || result.Endpoints[0].URL != server.URL+"/admin" || result.Endpoints[0].Status != 200 {
		t.Fatalf("unexpected normalized match: %+v", result.Endpoints)
	}
	validateFixtureResult(t, result)
}
func TestLiveCoreNuclei(t *testing.T) {
	d := liveDeps(t)
	server := fixtureHTTP(t)
	template := filepath.Join(t.TempDir(), "fixture.yaml")
	content := `id: cybot-fixture-marker
info:
  name: CYBOT fixture marker
  author: cybot
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "cybot-fixture-marker"
`
	if err := os.WriteFile(template, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	c := liveCapability(t, "web.scan")
	c.steps[0].Args = func(target string, r schema.RunRequest) []string {
		return replaceArgument(nucleiArgs(target, r), "-templates", template)
	}
	result, err := c.Run(context.Background(), liveRequest(server.URL), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Severity != "info" {
		t.Fatalf("missing fixture finding: %+v", result)
	}
	validateFixtureResult(t, result)
	// A nonmatching response must not create a finding.
	result, err = c.Run(context.Background(), liveRequest(server.URL+"/missing-fixture"), d)
	if err != nil || len(result.Findings) != 0 {
		t.Fatalf("false positive: %+v %v", result, err)
	}
}
func TestLiveCoreNmap(t *testing.T) {
	d := liveDeps(t)
	server := fixtureHTTP(t)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	tool, _ := d.Tools.Get("nmap")
	// A single fixture port exercises the actual Nmap XML contract without a broad scan.
	out, err := d.Runner.Run(context.Background(), execution.Spec{Tool: tool, Args: []string{"-sT", "-n", "-Pn", "-p", port, "-oX", "-", "127.0.0.1"}, Timeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := parseNmap(out.Stdout, liveRequest("127.0.0.1"))
	if err != nil || len(result.Services) != 1 {
		t.Fatalf("port missing: %+v %v", result, err)
	}
	validateFixtureResult(t, result)
}
func TestLiveCoreDNS(t *testing.T) {
	d := liveDeps(t)
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, e := conn.ReadFrom(buf)
			if e != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			if n < 17 {
				continue
			}
			end := 12
			for end < n && q[end] != 0 {
				end += int(q[end]) + 1
			}
			end += 5
			if end > n {
				continue
			}
			typ := binary.BigEndian.Uint16(q[end-4 : end-2])
			answer := append([]byte(nil), q[:end]...)
			answer[2] = 0x81
			answer[3] = 0x80
			answer[6] = 0
			answer[7] = 0
			if typ == 1 {
				answer[7] = 1
				answer = append(answer, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
			}
			_, _ = conn.WriteTo(answer, addr)
		}
	}()
	c := liveCapability(t, "dns.analyse")
	c.steps[0].Args = func(target string, r schema.RunRequest) []string {
		return append(dnsxArgs(target, r), "-resolver", conn.LocalAddr().String(), "-retry", "1", "-timeout", "1s")
	}
	result, err := c.Run(context.Background(), liveRequest("fixture.invalid"), d)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range result.Assets {
		found = found || a.Value == "127.0.0.1"
	}
	if !found {
		t.Fatalf("DNS response lost: %+v", result)
	}
	validateFixtureResult(t, result)
}
func TestLiveCoreSubfinderArguments(t *testing.T) {
	_ = liveDeps(t)
	args := append(subfinderArgs("fixture.invalid", schema.RunRequest{}), "-list-sources")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "subfinder", args...).CombinedOutput()
	if err != nil || !strings.Contains(strings.ToLower(string(out)), "crtsh") {
		t.Fatalf("subfinder flags/provider list invalid: %v %s", err, out)
	}
	// This is offline startup/argument validation, not an online provider test.
}
func TestLiveCoreCLIPersistence(t *testing.T) {
	_ = liveDeps(t)
	server := fixtureHTTP(t)
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(config, []byte("data_dir: "+filepath.Join(dir, "state")+"\npacks:\n  auto_update: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "cybot", append([]string{"--config", config}, args...)...)
		var diagnostics strings.Builder
		cmd.Stderr = &diagnostics
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("CLI %v: %v %s", args, err, diagnostics.String())
		}
		return out
	}
	var result schema.Result
	if err := json.Unmarshal(cli("run", "web.map", "--target", server.URL, "--approve"), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "completed" || result.RunID == "" {
		t.Fatalf("failed CLI result: %+v", result)
	}
	if !strings.Contains(string(cli("history", "list", "--limit", "1")), result.RunID) {
		t.Fatal("history missing run")
	}
	if !strings.Contains(string(cli("report", "generate", result.RunID, "--format", "markdown")), result.RunID) {
		t.Fatal("report missing run")
	}
	// Missing specialist dependencies must be visible instead of false success.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := exec.CommandContext(ctx, "cybot", "--config", config, "run", "code.audit", "--target", dir, "--approve").Run()
	if err == nil {
		t.Fatal("missing code-analysis tools reported success")
	}
}

func TestLiveCoreReadiness(t *testing.T) {
	_ = liveDeps(t)
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(config, []byte("data_dir: "+filepath.Join(dir, "state")+"\npacks:\n  auto_update: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "cybot", "--config", config, "capability", "readiness").Output()
	if err != nil {
		t.Fatal(err)
	}
	var report Readiness
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Tools) != 84 || len(report.Capabilities) != 71 || report.Counts["tools_available"] < 11 {
		t.Fatalf("unexpected inventory: %+v", report.Counts)
	}
	found := false
	for _, c := range report.Capabilities {
		if c.ID == "exploit.execute" {
			found = true
			if c.Status != "not-implemented" {
				t.Fatalf("help-only adapter advertised as %s", c.Status)
			}
		}
	}
	if !found {
		t.Fatal("capability absent from readiness report")
	}
}
