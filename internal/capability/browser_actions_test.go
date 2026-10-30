package capability

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/pkg/schema"
)

func TestBrowserActionsRejectUnsupportedInputBeforeExecution(t *testing.T) {
	c := browserCapability{mode: "automate"}
	for _, data := range []string{
		`null`, `[]`, `{} {}`, `{"actions":[{"action":"eval","selector":"alert(1)"}]}`,
		`{"actions":[{"action":"click","selector":"--cdp"}]}`,
		`{"actions":[{"action":"click","selector":"@e1"}]}`,
		`{"actions":[{"action":"wait","milliseconds":2001}]}`,
		`{"actions":[{"action":"wait","milliseconds":1.5}]}`,
		`{"actions":[{"action":"click","selector":"#fixture","unexpected":true}]}`,
		`{"target":"https://other.invalid","actions":[]}`,
	} {
		req := schema.RunRequest{Target: "https://fixture.invalid", Input: json.RawMessage(data), Approved: true}
		if err := c.ValidateRequest(req); err == nil {
			t.Error("invalid browser input accepted", data)
		}
	}
	req := schema.RunRequest{Target: "https://fixture.invalid", Input: json.RawMessage(`{"actions":[{"action":"click","selector":"button[data-label=\"a b\"]"}]}`)}
	if err := c.ValidateRequest(req); err == nil || !c.RequiresInputApproval(req) {
		t.Fatal("unapproved action accepted", err)
	}
	req.Approved = true
	commands, err := c.batchCommands(browserAutomateArgs(req.Target, req), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) < 3 || len(commands[2]) != 2 || commands[2][1] != `button[data-label="a b"]` {
		t.Fatal("selector was split or reinterpreted as commands", commands)
	}
	if _, err := (browserCapability{mode: "browse"}).actionCommands(req); err == nil {
		t.Fatal("read-only mode accepted actions")
	}
}

func TestBrowserRunsExcludeHostSessionConfigurationAndUseOwnedCleanup(t *testing.T) {
	t.Setenv("AGENT_BROWSER_AUTO_CONNECT", "1")
	t.Setenv("AGENT_BROWSER_PROVIDER", "unrelated-provider")
	t.Setenv("AGENT_BROWSER_PROFILE", "operator-profile")
	tools := registry.NewTools()
	if err := tools.Register(schema.Tool{ID: "agent-browser", Version: "0.40.0", Kind: "native", Binary: "agent-browser"}); err != nil {
		t.Fatal(err)
	}
	runner := &fixtureRunner{outputs: map[string][]byte{"agent-browser": []byte(`[{"success":true,"result":{"url":"https://fixture.invalid/"}}]`)}}
	c := browserCapability{definition: browserDefinition("web.browse", "Browser", "web-security", "d", "p"), mode: "browse"}
	for range 2 {
		_, err := c.Run(context.Background(), schema.RunRequest{RunID: "fixture", Target: "https://fixture.invalid", Input: json.RawMessage(`{}`)}, Dependencies{Tools: tools, Runner: runner, Evidence: evidence.New(t.TempDir())})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(runner.specs) != 4 {
		t.Fatal("each batch must have an owned-session close", len(runner.specs))
	}
	for i := 0; i < 4; i += 2 {
		batch, close := runner.specs[i], runner.specs[i+1]
		if batch.Args[0] != "--session" || batch.Args[1] != close.Args[1] || close.Args[len(close.Args)-1] != "close" {
			t.Fatal("cleanup did not select only the owned session", batch.Args, close.Args)
		}
		if batch.WorkDir == "" || batch.WorkDir != close.WorkDir {
			t.Fatal("browser state directory is not isolated")
		}
		if _, err := os.Stat(batch.WorkDir); !os.IsNotExist(err) {
			t.Fatal("owned browser state was not removed", err)
		}
		for _, value := range batch.Env {
			if strings.HasPrefix(value, "AGENT_BROWSER_AUTO_CONNECT=") || strings.HasPrefix(value, "AGENT_BROWSER_PROFILE=") || strings.HasPrefix(value, "AGENT_BROWSER_PROVIDER=") {
				t.Fatal("browser inherited unrelated operator session configuration", value)
			}
		}
		args := strings.Join(batch.Args, " ")
		if !strings.Contains(args, "--allowed-domains fixture.invalid") || !strings.Contains(args, "--omit-command") {
			t.Fatal("browser lacks hostname scope or command-output privacy", batch.Args)
		}
	}
	if runner.specs[0].Args[1] == runner.specs[2].Args[1] {
		t.Fatal("independent runs shared a browser session")
	}
}

func TestBrowserCurrentSnapshotAndEmptyCaptureContracts(t *testing.T) {
	data := `[{"success":true,"result":{"snapshot":"- link About [ref=e1, url=https://fixture.invalid/about]","origin":"https://fixture.invalid/","refs":{"e1":{"name":"About","role":"link"}}}}]`
	r, err := parseBrowserBatch("automate", []byte(data), schema.RunRequest{})
	if err != nil || len(r.Endpoints) != 2 || r.Endpoints[1].URL != "https://fixture.invalid/about" || len(r.Observations) != 1 {
		t.Fatalf("actual CLI snapshot format was lost: %+v %v", r, err)
	}
	if _, err := parseBrowserBatch("browse", []byte(`[{"success":true,"result":{"ms":2000,"waited":"timeout"}}]`), schema.RunRequest{}); err == nil {
		t.Fatal("wait-only output accepted as a completed page capture")
	}
}
