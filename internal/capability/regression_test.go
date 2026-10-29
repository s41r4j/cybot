package capability

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/pkg/schema"
	jsonschemas "github.com/s41r4j/cybot/schemas"
)

func validateFixtureResult(t *testing.T, r schema.Result) {
	t.Helper()
	r.RunID = uuid.NewString()
	r.Capability = "fixture"
	r.StartedAt = time.Now().UTC()
	r.FinishedAt = r.StartedAt
	if r.Status == "" {
		r.Status = "completed"
	}
	for i := range r.Findings {
		if r.Findings[i].EvidenceIDs == nil {
			r.Findings[i].EvidenceIDs = []string{}
		}
	}
	for i := range r.Endpoints {
		if r.Endpoints[i].Technology == nil {
			r.Endpoints[i].Technology = []string{}
		}
	}
	if err := jsonschemas.Validate("result", r); err != nil {
		t.Fatal(err)
	}
}

func TestNegativeMessagesAreNotFindings(t *testing.T) {
	for _, tc := range []struct{ tool, output string }{
		{"sqlmap", "all tested parameters do not appear to be injectable"},
		{"sqlmap", "parameter 'id' is not vulnerable"},
		{"corscanner", "Target is not vulnerable"},
		{"corscanner", "no CORS misconfigurations were found"},
		{"corscanner", "connection failed"},
	} {
		t.Run(tc.tool+tc.output, func(t *testing.T) {
			r, err := parseTool(tc.tool, []byte(tc.output), schema.RunRequest{Target: "https://example.test"})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Findings) != 0 {
				t.Fatalf("negative/error output became findings: %#v", r.Findings)
			}
			if strings.Contains(tc.output, "failed") && r.Status != "partial" {
				t.Fatal("unknown/error output reported as clean")
			}
			validateFixtureResult(t, r)
		})
	}
}

func TestPositiveReportsAndMixedNegativeProgress(t *testing.T) {
	sql := `[INFO] parameter 'other' is not injectable
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: id=fixture
`
	r, err := parseSQLMap([]byte(sql), schema.RunRequest{Target: "https://example.test"})
	if err != nil || len(r.Findings) != 1 {
		t.Fatalf("positive block: %#v %v", r, err)
	}
	cors, err := parseCORS([]byte("Target is not vulnerable\nhttps://example.test is vulnerable"), schema.RunRequest{Target: "https://example.test"})
	if err != nil || len(cors.Findings) != 1 {
		t.Fatalf("explicit positive: %#v %v", cors, err)
	}
}

func TestGenericOutputRemainsSchemaValidAndUnverified(t *testing.T) {
	for _, tc := range []struct {
		parser toolParser
		data   string
	}{
		{parseTextLines, "status message\nexample.test\n"},
		{parseJSONPassthrough, `{"status":"ok","secret":"FAKE_SENTINEL"}`},
	} {
		r, err := tc.parser([]byte(tc.data), schema.RunRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Assets) != 0 || len(r.Findings) != 0 || r.Status != "partial" || len(r.Warnings) == 0 || len(r.Observations) == 0 {
			t.Fatalf("unverified output misrepresented: %#v", r)
		}
		if strings.Contains(strings.Join(r.Observations, ""), "FAKE_SENTINEL") {
			t.Fatal("observation leaked secret")
		}
		validateFixtureResult(t, r)
	}
	if _, err := parseTextLines(bytes.Repeat([]byte("x"), 17<<20), schema.RunRequest{}); err == nil {
		t.Fatal("oversized line silently discarded")
	}
}

func TestNmapXMLContract(t *testing.T) {
	fixture := `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><hostnames><hostname name="example.test"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="fixture" version="1"/></port><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>`
	r, err := parseTool("nmap", []byte(fixture), schema.RunRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Assets) != 2 || len(r.Services) != 1 || r.Services[0].Port != 443 {
		t.Fatalf("wrong XML normalization: %#v", r)
	}
	validateFixtureResult(t, r)
	for _, bad := range []string{"not XML", `<other/>`, `<nmaprun><runstats><finished exit="error" errormsg="fixture error"/></runstats></nmaprun>`} {
		if _, err := parseNmap([]byte(bad), schema.RunRequest{}); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestSecretIDsHashEntireSecret(t *testing.T) {
	ids := map[string]bool{}
	for _, value := range []string{"FAKE-one", "FAKE-two"} {
		b, _ := json.Marshal(map[string]string{"DetectorName": "Fixture", "Raw": value})
		r, err := parseTruffleHog(b, schema.RunRequest{})
		if err != nil || len(r.Findings) != 1 {
			t.Fatalf("%v %#v", err, r)
		}
		id := r.Findings[0].ID
		if strings.Contains(id, "46414b45") || ids[id] {
			t.Fatalf("secret prefix exposed or ID collision: %s", id)
		}
		ids[id] = true
	}
}

func TestZAPMissingInstancesAndDistinctFindings(t *testing.T) {
	fixture := `{"site":[{"name":"https://example.test","alerts":[{"pluginid":"1","alert":"Header A","riskcode":"1","confidence":"2","instances":[]},{"pluginid":"2","alert":"Header B","riskcode":3,"confidence":3,"instances":[{"uri":"https://example.test/a"},{"uri":"https://example.test/b"}]}]}]}`
	r, err := parseZAPBaseline([]byte(fixture), schema.RunRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 3 {
		t.Fatalf("lost findings: %#v", r.Findings)
	}
	ids := map[string]bool{}
	for _, f := range r.Findings {
		if ids[f.ID] {
			t.Fatal("duplicate ID across alerts/URLs")
		}
		ids[f.ID] = true
	}
	validateFixtureResult(t, r)
	if _, err := parseZAPBaseline([]byte(`{}`), schema.RunRequest{}); err == nil {
		t.Fatal("accepted missing report")
	}
}

func TestBrowserEvidenceRedactsCredentials(t *testing.T) {
	tools := registry.NewTools()
	if err := tools.Register(schema.Tool{ID: "agent-browser", Kind: "native", Binary: "fixture"}); err != nil {
		t.Fatal(err)
	}
	runner := &fixtureRunner{outputs: map[string][]byte{"agent-browser": []byte(`[{"success":true,"result":{"url":"https://example.test/?token=FAKE_SENTINEL","headers":{"Authorization":"Bearer FAKE_SENTINEL"}}}]`)}}
	c := browserCapability{definition: browserDefinition("web.browse", "Browser", "web", "d", "p"), mode: "browse"}
	r, err := c.Run(context.Background(), schema.RunRequest{RunID: "fixture", Target: "https://example.test"}, Dependencies{Tools: tools, Runner: runner, Evidence: evidence.New(t.TempDir())})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(r.Evidence[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("FAKE_SENTINEL")) {
		t.Fatal("browser evidence leaked credentials")
	}
}

func TestMalformedBrowserReportsFail(t *testing.T) {
	for _, input := range []string{`[]`, `{}`, `[{"success":false,"error":"navigation failed"}]`, `[{"success":true},5]`} {
		if _, err := parseBrowserBatch("browse", []byte(input), schema.RunRequest{}); err == nil {
			t.Fatalf("accepted malformed/failed report: %s", input)
		}
	}
}

func TestDNSEnumDoesNotUseDNSXFlagsForSubfinder(t *testing.T) {
	r := NewRegistry()
	if err := RegisterBuiltins(r); err != nil {
		t.Fatal(err)
	}
	registered, _ := r.Get("dns.enum")
	c := registered.(externalCapability)
	for _, step := range c.steps {
		if step.ID != "subfinder" {
			continue
		}
		args := step.Args("fixture.invalid", schema.RunRequest{})
		joined := " " + strings.Join(args, " ") + " "
		if !strings.Contains(joined, " -d fixture.invalid ") || strings.Contains(joined, " -aaaa ") || strings.Contains(joined, " -resp ") || strings.Contains(joined, " -l ") {
			t.Fatalf("Subfinder received another tool's arguments: %v", args)
		}
		return
	}
	t.Fatal("Subfinder adapter missing")
}
