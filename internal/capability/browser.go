package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/pkg/schema"
	jsonschemas "github.com/s41r4j/cybot/schemas"
)

// Browser capabilities drive a real Chrome via the agent-browser CLI. Each
// capability runs one deterministic batch in a fresh owned session, followed
// by an explicit close, so no browser state is shared between operations.

var browserURLRe = regexp.MustCompile(`url=(\S+)`)

func browserBrowseArgs(target string, _ schema.RunRequest) []string {
	return []string{"--json", "batch", "--bail", "open " + target, "wait 2000", "snapshot -i -c --urls", "get url", "get title"}
}

func browserAutomateArgs(target string, _ schema.RunRequest) []string {
	return []string{"--json", "batch", "--bail", "open " + target, "wait 2000", "snapshot -i --urls", "get url", "get title"}
}

func browserHarArgs(target string, _ schema.RunRequest) []string {
	return []string{"--json", "batch", "--bail", "open " + target, "wait 2000", "network requests --json", "get url"}
}

type browserCapability struct {
	definition schema.CapabilityDefinition
	mode       string
}

func (c browserCapability) ID() string                              { return c.definition.ID }
func (c browserCapability) Definition() schema.CapabilityDefinition { return c.definition }

func (c browserCapability) Run(ctx context.Context, req schema.RunRequest, d Dependencies) (schema.Result, error) {
	if req.Capability != "" && req.Capability != c.ID() {
		return emptyResult(), fmt.Errorf("request capability does not match %s", c.ID())
	}
	target := strings.TrimSpace(req.Target)
	if err := validateBrowserTarget(target); err != nil {
		return emptyResult(), err
	}
	req.Target = target
	tool, ok := d.Tools.Get("agent-browser")
	if !ok {
		return emptyResult(), fmt.Errorf("agent-browser adapter is not registered")
	}
	var args []string
	switch c.mode {
	case "automate":
		args = browserAutomateArgs(target, req)
	case "har":
		args = browserHarArgs(target, req)
	default:
		args = browserBrowseArgs(target, req)
	}
	commands, inputErr := c.batchCommands(args, req)
	if inputErr != nil {
		return emptyResult(), inputErr
	}
	out, runErr := runIsolatedBrowser(ctx, tool, target, commands, d)
	normalized, parseErr := parseBrowserBatch(c.mode, out.Stdout, req)
	if parseErr != nil {
		if runErr != nil {
			return emptyResult(), runErr
		}
		return emptyResult(), fmt.Errorf("normalize agent-browser output: %w", parseErr)
	}
	if runErr != nil {
		normalized.Errors = append(normalized.Errors, schema.RunError{Tool: "agent-browser", Code: "BROWSER_EXECUTION_INCOMPLETE", Message: runErr.Error()})
	}
	ev, evErr := d.Evidence.Put(req.RunID, "agent-browser-batch", "application/json", out.Stdout)
	if evErr != nil {
		return emptyResult(), evErr
	}
	ev.Metadata = map[string]string{"tool": "agent-browser", "mode": c.mode, "target": target}
	for i := range normalized.Findings {
		normalized.Findings[i].EvidenceIDs = []string{ev.ID}
	}
	normalized.Evidence = append(normalized.Evidence, ev)
	normalized.Decisions = append(normalized.Decisions, schema.Decision{Stage: "browser-automation", Selected: "agent-browser", Reason: "Deterministic batch browser automation selected for JS-rendered discovery.", Skipped: []schema.SkippedOption{}})
	normalized.Assumptions = append(normalized.Assumptions, c.definition.Assumptions...)
	normalized.VerificationRecommended = append(normalized.VerificationRecommended, c.definition.VerificationSteps...)
	normalized.NextCapabilities = append(normalized.NextCapabilities, c.definition.NextCapabilities...)
	normalized.RelatedWorkflows = relatedWorkflows(c.ID())
	normalized.PossibleFalsePositives = falsePositiveGuidance(c.ID())
	if len(normalized.Errors) > 0 {
		normalized.Status = "partial"
	}
	return normalized, nil
}

func validateBrowserTarget(target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if len(target) > 8192 || strings.ContainsAny(target, "\"'\\") || strings.IndexFunc(target, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return fmt.Errorf("URL must encode spaces and unsafe characters before browser/tool execution")
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("target must be an http or https URL without embedded credentials")
	}
	return nil
}

func parseBrowserBatch(mode string, data []byte, req schema.RunRequest) (schema.Result, error) {
	r := emptyResult()
	var results []json.RawMessage
	if err := json.Unmarshal(data, &results); err != nil {
		var single map[string]any
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return emptyResult(), err
		}
		results = []json.RawMessage{data}
	}
	var requestDocs []map[string]any
	succeeded := 0
	for _, raw := range results {
		var cmd struct {
			Success *bool          `json:"success"`
			Error   string         `json:"error"`
			Result  map[string]any `json:"result"`
		}
		if err := json.Unmarshal(raw, &cmd); err != nil {
			return r, fmt.Errorf("invalid browser command result: %w", err)
		}
		if cmd.Success == nil {
			return r, fmt.Errorf("browser command result is missing success")
		}
		if !*cmd.Success {
			r.Errors = append(r.Errors, schema.RunError{Tool: "agent-browser", Code: "BROWSER_COMMAND_FAILED", Message: cmd.Error, Retryable: false})
			continue
		}
		succeeded++
		if cmd.Result != nil {
			requestDocs = append(requestDocs, cmd.Result)
		}
	}
	if succeeded == 0 {
		return r, fmt.Errorf("no browser command completed successfully")
	}
	seen := map[string]bool{}
	addEndpoint := func(raw string, method string, status int, tech []string) {
		raw = strings.TrimSpace(raw)
		key := method + "\x00" + raw
		if raw == "" || seen[key] {
			return
		}
		if u, e := url.Parse(raw); e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return
		}
		seen[key] = true
		if tech == nil {
			tech = []string{}
		}
		r.Endpoints = append(r.Endpoints, schema.Endpoint{URL: evidence.SanitizeURL(raw), Method: method, Status: status, Technology: tech})
	}
	for _, doc := range requestDocs {
		switch {
		case doc["snapshot"] != nil:
			parseBrowserTree(text(doc["snapshot"]), addEndpoint)
			if mode == "automate" {
				if refs, ok := doc["refs"].(map[string]any); ok {
					keys := make([]string, 0, len(refs))
					for ref := range refs {
						keys = append(keys, ref)
					}
					sort.Strings(keys)
					for _, ref := range keys {
						if control, ok := refs[ref].(map[string]any); ok {
							r.Observations = append(r.Observations, evidence.RedactText(fmt.Sprintf("Interactive control ref=%s role=%s name=%s", ref, text(control["role"]), text(control["name"]))))
						}
					}
				}
			}
			if origin := text(doc["origin"]); origin != "" {
				addEndpoint(origin, "GET", 0, nil)
			}
		case doc["url"] != nil:
			addEndpoint(text(doc["url"]), "GET", 0, nil)
		case doc["requests"] != nil:
			if reqs, ok := doc["requests"].([]any); ok {
				for _, rq := range reqs {
					if m, ok := rq.(map[string]any); ok {
						u := text(m["url"])
						if u == "" {
							continue
						}
						addEndpoint(u, strings.ToUpper(text(m["method"])), int(number(m["status"])), texts(m["resourceType"]))
					}
				}
			}
		}
	}
	sort.Slice(r.Endpoints, func(i, j int) bool { return r.Endpoints[i].URL < r.Endpoints[j].URL })
	if len(r.Endpoints) == 0 && len(r.Observations) == 0 {
		return r, fmt.Errorf("browser report contains no completed page or network capture")
	}
	r.Summary = fmt.Sprintf("agent-browser %s completed: %d endpoint(s) discovered from rendered DOM and network.", mode, len(r.Endpoints))
	r.Confidence = 0.8
	return r, nil
}

func parseBrowserTree(tree string, addEndpoint func(string, string, int, []string)) {
	for _, line := range strings.Split(tree, "\n") {
		if m := browserURLRe.FindStringSubmatch(line); len(m) == 2 {
			addEndpoint(strings.TrimSuffix(strings.TrimSuffix(m[1], "]"), ","), "GET", 0, nil)
		}
	}
}

func browserDefinition(id, title, category, description, purpose string) schema.CapabilityDefinition {
	d := schema.CapabilityDefinition{
		ID: id, Title: title, Version: "1.1.0", Category: category, Stability: "experimental",
		Documentation: schema.Documentation{
			Description: description, Purpose: purpose,
			Arguments:           []schema.Argument{{Name: "target", Type: "url", Required: true, Description: "Policy-authorized http/https URL."}},
			Examples:            []schema.Example{{Description: "Browse a target", Command: "cybot run " + id + " --target https://authorized.example --approve"}},
			ExpectedOutput:      "A normalized cybot.result with endpoints discovered from the rendered DOM and network activity.",
			OutputSchema:        "cybot://schemas/result",
			Limitations:         []string{"Requires the pinned browser profile and Chromium.", "Each run uses a fresh anonymous browser and restricts navigation/subresources to the requested hostname; this does not bind traffic to a single port or path.", "Interactive mode supports at most 16 explicit click/wait actions; it does not accept JavaScript, fills, uploads or arbitrary CLI commands. Returned references describe this run and cannot be reused after its session closes.", "Network capture returns observed requests rather than a complete HAR archive; JS-heavy pages may need wait tuning.", "Container runs disable Chromium's internal sandbox within the bounded nonroot container; this is not a full browser sandbox certification."},
			RequiredPermissions: []string{"Explicit target authorization", "Capability approval under active policy"},
			RelatedCommands:     []string{"cybot capability plan " + id, "cybot tool doctor agent-browser"},
			CommonMistakes:      []string{"Passing a non-http(s) target", "Assuming every rendered link is in scope"},
			BestPractices:       []string{"Run web.map first", "Review extracted endpoints before deeper scanning"},
		},
		InputSchema:  browserInputSchema(id),
		OutputSchema: jsonschemas.Must("result"),
		Workflow: []schema.DecisionNode{
			{ID: "validate", Action: "Validate strict input and policy scope", Condition: "input matches schema and policy permits target", OnSuccess: "launch", OnFailure: "deny"},
			{ID: "launch", Action: "Launch agent-browser batch with a fresh Chrome session", Condition: "adapter is healthy", OnSuccess: "navigate", OnFailure: "fail"},
			{ID: "navigate", Action: "Open target and wait for render", Condition: "navigation succeeded", OnSuccess: "capture", OnFailure: "fail"},
			{ID: "capture", Action: "Snapshot DOM and capture network", Condition: "session is live", OnSuccess: "normalize", OnFailure: "fail"},
			{ID: "normalize", Action: "Extract endpoints into cybot.result", Condition: "capture produced data", OnSuccess: "return", OnFailure: "fail"},
		},
		ToolChoices:         []schema.ToolChoice{{ToolID: "agent-browser", SelectedWhen: "target is http(s) and adapter is healthy", SkipWhen: "adapter missing or target invalid", Reason: "Deterministic CDP browser automation with ref-based snapshots and network capture."}},
		Assumptions:         []string{"The target URL is authorized by policy.", "The agent-browser daemon and Chrome are available on the host or toolbox."},
		VerificationSteps:   []string{"Confirm discovered endpoints return 200 over an authorized channel.", "Spot-check JS-rendered endpoints in a manual browser."},
		RelatedCapabilities: []string{"web.map", "js.extract"},
		NextCapabilities:    []string{"web.map", "js.extract", "web.scan"},
	}
	if id == "web.automate" {
		d.Documentation.Arguments = append(d.Documentation.Arguments, schema.Argument{Name: "input-file", Type: "path", Required: false, Description: "JSON object with up to 16 click/wait actions. Click requires selector; wait requires milliseconds (0–2000). Actions require --approve even under advisory policy."})
		d.Documentation.Examples = append(d.Documentation.Examples, schema.Example{Description: "Execute an explicitly authorized bounded interaction", Command: "cybot run web.automate --target https://authorized.example --input-file actions.json --approve"})
		d.Documentation.RequiredPermissions = append(d.Documentation.RequiredPermissions, "Explicit --approve for all supplied actions, including in advisory mode")
	}
	return d
}

func RegisterBrowserCapabilities(r *Registry) error {
	caps := []browserCapability{
		{
			definition: browserDefinition("web.browse", "Web Browse (Rendered DOM)", "web-security",
				"Open a target in a real Chrome session and return the rendered accessibility snapshot plus discovered endpoints.",
				"Discover JS-rendered endpoints and page structure that plain HTTP crawlers cannot see."),
			mode: "browse",
		},
		{
			definition: browserDefinition("web.automate", "Web Automation (Interactive)", "web-security",
				"Perform a bounded sequence of explicitly approved clicks/waits and capture the resulting interactive page; omit actions for inspection only.",
				"Execute operator-specified interactions and return control roles, labels and session-scoped references for review."),
			mode: "automate",
		},
		{
			definition: browserDefinition("web.har", "Web HAR Capture", "web-security",
				"Open a target in a real browser and capture the observed network request log as normalized endpoints.",
				"Capture request methods, status codes, and resource types from a fresh anonymous, JS-rendered session."),
			mode: "har",
		},
	}
	for _, c := range caps {
		if err := r.Register(c); err != nil {
			return err
		}
	}
	return nil
}
