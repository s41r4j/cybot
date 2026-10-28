package capability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/pkg/schema"
	jsonschemas "github.com/s41r4j/cybot/schemas"
)

// ZAP baseline capability runs OWASP ZAP's zap-baseline.py against a target and
// normalizes the JSON report into cybot findings.

type ZAPBaseline struct{}

func (ZAPBaseline) ID() string { return "web.zap" }
func (ZAPBaseline) Definition() schema.CapabilityDefinition {
	return schema.CapabilityDefinition{
		ID: "web.zap", Title: "OWASP ZAP Baseline Scan", Version: "1.0.0", Category: "web-security", Stability: "stable",
		Documentation: schema.Documentation{
			Description: "Run a deterministic OWASP ZAP baseline scan against a policy-authorized web target.",
			Purpose:     "Surface common web vulnerabilities (injection, XSS, security misconfiguration) using a hardened, deterministic ZAP baseline.",
			Arguments:   []schema.Argument{{Name: "target", Type: "url", Required: true, Description: "Policy-authorized http/https URL."}},
			Examples: []schema.Example{
				{Description: "Scan an authorized target", Command: "cybot run web.zap --target https://authorized.example --approve"},
			},
			ExpectedOutput:      "A cybot.result with findings from the ZAP baseline report, including severity, alert, and affected URL.",
			OutputSchema:        "cybot://schemas/result",
			Limitations:         []string{"ZAP baseline is passive-leaning; it does not attempt all active attack vectors.", "Requires the ZAP docker image to be pulled on the host."},
			RequiredPermissions: []string{"Explicit target authorization", "Capability approval under active policy"},
			RelatedCommands:     []string{"cybot capability plan web.zap", "cybot tool doctor zap"},
			CommonMistakes:      []string{"Scanning targets without authorization", "Assuming a baseline clean scan means the target is secure"},
			BestPractices:       []string{"Run web.map first to confirm reachability", "Manually verify high-severity ZAP alerts"},
		},
		InputSchema:  jsonRaw(`{"type":"object","additionalProperties":false,"required":["target"],"properties":{"target":{"type":"string","format":"uri"}}}`),
		OutputSchema: jsonschemas.Must("result"),
		Workflow: []schema.DecisionNode{
			{ID: "validate", Action: "Validate strict input and policy scope", Condition: "input matches schema and policy permits target", OnSuccess: "select", OnFailure: "deny"},
			{ID: "select", Action: "Select the ZAP baseline adapter", Condition: "adapter is healthy and image is present", OnSuccess: "scan", OnFailure: "fail"},
			{ID: "scan", Action: "Run zap-baseline.py and collect the JSON report", Condition: "scan completes within timeout", OnSuccess: "normalize", OnFailure: "fail"},
			{ID: "normalize", Action: "Normalize ZAP alerts into cybot findings", Condition: "report parsed", OnSuccess: "return", OnFailure: "fail"},
		},
		ToolChoices:         []schema.ToolChoice{{ToolID: "zap", SelectedWhen: "target is http(s) and the ZAP image is present", SkipWhen: "image missing or target invalid", Reason: "Deterministic ZAP baseline adapter with structured JSON report."}},
		Assumptions:         []string{"The target URL is authorized by policy.", "The ZAP image is available locally or pullable."},
		VerificationSteps:   []string{"Manually confirm high-severity alerts with an authorized retest.", "Review ZAP alert details and affected URLs."},
		RelatedCapabilities: []string{"web.scan", "vuln.scan"},
		NextCapabilities:    []string{"vuln.scan", "sql.inject", "xss.detect"},
	}
}

func (ZAPBaseline) Run(ctx context.Context, req schema.RunRequest, d Dependencies) (schema.Result, error) {
	target := strings.TrimSpace(req.Target)
	if err := validateBrowserTarget(target); err != nil {
		return emptyResult(), err
	}
	tool, ok := d.Tools.Get("zap")
	if !ok {
		return emptyResult(), fmt.Errorf("zap adapter is not registered")
	}
	if tool.Kind != "docker" {
		return emptyResult(), fmt.Errorf("web.zap requires the ZAP Docker adapter")
	}
	out, runErr := d.Runner.Run(ctx, executionSpecZAP(d, tool, target))
	if runErr != nil {
		return emptyResult(), runErr
	}
	normalized, parseErr := parseZAPBaseline(out.Stdout, req)
	if parseErr != nil {
		return emptyResult(), fmt.Errorf("normalize ZAP output: %w", parseErr)
	}
	ev, evErr := d.Evidence.Put(req.RunID, "zap-baseline-report", "application/json", out.Stdout)
	if evErr != nil {
		return emptyResult(), evErr
	}
	ev.Metadata = map[string]string{"tool": "zap", "target": target}
	for i := range normalized.Findings {
		normalized.Findings[i].EvidenceIDs = []string{ev.ID}
	}
	normalized.Evidence = append(normalized.Evidence, ev)
	normalized.Decisions = append(normalized.Decisions, schema.Decision{Stage: "tool-selection", Selected: "zap", Reason: "ZAP baseline adapter collected a structured report; installed version is unverified.", Skipped: []schema.SkippedOption{}})
	if strings.HasSuffix(tool.DockerImage, ":stable") || strings.HasSuffix(tool.DockerImage, ":latest") {
		normalized.Warnings = append(normalized.Warnings, "ZAP image tag floats; its declared version has not been verified.")
	}
	normalized.Assumptions = append(normalized.Assumptions, "The target URL is authorized by policy.")
	normalized.VerificationRecommended = append(normalized.VerificationRecommended, "Manually confirm high-severity alerts with an authorized retest.")
	normalized.NextCapabilities = append(normalized.NextCapabilities, "vuln.scan", "sql.inject", "xss.detect")
	normalized.RelatedWorkflows = relatedWorkflows("web.zap")
	normalized.PossibleFalsePositives = falsePositiveGuidance("web.zap")
	return normalized, nil
}

// ZAP writes a JSON file and prints human-readable progress to stdout. Keep
// progress on stderr and return only the report on stdout. Exit 1/2 mean alerts.
func executionSpecZAP(d Dependencies, tool schema.Tool, target string) execution.Spec {
	const script = `"$@" >&2; code=$?; if [ "$code" -gt 2 ]; then exit "$code"; fi; cat /zap/wrk/cybot-report.json || exit 3; exit "$code"`
	args := []string{"-c", script, "cybot-zap", tool.Binary}
	args = append(args, zapBaselineArgs(target)...)
	return execution.Spec{Tool: tool, Args: args, Entrypoint: "sh", Timeout: d.Timeout, Network: true, AcceptExitCodes: []int{1, 2}}
}

func zapBaselineArgs(target string) []string {
	return []string{"-t", target, "-J", "cybot-report.json", "-m", "1", "-T", "5", "--autooff"}
}

type zapNumber int

func (n *zapNumber) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		value = string(data)
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("invalid ZAP numeric field: %w", err)
	}
	*n = zapNumber(parsed)
	return nil
}

type zapInstance struct {
	URI    string `json:"uri"`
	Method string `json:"method"`
}

func parseZAPBaseline(data []byte, req schema.RunRequest) (schema.Result, error) {
	r := emptyResult()
	var report struct {
		Site *[]struct {
			Name   string `json:"name"`
			Alerts []struct {
				ID         string          `json:"pluginid"`
				Alert      string          `json:"alert"`
				Riskcode   zapNumber       `json:"riskcode"`
				Confidence json.RawMessage `json:"confidence"`
				Desc       string          `json:"desc"`
				Solution   string          `json:"solution"`
				Instances  []zapInstance   `json:"instances"`
			} `json:"alerts"`
		} `json:"site"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return r, err
	}
	if report.Site == nil {
		return r, fmt.Errorf("ZAP report is missing its site array")
	}
	seen := map[string]bool{}
	for _, site := range *report.Site {
		for _, a := range site.Alerts {
			if a.Alert == "" || a.Riskcode < 0 || a.Riskcode > 3 {
				return r, fmt.Errorf("ZAP alert has an invalid title or risk code")
			}
			instances := a.Instances
			if len(instances) == 0 {
				instances = []zapInstance{{URI: site.Name}}
			}
			for _, instance := range instances {
				key := a.ID + "\x00" + a.Alert + "\x00" + instance.Method + "\x00" + instance.URI
				if seen[key] {
					continue
				}
				seen[key] = true
				desc := strings.TrimSpace(a.Desc)
				if a.Solution != "" {
					desc += " Solution: " + strings.TrimSpace(a.Solution)
				}
				if instance.URI != "" {
					desc += " Affected: " + instance.URI
				}
				r.Findings = append(r.Findings, schema.Finding{ID: "zap:" + stableKey(key), Title: a.Alert, Description: desc, Severity: severityFromZAP(int(a.Riskcode)), Confidence: zapConfidence(strings.Trim(string(a.Confidence), `"`))})
			}
		}
	}
	sortFindings(&r)
	r.Summary = fmt.Sprintf("ZAP baseline completed with %d finding(s).", len(r.Findings))
	r.Confidence = .8
	return r, nil
}

func severityFromZAP(riskcode int) schema.Severity {
	switch riskcode {
	case 3:
		return schema.SeverityHigh
	case 2:
		return schema.SeverityMedium
	case 1:
		return schema.SeverityLow
	default:
		return schema.SeverityInfo
	}
}
func zapConfidence(c string) float64 {
	switch strings.ToLower(c) {
	case "4", "confirmed":
		return 1
	case "3", "high":
		return .9
	case "2", "medium":
		return .75
	case "1", "low":
		return .55
	case "0", "false positive":
		return 0
	default:
		return .5
	}
}
func stableKey(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }
