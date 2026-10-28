package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/pkg/schema"
)

type toolStep struct {
	ID              string
	Args            func(target string, req schema.RunRequest) []string
	Required        bool
	AcceptExitCodes []int
}

type externalCapability struct {
	definition schema.CapabilityDefinition
	steps      []toolStep
}

func (c externalCapability) ID() string { return c.definition.ID }
func (c externalCapability) Definition() schema.CapabilityDefinition {
	d := c.definition
	d.Implementation = "adapter"
	d.Validation = "not-certified"
	d.ResourceScopes = []string{}
	implemented := 0
	for _, step := range c.steps {
		scope := toolScope(step.ID)
		d.ResourceScopes = append(d.ResourceScopes, scope)
		if scope != "target" {
			d.Documentation.Limitations = append(d.Documentation.Limitations, step.ID+" requires "+scope+"://RESOURCE and explicit approval; it does not act on a remote hostname.")
		}
		if reason := incompleteAdapters[step.ID]; reason != "" {
			d.Documentation.Limitations = append(d.Documentation.Limitations, step.ID+": "+reason)
		} else {
			implemented++
		}
		if normalization(step.ID) == "observations-only" {
			d.Stability = "experimental"
		}
	}
	d.ResourceScopes = unique(d.ResourceScopes, func(s string) string { return s })
	if implemented == 0 {
		d.Implementation = "not-implemented"
		d.Stability = "experimental"
	}
	if implemented < len(c.steps) && implemented > 0 {
		d.Implementation = "partial"
		d.Stability = "experimental"
	}
	return d
}

func (c externalCapability) Run(ctx context.Context, req schema.RunRequest, d Dependencies) (schema.Result, error) {
	target := strings.TrimSpace(req.Target)
	if err := validateCapabilityTarget(c.ID(), target); err != nil {
		return emptyResult(), err
	}
	combined := emptyResult()
	completed := 0
	for _, step := range c.steps {
		if scopeErr := validateStepScope(step.ID, req); scopeErr != nil {
			combined.Errors = append(combined.Errors, schema.RunError{Tool: step.ID, Code: "RESOURCE_SCOPE_REQUIRED", Message: scopeErr.Error()})
			if step.Required {
				return combined, scopeErr
			}
			continue
		}
		if reason := incompleteAdapters[step.ID]; reason != "" {
			combined.Errors = append(combined.Errors, schema.RunError{Tool: step.ID, Code: "ADAPTER_NOT_IMPLEMENTED", Message: reason})
			if step.Required {
				return combined, fmt.Errorf("%s: %s", step.ID, reason)
			}
			continue
		}
		tool, ok := d.Tools.Get(step.ID)
		if !ok {
			combined.Errors = append(combined.Errors, schema.RunError{Tool: step.ID, Code: "TOOL_NOT_REGISTERED", Message: "required deterministic adapter is not registered"})
			if step.Required {
				return combined, fmt.Errorf("required tool %q is not registered", step.ID)
			}
			continue
		}
		if tool.Version == "unresolved" || strings.HasSuffix(tool.DockerImage, ":latest") || strings.HasSuffix(tool.DockerImage, ":stable") {
			combined.Warnings = append(combined.Warnings, step.ID+": floating or unresolved version; reproducibility is unverified")
		}
		toolTarget, hostWorkdir, containerWorkdir, mounts, targetErr := executionTarget(target, tool.Kind == "docker")
		if targetErr != nil {
			return combined, targetErr
		}
		args := append([]string{}, tool.DefaultArgs...)
		if step.Args != nil {
			args = step.Args(toolTarget, req)
		}
		out, runErr := d.Runner.Run(ctx, execution.Spec{Tool: tool, Args: args, Timeout: d.Timeout, Retries: 0, Network: tool.RequiresNetwork, WorkDir: hostWorkdir, ContainerWorkDir: containerWorkdir, Mounts: mounts, AcceptExitCodes: step.AcceptExitCodes})
		if runErr != nil {
			combined.Errors = append(combined.Errors, schema.RunError{Tool: step.ID, Code: "TOOL_EXECUTION_FAILED", Message: runErr.Error(), Retryable: false})
			if step.Required {
				return combined, runErr
			}
			continue
		}
		normalized, parseErr := parseTool(step.ID, out.Stdout, req)
		if parseErr != nil {
			combined.Errors = append(combined.Errors, schema.RunError{Tool: step.ID, Code: "OUTPUT_CONTRACT_FAILED", Message: parseErr.Error(), Retryable: false})
			if step.Required {
				return combined, fmt.Errorf("normalize %s output: %w", step.ID, parseErr)
			}
			continue
		}
		evidenceBytes, mediaType, redactErr := evidenceOutput(step.ID, out.Stdout)
		if redactErr != nil {
			return combined, fmt.Errorf("redact %s evidence: %w", step.ID, redactErr)
		}
		ev, evidenceErr := d.Evidence.Put(req.RunID, step.ID+"-structured-output", mediaType, evidenceBytes)
		if evidenceErr != nil {
			return combined, evidenceErr
		}
		ev.Metadata = map[string]string{"tool": step.ID, "parser": tool.Parser, "version": tool.Version, "target": target}
		for i := range normalized.Findings {
			normalized.Findings[i].EvidenceIDs = []string{ev.ID}
		}
		normalized.Evidence = append(normalized.Evidence, ev)
		mergeResult(&combined, normalized)
		combined.Decisions = append(combined.Decisions, schema.Decision{Stage: "tool-selection", Selected: step.ID, Reason: "Configured adapter completed; evidence records its declared version.", Skipped: []schema.SkippedOption{}})
		completed++
	}
	if completed == 0 {
		return combined, fmt.Errorf("no deterministic tool step completed")
	}
	combined.Summary = summaryFor(c.ID(), combined, completed)
	combined.Confidence = resultConfidence(combined)
	combined.Assumptions = append([]string{}, c.definition.Assumptions...)
	combined.VerificationRecommended = append([]string{}, c.definition.VerificationSteps...)
	combined.NextCapabilities = append([]string{}, c.definition.NextCapabilities...)
	combined.RelatedWorkflows = relatedWorkflows(c.ID())
	combined.PossibleFalsePositives = falsePositiveGuidance(c.ID())
	if len(combined.Errors) > 0 || combined.Status == "partial" {
		combined.Status = "partial"
		if len(combined.Findings) == 0 {
			combined.Confidence = 0
		}
	}
	return combined, nil
}

type reportCapability struct{ definition schema.CapabilityDefinition }

func (c reportCapability) ID() string                              { return c.definition.ID }
func (c reportCapability) Definition() schema.CapabilityDefinition { return c.definition }
func (c reportCapability) Run(ctx context.Context, req schema.RunRequest, d Dependencies) (schema.Result, error) {
	if d.LoadResult == nil {
		return emptyResult(), fmt.Errorf("run history is unavailable")
	}
	source, err := d.LoadResult(ctx, strings.TrimSpace(req.Target))
	if err != nil {
		return emptyResult(), fmt.Errorf("load source run: %w", err)
	}
	result := emptyResult()
	manifest, err := json.MarshalIndent(schema.Report{ID: source.RunID + ":normalized", RunID: source.RunID, Format: "json", Result: source}, "", "  ")
	if err != nil {
		return result, err
	}
	ev, err := d.Evidence.Put(req.RunID, "normalized-report", "application/json", manifest)
	if err != nil {
		return result, err
	}
	ev.Metadata = map[string]string{"source_run_id": source.RunID, "schema": "cybot://schemas/report"}
	result.Evidence = append(result.Evidence, ev)
	result.Summary = "Generated a normalized report artifact for run " + source.RunID + "."
	result.Confidence = 1
	result.Decisions = []schema.Decision{{Stage: "reporting", Selected: "stored-normalized-result", Reason: "Reports are generated from schema-validated run history, never raw tool output.", Skipped: []schema.SkippedOption{}}}
	result.Assumptions = []string{"The selected stored run is the intended reporting source."}
	result.VerificationRecommended = []string{"Verify the report SHA-256 and source run ID."}
	return result, nil
}

func executionTarget(target string, docker bool) (string, string, string, []execution.Mount, error) {
	info, err := os.Stat(target)
	if err != nil {
		if os.IsNotExist(err) {
			return target, "", "", nil, nil
		}
		return "", "", "", nil, fmt.Errorf("inspect target: %w", err)
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", "", "", nil, err
	}
	if !docker {
		hostWorkdir := ""
		if info.IsDir() {
			hostWorkdir = abs
		}
		return abs, hostWorkdir, "", nil, nil
	}
	containerTarget := "/input"
	containerWorkdir := ""
	if info.IsDir() {
		containerWorkdir = containerTarget
	}
	return containerTarget, "", containerWorkdir, []execution.Mount{{Source: abs, Target: containerTarget, ReadOnly: true}}, nil
}

func validateCapabilityTarget(id, target string) error {
	if target == "" {
		return fmt.Errorf("target is required")
	}
	switch id {
	case "dns.analyse", "dns.enum":
		return validateHostname(target)
	case "service.enumerate", "port.scan":
		if net.ParseIP(target) != nil {
			return nil
		}
		return validateHostname(target)
	case "web.map", "web.scan", "web.content.discover", "api.audit", "tech.fingerprint", "waf.detect", "dir.bruteforce", "vuln.scan", "sql.inject", "xss.detect", "cors.audit", "cms.detect":
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
			return fmt.Errorf("target must be an http or https URL without embedded credentials")
		}
		return nil
	case "tls.audit":
		if net.ParseIP(target) != nil {
			return nil
		}
		return validateHostname(target)
	case "code.audit", "secret.scan", "dependency.scan", "cloud.review", "js.analyse", "js.extract":
		if _, err := os.Stat(target); err != nil {
			return fmt.Errorf("target must be an existing local path: %w", err)
		}
		return nil
	case "container.scan":
		if info, err := os.Stat(target); err == nil {
			if info.IsDir() {
				return fmt.Errorf("local container target must be an OCI or Docker archive file")
			}
			return nil
		}
		if strings.ContainsAny(target, "\r\n\t ") {
			return fmt.Errorf("container target must be one image reference without whitespace")
		}
		return nil
	default:
		return nil
	}
}

func evidenceOutput(tool string, data []byte) ([]byte, string, error) {
	if tool != "gitleaks" && tool != "trufflehog" && tool != "trivy" {
		if json.Valid(data) {
			return data, "application/json", nil
		}
		if _, err := decodeDocuments(data); err == nil {
			return data, "application/x-ndjson", nil
		}
		return data, "text/plain", nil
	}
	var value any
	if json.Unmarshal(data, &value) == nil {
		redactValue(value)
		out, err := json.Marshal(value)
		return out, "application/json", err
	}
	docs, err := decodeDocuments(data)
	if err != nil {
		return nil, "", err
	}
	for _, doc := range docs {
		redactValue(doc)
	}
	lines := make([][]byte, 0, len(docs))
	for _, doc := range docs {
		b, e := json.Marshal(doc)
		if e != nil {
			return nil, "", e
		}
		lines = append(lines, b)
	}
	return []byte(strings.Join(byteStrings(lines), "\n")), "application/x-ndjson", nil
}
func redactValue(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			lower := strings.ToLower(k)
			if lower == "raw" || lower == "rawv2" || lower == "secret" || lower == "match" || lower == "extra_data" {
				x[k] = "[REDACTED]"
				continue
			}
			redactValue(child)
		}
	case []any:
		for _, child := range x {
			redactValue(child)
		}
	}
}
func byteStrings(xs [][]byte) []string {
	out := make([]string, len(xs))
	for i := range xs {
		out[i] = string(xs[i])
	}
	return out
}

func mergeResult(dst *schema.Result, src schema.Result) {
	dst.Warnings = append(dst.Warnings, src.Warnings...)
	dst.Observations = append(dst.Observations, src.Observations...)
	if src.Status == "partial" {
		dst.Status = "partial"
	}
	dst.Assets = append(dst.Assets, src.Assets...)
	dst.Services = append(dst.Services, src.Services...)
	dst.Endpoints = append(dst.Endpoints, src.Endpoints...)
	dst.Findings = append(dst.Findings, src.Findings...)
	dst.Evidence = append(dst.Evidence, src.Evidence...)
	dst.Errors = append(dst.Errors, src.Errors...)
	dst.Decisions = append(dst.Decisions, src.Decisions...)
	deduplicateResult(dst)
}
func deduplicateResult(r *schema.Result) {
	r.Assets = unique(r.Assets, func(v schema.Asset) string { return v.Type + "\x00" + v.Value })
	r.Services = unique(r.Services, func(v schema.Service) string { return fmt.Sprintf("%s\x00%d\x00%s", v.Host, v.Port, v.Protocol) })
	r.Endpoints = unique(r.Endpoints, func(v schema.Endpoint) string { return v.Method + "\x00" + v.URL })
	r.Findings = unique(r.Findings, func(v schema.Finding) string { return v.ID })
	sort.Slice(r.Assets, func(i, j int) bool { return r.Assets[i].Type+r.Assets[i].Value < r.Assets[j].Type+r.Assets[j].Value })
	sort.Slice(r.Services, func(i, j int) bool {
		if r.Services[i].Host == r.Services[j].Host {
			return r.Services[i].Port < r.Services[j].Port
		}
		return r.Services[i].Host < r.Services[j].Host
	})
	sort.Slice(r.Endpoints, func(i, j int) bool { return r.Endpoints[i].URL < r.Endpoints[j].URL })
	sortFindings(r)
}
func unique[T any](in []T, key func(T) string) []T {
	seen := map[string]bool{}
	out := []T{}
	for _, v := range in {
		k := key(v)
		if !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}
func summaryFor(id string, r schema.Result, tools int) string {
	return fmt.Sprintf("%s completed with %d tool(s): %d asset(s), %d service(s), %d endpoint(s), and %d finding(s).", id, tools, len(r.Assets), len(r.Services), len(r.Endpoints), len(r.Findings))
}
func resultConfidence(r schema.Result) float64 {
	if len(r.Findings) > 0 {
		total := 0.0
		for _, f := range r.Findings {
			total += f.Confidence
		}
		return total / float64(len(r.Findings))
	}
	return .85
}
func relatedWorkflows(id string) []string {
	switch id {
	case "asset.discover", "dns.analyse", "dns.enum", "service.enumerate", "port.scan", "web.map", "web.scan", "web.content.discover", "api.audit", "js.analyse", "js.extract", "tech.fingerprint", "waf.detect", "dir.bruteforce", "vuln.scan", "xss.detect", "cors.audit", "cms.detect", "pattern.detect":
		return []string{"web-assessment", "bug-bounty-recon", "vulnerability-assessment"}
	default:
		return []string{}
	}
}
func falsePositiveGuidance(id string) []string {
	switch id {
	case "secret.scan":
		return []string{"Test values and revoked credentials may match secret patterns."}
	case "web.scan", "api.audit", "vuln.scan":
		return []string{"Template matches require authorized manual confirmation."}
	case "dependency.scan", "container.scan":
		return []string{"Package reachability and vendor backports may change exploitability."}
	case "code.audit", "js.analyse", "js.extract":
		return []string{"Static-analysis matches may be unreachable or sanitized by surrounding code."}
	case "sql.inject":
		return []string{"SQLMap findings require manual verification; false positives are common with WAFs."}
	case "xss.detect":
		return []string{"XSS detection tools may report low-risk reflected XSS as exploitable."}
	case "dns.enum", "cloud.enum":
		return []string{"Enumerated resources may be shared or not under target control."}
	case "tls.audit":
		return []string{"TLS findings may vary with server configuration and intermediary proxies."}
	case "cors.audit":
		return []string{"CORS misconfigurations may be intentional for public APIs."}
	default:
		return []string{"Dynamic infrastructure and shared services may change observed ownership or exposure."}
	}
}

func nmapArgs(target string, _ schema.RunRequest) []string {
	return []string{"-sV", "-sC", "-oX", "-", "-T4", "--top-ports", "1000", target}
}
func whatwebArgs(target string, _ schema.RunRequest) []string {
	return []string{"--log-json", "/dev/stdout", "--no-errors", "-q", target}
}
func wafw00fArgs(target string, _ schema.RunRequest) []string {
	return []string{"-a", "-o", "-", target}
}
func gobusterArgs(target string, _ schema.RunRequest) []string {
	base := strings.TrimRight(target, "/")
	return []string{"dir", "-u", base, "-w", "/usr/share/wordlists/dirb/common.txt", "--no-error", "-q"}
}
func testsslArgs(target string, _ schema.RunRequest) []string {
	return []string{"--jsonfile-pretty", "/dev/stdout", "--quiet", target}
}
func niktoArgs(target string, _ schema.RunRequest) []string {
	return []string{"-h", target, "-Format", "json", "-nointeractive"}
}
func sqlmapArgs(target string, _ schema.RunRequest) []string {
	return []string{"-u", target, "--batch", "--random-agent", "--level", "1", "--risk", "1"}
}
func dirsearchArgs(target string, _ schema.RunRequest) []string {
	return []string{"-u", target, "--format", "json", "-q"}
}
func xsstrikeArgs(target string, _ schema.RunRequest) []string {
	return []string{"-u", target, "--crawl", "--blind"}
}
func cloudEnumArgs(target string, _ schema.RunRequest) []string {
	return []string{"-k", target}
}
func linkfinderArgs(target string, _ schema.RunRequest) []string {
	return []string{"-i", target, "-o", "cli"}
}
func jsluiceArgs(target string, _ schema.RunRequest) []string {
	return []string{target}
}
func massdnsArgs(target string, _ schema.RunRequest) []string {
	return []string{"-o", "S", "-q", "-r", "/usr/share/resolvers.txt", target}
}
func corscannerArgs(target string, _ schema.RunRequest) []string {
	return []string{"-u", target}
}
func cmseekArgs(target string, _ schema.RunRequest) []string {
	return []string{"-u", target, "--random-agent", "--batch", "--follow-redirect"}
}

func dnsxArgs(target string, _ schema.RunRequest) []string {
	return []string{"-silent", "-json", "-a", "-aaaa", "-resp", "-disable-update-check", "-rate-limit", "10", "-threads", "2", "-l", target}
}

func subfinderArgs(target string, _ schema.RunRequest) []string {
	return []string{"-d", target, "-silent", "-json", "-disable-update-check", "-rate-limit", "10", "-timeout", "10", "-max-time", "2"}
}

func naabuArgs(target string, _ schema.RunRequest) []string {
	return []string{"-host", target, "-silent", "-json", "-top-ports", "100", "-scan-type", "c", "-rate", "10", "-c", "2", "-Pn", "-no-stdin", "-disable-update-check"}
}
func httpxArgs(target string, _ schema.RunRequest) []string {
	return []string{"-u", target, "-silent", "-json", "-status-code", "-tech-detect", "-no-fallback", "-threads", "5", "-rate-limit", "10", "-disable-update-check"}
}
func katanaArgs(target string, _ schema.RunRequest) []string {
	return []string{"-u", target, "-silent", "-jsonl", "-depth", "2", "-disable-update-check", "-concurrency", "2", "-parallelism", "1", "-rate-limit", "10"}
}
func nucleiArgs(target string, _ schema.RunRequest) []string {
	return []string{"-u", target, "-silent", "-jsonl", "-no-interactsh", "-disable-update-check", "-rate-limit", "10", "-concurrency", "2", "-bulk-size", "1", "-templates", "/opt/cybot/share/nuclei-templates"}
}
func nucleiAPIArgs(target string, req schema.RunRequest) []string {
	args := nucleiArgs(target, req)
	return append(args, "-tags", "api")
}
func ffufArgs(target string, _ schema.RunRequest) []string {
	base := strings.TrimRight(target, "/")
	return []string{"-u", base + "/FUZZ", "-w", "/opt/cybot/share/seclists/Discovery/Web-Content/common.txt", "-json", "-noninteractive", "-rate", "10", "-t", "2"}
}
func gitleaksArgs(target string, _ schema.RunRequest) []string {
	return []string{"dir", target, "--report-format", "json", "--report-path", "-", "--redact=100", "--no-banner", "--no-color"}
}
func trufflehogArgs(target string, _ schema.RunRequest) []string {
	return []string{"filesystem", target, "--json", "--no-update", "--no-verification"}
}
func gosecArgs(_ string, _ schema.RunRequest) []string {
	return []string{"-no-fail", "-fmt", "json", "./..."}
}
func semgrepArgs(target string, _ schema.RunRequest) []string {
	return []string{"scan", "--json", "--metrics=off", "--disable-version-check", "--config", "/opt/cybot/rules/semgrep-security.yaml", target}
}
func trivyFilesystemArgs(target string, _ schema.RunRequest) []string {
	return []string{"filesystem", "--cache-dir", "/home/cybot/.cache/trivy", "--format", "json", "--scanners", "vuln,misconfig,secret", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-version-check", "--offline-scan", "--disable-telemetry", target}
}
func trivyImageArgs(target string, req schema.RunRequest) []string {
	args := []string{"image", "--cache-dir", "/home/cybot/.cache/trivy", "--format", "json", "--scanners", "vuln,misconfig,secret", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-version-check", "--offline-scan", "--disable-telemetry"}
	if info, err := os.Stat(req.Target); err == nil && !info.IsDir() {
		return append(args, "--input", target)
	}
	return append(args, target)
}
func trivyConfigArgs(target string, _ schema.RunRequest) []string {
	return []string{"config", "--cache-dir", "/home/cybot/.cache/trivy", "--format", "json", "--skip-check-update", "--skip-version-check", "--disable-telemetry", target}
}
func syftArgs(target string, _ schema.RunRequest) []string {
	return []string{"scan", target, "-o", "cyclonedx-json"}
}
func grypeArgs(target string, req schema.RunRequest) []string {
	if _, err := os.Stat(req.Target); err == nil {
		if req.Capability == "dependency.scan" {
			target = "dir:" + target
		}
	} else if req.Capability == "container.scan" {
		target = "registry:" + target
	}
	return []string{target, "-o", "json", "--quiet"}
}
