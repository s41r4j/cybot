package capability

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/s41r4j/cybot/catalog"
	"github.com/s41r4j/cybot/pkg/schema"
	jsonschemas "github.com/s41r4j/cybot/schemas"
)

// CVE lookup searches the embedded curated CVE dictionary deterministically.
// It requires no network or tool adapter and returns normalized findings.

type CVELookup struct{}

func (CVELookup) ID() string { return "cve.lookup" }
func (CVELookup) Definition() schema.CapabilityDefinition {
	return schema.CapabilityDefinition{
		ID: "cve.lookup", Title: "CVE Lookup", Version: "1.0.0", Category: "intelligence", Stability: "stable",
		Documentation: schema.Documentation{
			Description: "Search the embedded curated CVE dictionary by CVE ID, product keyword, or capability.",
			Purpose:     "Provide deterministic, offline CVE context for discovered software versions and scan findings.",
			Arguments:   []schema.Argument{{Name: "target", Type: "string", Required: true, Description: "CVE ID, product keyword, or capability to search for."}},
			Examples: []schema.Example{
				{Description: "Look up a CVE by ID", Command: "cybot run cve.lookup --target CVE-2021-44228 --approve"},
				{Description: "Search by keyword", Command: "cybot run cve.lookup --target exchange --approve"},
			},
			ExpectedOutput:      "A cybot.result with findings for each matching CVE, including severity, CVSS, affected versions, and owning capabilities.",
			OutputSchema:        "cybot://schemas/result",
			Limitations:         []string{"The dictionary is curated and smaller than the full CVE database.", "Keyword matches may over- or under-match product naming."},
			RequiredPermissions: []string{"None beyond standard policy approval."},
			RelatedCommands:     []string{"cybot capability search cve", "cybot exploit search"},
			CommonMistakes:      []string{"Assuming absence of a CVE means the product is secure", "Treating a keyword match as a confirmed vulnerability"},
			BestPractices:       []string{"Pair with scan findings and version inventory", "Verify exploitability against the actual deployed version"},
		},
		InputSchema:  jsonRaw(`{"type":"object","additionalProperties":false,"required":["target"],"properties":{"target":{"type":"string","minLength":1}}}`),
		OutputSchema: jsonschemas.Must("result"),
		Workflow: []schema.DecisionNode{
			{ID: "normalize", Action: "Normalize the query string", Condition: "target is non-empty", OnSuccess: "search", OnFailure: "fail"},
			{ID: "search", Action: "Match CVE ID, keywords, affected products, and capabilities", Condition: "dictionary loaded", OnSuccess: "rank", OnFailure: "return-empty"},
			{ID: "rank", Action: "Rank by relevance and severity", Condition: "at least one match", OnSuccess: "return"},
		},
		ToolChoices:         []schema.ToolChoice{},
		Assumptions:         []string{"The curated dictionary is current enough for the target.", "Matches require manual severity confirmation."},
		VerificationSteps:   []string{"Confirm the exact affected version against vendor advisories.", "Validate exploitability in a controlled environment."},
		RelatedCapabilities: []string{"vuln.scan", "exploit.search", "dependency.scan"},
		NextCapabilities:    []string{"exploit.search", "vuln.scan"},
	}
}

func (CVELookup) Run(ctx context.Context, req schema.RunRequest, d Dependencies) (schema.Result, error) {
	query := strings.ToLower(strings.TrimSpace(req.Target))
	if query == "" {
		return emptyResult(), fmt.Errorf("target is required")
	}
	cves, err := catalog.CVEs()
	if err != nil {
		return emptyResult(), fmt.Errorf("load CVE dictionary: %w", err)
	}
	result := emptyResult()
	for _, cve := range cves {
		id := strings.ToLower(cve.ID)
		exact := query == id
		if exact || cveMatches(cve, query) {
			severity := cve.Severity
			confidence := 0.9
			if !exact {
				confidence = 0.75
			}
			sev := severity
			if sev == "" {
				sev = severityFromCVSS(cve.CVSS)
			}
			affected := ""
			if len(cve.Affected) > 0 {
				affected = " Affected: " + strings.Join(cve.Affected, "; ") + "."
			}
			exploit := ""
			if cve.ExploitKnown {
				exploit = " Public exploit known."
			}
			result.Findings = append(result.Findings, schema.Finding{
				ID:          "cve:" + strings.ToLower(cve.ID),
				Title:       cve.ID + ": " + cve.Title,
				Description: cve.Description + affected + exploit,
				Severity:    sev,
				Confidence:  confidence,
				Risk:        fmt.Sprintf("cvss %.1f", cve.CVSS),
			})
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Severity == result.Findings[j].Severity {
			return result.Findings[i].ID < result.Findings[j].ID
		}
		return severityRank(result.Findings[i].Severity) > severityRank(result.Findings[j].Severity)
	})
	result.Summary = fmt.Sprintf("CVE lookup for %q matched %d record(s).", req.Target, len(result.Findings))
	result.Confidence = 0.85
	result.NextCapabilities = []string{"exploit.search", "vuln.scan"}
	result.VerificationRecommended = []string{"Confirm the deployed version against vendor advisories."}
	if len(result.Findings) == 0 {
		result.Summary = fmt.Sprintf("CVE lookup for %q matched no curated records.", req.Target)
	}
	return result, nil
}

func cveMatches(cve schema.CVE, query string) bool {
	if strings.Contains(strings.ToLower(cve.Title), query) {
		return true
	}
	if strings.Contains(strings.ToLower(cve.Description), query) {
		return true
	}
	if strings.Contains(strings.ToLower(cve.CWE), query) {
		return true
	}
	for _, kw := range cve.Keywords {
		if strings.Contains(query, strings.ToLower(kw)) || strings.Contains(strings.ToLower(kw), query) {
			return true
		}
	}
	for _, cap := range cve.Capabilities {
		if strings.Contains(strings.ToLower(cap), query) {
			return true
		}
	}
	return false
}

func severityFromCVSS(score float64) schema.Severity {
	switch {
	case score >= 9.0:
		return schema.SeverityCritical
	case score >= 7.0:
		return schema.SeverityHigh
	case score >= 4.0:
		return schema.SeverityMedium
	case score > 0:
		return schema.SeverityLow
	default:
		return schema.SeverityInfo
	}
}

func severityRank(s schema.Severity) int {
	switch s {
	case schema.SeverityCritical:
		return 5
	case schema.SeverityHigh:
		return 4
	case schema.SeverityMedium:
		return 3
	case schema.SeverityLow:
		return 2
	default:
		return 1
	}
}
