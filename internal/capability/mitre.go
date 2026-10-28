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

// MITRE ATT&CK mapping looks up techniques in the embedded catalog and returns
// the capabilities that can detect or exercise each technique.

type MitreMap struct{}

func (MitreMap) ID() string { return "mitre.map" }
func (MitreMap) Definition() schema.CapabilityDefinition {
	return schema.CapabilityDefinition{
		ID: "mitre.map", Title: "MITRE ATT&CK Mapping", Version: "1.0.0", Category: "intelligence", Stability: "stable",
		Documentation: schema.Documentation{
			Description: "Look up MITRE ATT&CK techniques by technique ID, tactic, or capability and return detection/action capability mappings.",
			Purpose:     "Translate ATT&CK techniques into deterministic CYBOT capability runs and vice versa.",
			Arguments:   []schema.Argument{{Name: "target", Type: "string", Required: true, Description: "ATT&CK technique ID (e.g. T1190), tactic, or capability ID to map."}},
			Examples: []schema.Example{
				{Description: "Map a technique", Command: "cybot run mitre.map --target T1190 --approve"},
				{Description: "Map by tactic", Command: "cybot run mitre.map --target reconnaissance --approve"},
				{Description: "Reverse map from a capability", Command: "cybot run mitre.map --target sql.inject --approve"},
			},
			ExpectedOutput:      "A cybot.result with findings for each matching technique, including tactic, detection capabilities, and action capabilities.",
			OutputSchema:        "cybot://schemas/result",
			Limitations:         []string{"The catalog is curated, not the full ATT&CK matrix.", "Technique IDs must match the embedded catalog."},
			RequiredPermissions: []string{"None beyond standard policy approval."},
			RelatedCommands:     []string{"cybot capability search mitre", "cybot cve lookup"},
			CommonMistakes:      []string{"Assuming a mapped technique is proven to be present", "Confusing detection capability with confirmed action"},
			BestPractices:       []string{"Use mappings to plan coverage", "Execute detection capabilities to gather evidence before acting"},
		},
		InputSchema:  jsonRaw(`{"type":"object","additionalProperties":false,"required":["target"],"properties":{"target":{"type":"string","minLength":1}}}`),
		OutputSchema: jsonschemas.Must("result"),
		Workflow: []schema.DecisionNode{
			{ID: "normalize", Action: "Normalize the query string", Condition: "target is non-empty", OnSuccess: "search", OnFailure: "fail"},
			{ID: "search", Action: "Match technique ID, tactic, or capability", Condition: "catalog loaded", OnSuccess: "rank", OnFailure: "return-empty"},
			{ID: "rank", Action: "Sort matches by technique ID", Condition: "at least one match", OnSuccess: "return"},
		},
		ToolChoices:         []schema.ToolChoice{},
		Assumptions:         []string{"The catalog matches current ATT&CK technique naming.", "Mapping implies capability coverage, not confirmed attacker activity."},
		VerificationSteps:   []string{"Execute the mapped detection capability against an authorized target.", "Confirm technique relevance from actual evidence."},
		RelatedCapabilities: []string{"cve.lookup", "vuln.scan"},
		NextCapabilities:    []string{"cve.lookup", "vuln.scan"},
	}
}

func (MitreMap) Run(ctx context.Context, req schema.RunRequest, d Dependencies) (schema.Result, error) {
	query := strings.ToLower(strings.TrimSpace(req.Target))
	if query == "" {
		return emptyResult(), fmt.Errorf("target is required")
	}
	techniques, err := catalog.AttackTechniques()
	if err != nil {
		return emptyResult(), fmt.Errorf("load ATT&CK catalog: %w", err)
	}
	result := emptyResult()
	for _, t := range techniques {
		if techniqueMatches(t, query) {
			det := t.DetectionCapabilities
			if len(det) == 0 {
				det = []string{}
			}
			act := t.ActionCapabilities
			if len(act) == 0 {
				act = []string{}
			}
			result.Findings = append(result.Findings, schema.Finding{
				ID:          "mitre:" + strings.ToLower(t.ID),
				Title:       t.ID + ": " + t.Name,
				Description: fmt.Sprintf("Tactic: %s. %s", t.Tactic, t.Description),
				Severity:    schema.SeverityInfo,
				Confidence:  0.9,
				Risk:        "detection: " + strings.Join(det, ",") + "; action: " + strings.Join(act, ","),
			})
		}
	}
	sort.Slice(result.Findings, func(i, j int) bool { return result.Findings[i].ID < result.Findings[j].ID })
	result.Summary = fmt.Sprintf("MITRE mapping for %q matched %d technique(s).", req.Target, len(result.Findings))
	result.Confidence = 0.9
	result.NextCapabilities = []string{"cve.lookup", "vuln.scan"}
	result.VerificationRecommended = []string{"Execute mapped detection capabilities against authorized targets."}
	if len(result.Findings) == 0 {
		result.Summary = fmt.Sprintf("MITRE mapping for %q matched no curated techniques.", req.Target)
	}
	return result, nil
}

func techniqueMatches(t schema.AttackTechnique, query string) bool {
	if strings.EqualFold(t.ID, query) {
		return true
	}
	if strings.Contains(strings.ToLower(t.Name), query) {
		return true
	}
	if strings.Contains(strings.ToLower(t.Tactic), query) {
		return true
	}
	for _, c := range t.DetectionCapabilities {
		if strings.EqualFold(c, query) || strings.Contains(strings.ToLower(c), query) {
			return true
		}
	}
	for _, c := range t.ActionCapabilities {
		if strings.EqualFold(c, query) || strings.Contains(strings.ToLower(c), query) {
			return true
		}
	}
	return false
}
