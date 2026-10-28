package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/s41r4j/cybot/pkg/schema"
)

type ValidateFinding struct{}

type validationInput struct {
	SourceRunID string            `json:"source_run_id"`
	FindingID   string            `json:"finding_id"`
	Checks      map[string]string `json:"checks"`
}

var validationQuestions = []struct{ id, question, failure string }{
	{"actionable", "A reproducible request demonstrates the issue", "CHAIN-REQUIRED"},
	{"accepted_impact", "The program accepts the demonstrated impact", "DOWNGRADE"},
	{"in_scope", "The asset and operation are explicitly in scope", "KILL"},
	{"no_privileged_assumption", "The attack does not rely on excluded privileges", "KILL"},
	{"novel", "The issue is not known or intended behavior", "DOWNGRADE"},
	{"impact_evidenced", "Evidence demonstrates concrete impact", "CHAIN-REQUIRED"},
	{"not_excluded", "The issue is not excluded by program rules", "KILL"},
}

func (ValidateFinding) ID() string { return "validate.finding" }
func (ValidateFinding) Definition() schema.CapabilityDefinition {
	d := capabilityDefinition("validate.finding", "Evidence-backed Finding Review", "validation", nil, []string{"report.generate"})
	d.Documentation.Description = "Review seven explicit operator assertions against a stored finding with hash-verified evidence. Prose alone remains unverified."
	d.Documentation.Purpose = "Make review decisions traceable without claiming keywords prove scope, novelty or exploitability."
	d.Documentation.ExpectedOutput = "CHECKLIST_PASS, KILL, DOWNGRADE, CHAIN-REQUIRED, or UNVERIFIED; operator assertions are identified explicitly."
	d.Documentation.Arguments = append(d.Documentation.Arguments, schema.Argument{Name: "input-file", Type: "path", Required: false, Description: "JSON containing source_run_id, finding_id and all seven checks (pass/fail/unknown)."})
	d.Documentation.Limitations = []string{"Operator assertions are not independent security verification.", "A source finding and readable hash-verified evidence are required for CHECKLIST_PASS."}
	d.Documentation.Examples = []schema.Example{{Description: "Review a stored finding", Command: "cybot run validate.finding --target review --input-file review.json --approve"}}
	d.Assumptions = []string{"The reviewer is authorized and accurately records program rules and test outcomes."}
	d.VerificationSteps = []string{"Independently review exploitability, program scope and supporting evidence before reporting."}
	return d
}

func (ValidateFinding) Run(ctx context.Context, req schema.RunRequest, d Dependencies) (schema.Result, error) {
	result := emptyResult()
	var input validationInput
	decoder := json.NewDecoder(strings.NewReader(string(req.Input)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return result, fmt.Errorf("invalid finding review input: %w", err)
	}
	for key, value := range input.Checks {
		known := false
		for _, q := range validationQuestions {
			known = known || q.id == key
		}
		if !known || (value != "pass" && value != "fail" && value != "unknown") {
			return result, fmt.Errorf("unknown review check or invalid pass/fail/unknown value: %s", key)
		}
	}
	evidenceOK := false
	if input.SourceRunID != "" || input.FindingID != "" {
		if input.SourceRunID == "" || input.FindingID == "" || d.LoadResult == nil || d.Evidence == nil {
			return result, fmt.Errorf("review requires source_run_id, finding_id, history and evidence storage")
		}
		source, err := d.LoadResult(ctx, input.SourceRunID)
		if err != nil {
			return result, fmt.Errorf("load review source: %w", err)
		}
		if source.Status == "failed" {
			return result, fmt.Errorf("cannot validate a finding from a failed source run")
		}
		var selected *schema.Finding
		for i := range source.Findings {
			if source.Findings[i].ID == input.FindingID {
				selected = &source.Findings[i]
				break
			}
		}
		if selected == nil {
			return result, fmt.Errorf("finding is not present in source run")
		}
		if len(selected.EvidenceIDs) > 0 {
			evidenceOK = true
			for _, id := range selected.EvidenceIDs {
				found := false
				for _, ev := range source.Evidence {
					if ev.ID != id {
						continue
					}
					if err := d.Evidence.Verify(ev); err != nil {
						return result, fmt.Errorf("verify finding evidence: %w", err)
					}
					result.Evidence = append(result.Evidence, ev)
					found = true
					break
				}
				if !found {
					return result, fmt.Errorf("finding references missing evidence %s", id)
				}
			}
		}
		result.Observations = append(result.Observations, "Review source: "+input.SourceRunID+" / "+input.FindingID+". Evidence integrity does not prove the finding's truth.")
	}
	verdict := "CHECKLIST_PASS"
	unknown := !evidenceOK
	for _, q := range validationQuestions {
		value := input.Checks[q.id]
		if value == "" {
			value = "unknown"
		}
		reason := "Operator assertion: " + q.question + ". Not independently verified."
		result.Decisions = append(result.Decisions, schema.Decision{Stage: q.id, Selected: value, Reason: reason})
		if value == "unknown" {
			unknown = true
		}
		if value == "fail" {
			if q.failure == "KILL" || verdict != "KILL" && (verdict == "CHECKLIST_PASS" || q.failure == "CHAIN-REQUIRED") {
				verdict = q.failure
			}
		}
	}
	if unknown && verdict == "CHECKLIST_PASS" {
		verdict = "UNVERIFIED"
	}
	result.Status = "partial"
	if verdict == "CHECKLIST_PASS" {
		result.Status = "completed"
	}
	result.Summary = verdict + " — evidence-backed checklist of operator assertions; independent review remains required."
	result.Confidence = 0
	result.Warnings = []string{"Text, operator assertions and evidence hashes cannot independently establish exploitability, scope or novelty."}
	result.VerificationRecommended = []string{"Review the stored finding, program rules and actual evidence before preparing any submission."}
	result.NextCapabilities = []string{"report.generate"}
	return result, nil
}
