package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/s41r4j/cybot/internal/capability"
	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/memory"
	"github.com/s41r4j/cybot/internal/policy"
	"github.com/s41r4j/cybot/pkg/schema"
	jsonschemas "github.com/s41r4j/cybot/schemas"
)

type Orchestrator struct {
	Capabilities *capability.Registry
	Policy       *policy.Engine
	Dependencies capability.Dependencies
	Memory       *memory.Store
	Audit        interface {
		Write(context.Context, schema.AuditEvent) error
	}
}

func (o *Orchestrator) Plan(req schema.RunRequest) (schema.ExecutionPlan, error) {
	if err := jsonschemas.Validate("run-request", req); err != nil {
		return schema.ExecutionPlan{}, fmt.Errorf("validate request: %w", err)
	}
	c, ok := o.Capabilities.Get(req.Capability)
	if !ok {
		return schema.ExecutionPlan{}, fmt.Errorf("unknown capability %q", req.Capability)
	}
	d := c.Definition()
	decision := o.Policy.Evaluate(req)
	keyInput, _ := json.Marshal(struct {
		Capability, Target string
		Input              json.RawMessage
	}{req.Capability, req.Target, req.Input})
	sum := sha256.Sum256(keyInput)
	executable := decision.Allowed
	if o.Policy.Config().EnforcementMode == "suggestive" {
		executable = true
	}
	p := schema.ExecutionPlan{Capability: req.Capability, Target: req.Target, DeterministicKey: hex.EncodeToString(sum[:]), PolicyDecision: decision.Reason, RequiresApproval: decision.RequiresApproval, Executable: executable, Stages: []schema.PlanStage{}, SelectedTools: []string{}, SkippedTools: []schema.SkippedOption{}, Assumptions: d.Assumptions, ExpectedSchema: "cybot://schemas/result"}
	p.Warnings = append(p.Warnings, decision.Warnings...)
	p.ToolAvailability = "not-checked"
	p.Warnings = append(p.Warnings, "Tool availability and installed versions have not been checked; use cybot tool doctor.")
	if o.Policy.Config().EnforcementMode == "suggestive" {
		p.RequiresApproval = false
	}
	if guard, ok := c.(interface{ ValidateRequest(schema.RunRequest) error }); ok {
		if err := guard.ValidateRequest(req); err != nil {
			p.Executable = false
			p.Warnings = append(p.Warnings, "Invalid capability input: "+err.Error())
		}
	}
	if guard, ok := c.(interface{ RequiresInputApproval(schema.RunRequest) bool }); ok && guard.RequiresInputApproval(req) {
		p.RequiresApproval = true
	}
	if err := capability.ValidateTarget(c, req.Target); err != nil {
		p.Executable = false
		p.Warnings = append(p.Warnings, "Invalid target: "+err.Error())
	}
	if d.Implementation == "not-implemented" {
		p.Executable = false
		p.Warnings = append(p.Warnings, "The advertised operation is not implemented; installing its executable will not make this plan runnable.")
	}
	for _, scope := range d.ResourceScopes {
		if scope != "target" && strings.HasPrefix(req.Target, scope+"://") && !req.Approved {
			p.RequiresApproval = true
			p.Executable = false
			p.Warnings = append(p.Warnings, "Local and interface resources require explicit approval regardless of advisory policy mode.")
		}
	}
	if d.Stability == "experimental" {
		p.SkippedTools = append(p.SkippedTools, schema.SkippedOption{Option: req.Capability, Reason: "capability stability is experimental; execution may produce unverified results"})
	}
	for i, node := range d.Workflow {
		tools := []string{}
		for _, choice := range d.ToolChoices {
			if choice.SkipWhen == "always" || choice.SelectedWhen == "never in version 1.0.0" {
				continue
			}
			if _, exists := o.Dependencies.Tools.Get(choice.ToolID); exists {
				tools = append(tools, choice.ToolID)
			}
		}
		p.Stages = append(p.Stages, schema.PlanStage{Order: i + 1, ID: node.ID, Action: node.Action, Condition: node.Condition, Tools: tools, Parallel: false, Verification: verificationAt(d.VerificationSteps, i)})
	}
	for _, choice := range d.ToolChoices {
		tool, exists := o.Dependencies.Tools.Get(choice.ToolID)
		if !exists || choice.SkipWhen == "always" || choice.SelectedWhen == "never in version 1.0.0" {
			p.SkippedTools = append(p.SkippedTools, schema.SkippedOption{Option: choice.ToolID, Reason: choice.Reason})
			continue
		}
		p.SelectedTools = append(p.SelectedTools, tool.ID)
		if tool.Version == "unresolved" || strings.HasSuffix(tool.DockerImage, ":latest") || strings.HasSuffix(tool.DockerImage, ":stable") {
			p.Warnings = append(p.Warnings, tool.ID+": tool version is not locked; reproducibility is unverified")
		}
	}
	p.Target = evidence.RedactText(p.Target)
	for i := range p.Warnings {
		p.Warnings[i] = evidence.RedactText(p.Warnings[i])
	}
	return p, nil
}
func verificationAt(xs []string, i int) string {
	if len(xs) == 0 {
		return "Validate normalized output against its JSON Schema."
	}
	return xs[i%len(xs)]
}

func (o *Orchestrator) Run(ctx context.Context, req schema.RunRequest) (schema.Result, error) {
	if err := jsonschemas.Validate("run-request", req); err != nil {
		return schema.Result{}, fmt.Errorf("validate request: %w", err)
	}
	c, ok := o.Capabilities.Get(req.Capability)
	if !ok {
		return schema.Result{}, fmt.Errorf("unknown capability %q", req.Capability)
	}
	if err := o.Policy.Authorize(req); err != nil {
		auditErr := o.audit(ctx, schema.AuditEvent{Timestamp: time.Now().UTC(), Level: "warn", Event: "policy.denied", Capability: req.Capability, Target: req.Target, Status: "denied", Message: err.Error()})
		return schema.Result{}, errors.Join(err, auditErr)
	}
	runID := uuid.NewString()
	req.RunID = runID
	started := time.Now().UTC()
	warnings := append([]string{}, o.Policy.Evaluate(req).Warnings...)
	for _, warning := range warnings {
		if e := o.audit(ctx, schema.AuditEvent{Timestamp: started, Level: "warn", Event: "policy.advisory", RunID: runID, Capability: req.Capability, Target: req.Target, Status: "advisory", Message: warning}); e != nil {
			warnings = append(warnings, "Audit write failed: "+e.Error())
		}
	}
	if e := o.audit(ctx, schema.AuditEvent{Timestamp: started, Level: "info", Event: "run.started", RunID: runID, Capability: req.Capability, Target: req.Target, Status: "running", Message: "Capability execution started with " + o.Policy.Config().EnforcementMode + " policy."}); e != nil {
		warnings = append(warnings, "Audit write failed: "+e.Error())
	}
	ctx, cancel := context.WithTimeout(ctx, o.Policy.Config().Timeout)
	defer cancel()
	r, err := c.Run(ctx, req, o.Dependencies)
	r.Warnings = append(warnings, r.Warnings...)
	r.RunID = runID
	r.Capability = req.Capability
	r.Target = req.Target
	r.StartedAt = started
	r.FinishedAt = time.Now().UTC()
	if err != nil {
		r.Status = "failed"
		r.Errors = append(r.Errors, schema.RunError{Code: "CAPABILITY_FAILED", Message: err.Error()})
		if r.Summary == "" {
			r.Summary = "Capability execution failed before producing a complete normalized result."
		}
		if r.Confidence == 0 {
			r.Confidence = 1
		}
	} else if r.Status == "" {
		r.Status = "completed"
	}
	normalizeCollections(&r)
	evidence.RedactResult(&r)
	if schemaErr := jsonschemas.Validate("result", r); schemaErr != nil {
		err = fmt.Errorf("capability output contract failed: %w", schemaErr)
		r = schemaFailureResult(runID, req.Capability, req.Target, started, time.Now().UTC(), err)
		r.Warnings = warnings
	}
	level := "info"
	if r.Status == "failed" {
		level = "error"
	}
	if e := o.audit(context.Background(), schema.AuditEvent{Timestamp: r.FinishedAt, Level: level, Event: "run.finished", RunID: runID, Capability: req.Capability, Target: req.Target, Status: r.Status, Message: r.Summary}); e != nil {
		r.Warnings = append(r.Warnings, "Audit write failed: "+e.Error())
	}
	evidence.RedactResult(&r)
	if saveErr := o.Memory.SaveResult(context.Background(), r); saveErr != nil {
		err = errors.Join(err, fmt.Errorf("save result: %w", saveErr))
		r.Errors = append(r.Errors, schema.RunError{Code: "PERSISTENCE_FAILED", Message: saveErr.Error()})
		r.Warnings = append(r.Warnings, "This run could not be saved to history or engagement memory.")
	}
	evidence.RedactResult(&r)
	return r, evidence.RedactError(err)
}
func schemaFailureResult(runID, capabilityID, target string, started, finished time.Time, cause error) schema.Result {
	r := schema.Result{RunID: runID, Capability: capabilityID, Target: target, Status: "failed", Summary: "Capability output failed strict CYBOT result-schema validation.", Confidence: 1, StartedAt: started, FinishedAt: finished, Errors: []schema.RunError{{Code: "OUTPUT_SCHEMA_FAILED", Message: cause.Error(), Retryable: false}}}
	normalizeCollections(&r)
	return r
}
func (o *Orchestrator) audit(ctx context.Context, e schema.AuditEvent) error {
	evidence.RedactAudit(&e)
	if o.Audit != nil {
		return o.Audit.Write(ctx, e)
	}
	return nil
}

func normalizeCollections(r *schema.Result) {
	if r.Assets == nil {
		r.Assets = []schema.Asset{}
	}
	if r.Services == nil {
		r.Services = []schema.Service{}
	}
	if r.Endpoints == nil {
		r.Endpoints = []schema.Endpoint{}
	}
	for i := range r.Endpoints {
		if r.Endpoints[i].Technology == nil {
			r.Endpoints[i].Technology = []string{}
		}
	}
	if r.Findings == nil {
		r.Findings = []schema.Finding{}
	}
	if r.Evidence == nil {
		r.Evidence = []schema.Evidence{}
	}
	if r.Errors == nil {
		r.Errors = []schema.RunError{}
	}
	if r.Decisions == nil {
		r.Decisions = []schema.Decision{}
	}
	for i := range r.Decisions {
		if r.Decisions[i].Skipped == nil {
			r.Decisions[i].Skipped = []schema.SkippedOption{}
		}
	}
	for i := range r.Findings {
		if r.Findings[i].EvidenceIDs == nil {
			r.Findings[i].EvidenceIDs = []string{}
		}
	}
	if r.Assumptions == nil {
		r.Assumptions = []string{}
	}
	if r.VerificationRecommended == nil {
		r.VerificationRecommended = []string{}
	}
	if r.NextCapabilities == nil {
		r.NextCapabilities = []string{}
	}
	if r.RelatedWorkflows == nil {
		r.RelatedWorkflows = []string{}
	}
	if r.PossibleFalsePositives == nil {
		r.PossibleFalsePositives = []string{}
	}
}
