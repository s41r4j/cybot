package capability

import (
	"context"
	"time"

	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/internal/registry"
)

// Readiness is an availability and implementation audit, never a scan certificate.
type Readiness struct {
	SchemaVersion int                   `json:"schema_version" yaml:"schema_version"`
	Scope         string                `json:"scope" yaml:"scope"`
	Tools         []ToolReadiness       `json:"tools" yaml:"tools"`
	Capabilities  []CapabilityReadiness `json:"capabilities" yaml:"capabilities"`
	Counts        map[string]int        `json:"counts" yaml:"counts"`
	ReleaseReady  bool                  `json:"release_ready" yaml:"release_ready"`
}
type ToolReadiness struct {
	ID              string `json:"id" yaml:"id"`
	DeclaredVersion string `json:"declared_version" yaml:"declared_version"`
	Availability    string `json:"availability" yaml:"availability"`
	Reason          string `json:"reason,omitempty" yaml:"reason,omitempty"`
}
type AdapterReadiness struct {
	Tool           string `json:"tool" yaml:"tool"`
	Required       bool   `json:"required" yaml:"required"`
	Availability   string `json:"availability" yaml:"availability"`
	Implementation string `json:"implementation" yaml:"implementation"`
	Normalization  string `json:"normalization" yaml:"normalization"`
	Reason         string `json:"reason,omitempty" yaml:"reason,omitempty"`
	ResourceScope  string `json:"resource_scope" yaml:"resource_scope"`
}
type CapabilityReadiness struct {
	ID         string             `json:"id" yaml:"id"`
	Status     string             `json:"status" yaml:"status"`
	Adapters   []AdapterReadiness `json:"adapters" yaml:"adapters"`
	Validation string             `json:"validation" yaml:"validation"`
}

// These invocations do not perform the capability their names promise.
// Keep their metadata discoverable, but do not count help/status as execution.
var incompleteAdapters = map[string]string{
	"amass":        "the pinned v5 release requires its engine/database workflow; the legacy adapter is incompatible and has not been implemented for v5",
	"metasploit":   "adapter only displays help; exploit execution is not implemented",
	"covenant":     "adapter only displays help; C2 execution is not implemented",
	"kekeo":        "adapter only exits; ticket operations are not implemented",
	"powersploit":  "adapter only lists modules; post-exploitation execution is not implemented",
	"gf":           "adapter only lists patterns; target matching is not implemented",
	"gophish":      "starting a server does not create or scope a campaign; a campaign/configuration contract is required",
	"dnschef":      "the current listener ignores the requested target; an explicit scoped DNS configuration is required",
	"chisel":       "starting a reverse server does not implement a scoped forwarding/tunnel request",
	"sharppersist": "adapter checks persistence; installation and rollback are not implemented",
	"mythic":       "adapter reports status; task execution is not implemented",
}

func normalization(tool string) string {
	switch tool {
	case "system-dns-resolver":
		return "built-in"
	case "subfinder", "amass", "dnsx", "nmap", "naabu", "httpx", "katana", "ffuf", "nuclei",
		"gitleaks", "trufflehog", "gosec", "semgrep", "trivy", "syft", "grype", "whatweb",
		"testssl", "sqlmap", "jsluice", "corscanner", "wpscan", "agent-browser", "zap":
		return "tool-specific"
	default:
		return "observations-only"
	}
}

func InspectReadiness(ctx context.Context, caps *Registry, tools *registry.ToolRegistry, runner execution.Runner) Readiness {
	result := Readiness{SchemaVersion: 1, Scope: "Binary availability and adapter implementation only; versions, credentials, target access and scan accuracy are not certified.", Tools: []ToolReadiness{}, Capabilities: []CapabilityReadiness{}, Counts: map[string]int{}}
	available := map[string]ToolReadiness{}
	for _, tool := range tools.List() {
		row := ToolReadiness{ID: tool.ID, DeclaredVersion: tool.Version, Availability: "available"}
		if tool.ID != "system-dns-resolver" {
			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			err := runner.Health(probeCtx, tool)
			cancel()
			if err != nil {
				row.Availability = "unavailable"
				row.Reason = err.Error()
			}
		}
		available[tool.ID] = row
		result.Tools = append(result.Tools, row)
		result.Counts["tools_"+row.Availability]++
	}
	for _, c := range caps.List() {
		row := CapabilityReadiness{ID: c.ID(), Status: "ready-to-test", Adapters: []AdapterReadiness{}, Validation: "not-certified"}
		steps := []toolStep{}
		if external, ok := c.(externalCapability); ok {
			steps = external.steps
		} else {
			for _, choice := range c.Definition().ToolChoices {
				if choice.SkipWhen != "always" {
					steps = append(steps, toolStep{ID: choice.ToolID, Required: true})
				}
			}
		}
		runnable, missing, requiredMissing, incomplete, observations := 0, 0, false, 0, false
		for _, step := range steps {
			tool, exists := available[step.ID]
			a := AdapterReadiness{Tool: step.ID, Required: step.Required, Availability: tool.Availability, Implementation: "adapter", Normalization: normalization(step.ID), Reason: tool.Reason, ResourceScope: toolScope(step.ID)}
			if !exists {
				a.Availability = "unregistered"
				a.Reason = "tool is not registered"
			}
			if reason := incompleteAdapters[step.ID]; reason != "" {
				a.Implementation = "not-implemented"
				a.Reason = reason
				incomplete++
				if step.Required {
					requiredMissing = true
				}
			} else if a.Availability == "available" {
				runnable++
				observations = observations || a.Normalization == "observations-only"
			} else {
				missing++
				requiredMissing = requiredMissing || step.Required
			}
			row.Adapters = append(row.Adapters, a)
		}
		switch {
		case len(steps) == 0:
			row.Status = "built-in"
		case incomplete == len(steps):
			row.Status = "not-implemented"
		case requiredMissing || runnable == 0:
			row.Status = "unavailable"
		case missing > 0 || incomplete > 0 || observations:
			row.Status = "partial"
		}
		result.Counts["capabilities_"+row.Status]++
		result.Capabilities = append(result.Capabilities, row)
	}
	return result
}
