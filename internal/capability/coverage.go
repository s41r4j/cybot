package capability

import (
	"sort"

	"github.com/s41r4j/cybot/internal/registry"
)

// Coverage enumerates the entire product, without probing binaries or scanning.
// A release gate must pair it with fresh, artifact-bound live evidence.
type Coverage struct {
	SchemaVersion int                  `json:"schema_version"`
	ReleaseReady  bool                 `json:"release_ready"`
	Tools         []CoverageTool       `json:"tools"`
	Capabilities  []CoverageCapability `json:"capabilities"`
}
type CoverageTool struct {
	ID             string   `json:"id"`
	Version        string   `json:"version"`
	Platforms      []string `json:"platforms"`
	Normalization  string   `json:"normalization"`
	Implementation string   `json:"implementation"`
	ResourceScope  string   `json:"resource_scope"`
	Capabilities   []string `json:"capabilities"`
	Validation     string   `json:"validation"`
	Blockers       []string `json:"blockers"`
}
type CoverageCapability struct {
	ID             string   `json:"id"`
	Implementation string   `json:"implementation"`
	Tools          []string `json:"tools"`
	Validation     string   `json:"validation"`
	Blockers       []string `json:"blockers"`
}

func CatalogCoverage(caps *Registry, tools *registry.ToolRegistry) Coverage {
	report := Coverage{SchemaVersion: 1, Tools: []CoverageTool{}, Capabilities: []CoverageCapability{}}
	owners := map[string][]string{}
	for _, c := range caps.List() {
		row := CoverageCapability{ID: c.ID(), Implementation: "built-in", Tools: []string{}, Validation: "not-certified", Blockers: []string{"fresh platform-specific end-to-end evidence is required"}}
		if external, ok := c.(externalCapability); ok {
			row.Implementation = external.Definition().Implementation
			for _, step := range external.steps {
				row.Tools = append(row.Tools, step.ID)
				if reason := incompleteAdapters[step.ID]; reason != "" {
					row.Blockers = append(row.Blockers, step.ID+": "+reason)
				}
				if normalization(step.ID) == "observations-only" {
					row.Blockers = append(row.Blockers, step.ID+": operation-specific normalization is unverified")
				}
			}
		} else {
			for _, choice := range c.Definition().ToolChoices {
				if choice.SkipWhen != "always" {
					row.Tools = append(row.Tools, choice.ToolID)
				}
			}
			if len(row.Tools) > 0 {
				row.Implementation = "adapter"
			}
		}
		row.Tools = unique(row.Tools, func(s string) string { return s })
		sort.Strings(row.Tools)
		for _, id := range row.Tools {
			owners[id] = append(owners[id], row.ID)
		}
		report.Capabilities = append(report.Capabilities, row)
	}
	for _, tool := range tools.List() {
		platforms := append([]string{}, tool.SupportedOS...)
		row := CoverageTool{ID: tool.ID, Version: tool.Version, Platforms: platforms, Normalization: normalization(tool.ID), Implementation: "adapter", ResourceScope: toolScope(tool.ID), Capabilities: append([]string{}, owners[tool.ID]...), Validation: "not-certified", Blockers: []string{"pinned binary/version and fresh real-operation evidence are required"}}
		if len(platforms) == 0 {
			row.Blockers = append(row.Blockers, "supported operating systems have not been explicitly declared")
		}
		if tool.ID == "system-dns-resolver" {
			row.Implementation = "built-in"
		}
		if reason := incompleteAdapters[tool.ID]; reason != "" {
			row.Implementation = "not-implemented"
			row.Blockers = append(row.Blockers, reason)
		}
		if len(row.Capabilities) == 0 {
			row.Blockers = append(row.Blockers, "catalog tool has no executable capability mapping")
		}
		if row.Normalization == "observations-only" {
			row.Blockers = append(row.Blockers, "operation-specific normalization is unverified")
		}
		report.Tools = append(report.Tools, row)
	}
	return report
}
