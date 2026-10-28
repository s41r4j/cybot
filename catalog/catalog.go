// Package catalog embeds CYBOT's curated, provenance-bearing source and tool catalog.
package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/s41r4j/cybot/pkg/schema"
	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var files embed.FS

func Patterns() ([]schema.VulnerabilityPattern, error) {
	var c schema.VulnerabilityCatalog
	if err := decode("patterns.yaml", &c); err != nil {
		return nil, err
	}
	for i := range c.Patterns {
		if len(c.Patterns[i].ChainTemplates) == 0 {
			c.Patterns[i].ChainTemplates = []string{}
		}
		if len(c.Patterns[i].Detection) == 0 {
			c.Patterns[i].Detection = []string{}
		}
	}
	sort.Slice(c.Patterns, func(i, j int) bool { return c.Patterns[i].ID < c.Patterns[j].ID })
	return c.Patterns, nil
}

func Platforms() ([]schema.PlatformChain, error) {
	var c schema.PlatformCatalog
	if err := decode("platforms.yaml", &c); err != nil {
		return nil, err
	}
	for i := range c.Platforms {
		if len(c.Platforms[i].Chains) == 0 {
			c.Platforms[i].Chains = []schema.PlatformPhase{}
		}
		if len(c.Platforms[i].ToolMapping) == 0 {
			c.Platforms[i].ToolMapping = []string{}
		}
	}
	sort.Slice(c.Platforms, func(i, j int) bool { return c.Platforms[i].ID < c.Platforms[j].ID })
	return c.Platforms, nil
}

func SeverityMappings() ([]schema.SeverityMapping, error) {
	var raw map[string][]map[string]any
	b, err := files.ReadFile("severity-mapping.yaml")
	if err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	platforms, ok := raw["platforms"]
	if !ok {
		return nil, fmt.Errorf("missing platforms key in severity-mapping.yaml")
	}
	var out []schema.SeverityMapping
	for _, p := range platforms {
		id, _ := p["id"].(string)
		name, _ := p["name"].(string)
		out = append(out, schema.SeverityMapping{ID: id, Name: name, Features: p})
	}
	return out, nil
}

func Sources() ([]schema.Source, error) {
	var out []schema.Source
	if err := decode("sources.yaml", &out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func CVEs() ([]schema.CVE, error) {
	var c schema.CVECatalog
	if err := decode("cves.yaml", &c); err != nil {
		return nil, err
	}
	for i := range c.CVEs {
		if len(c.CVEs[i].Affected) == 0 {
			c.CVEs[i].Affected = []string{}
		}
		if len(c.CVEs[i].Keywords) == 0 {
			c.CVEs[i].Keywords = []string{}
		}
		if len(c.CVEs[i].Capabilities) == 0 {
			c.CVEs[i].Capabilities = []string{}
		}
	}
	sort.Slice(c.CVEs, func(i, j int) bool { return c.CVEs[i].ID < c.CVEs[j].ID })
	return c.CVEs, nil
}
func AttackTechniques() ([]schema.AttackTechnique, error) {
	var c schema.AttackCatalog
	if err := decode("attack.yaml", &c); err != nil {
		return nil, err
	}
	for i := range c.Techniques {
		if len(c.Techniques[i].DetectionCapabilities) == 0 {
			c.Techniques[i].DetectionCapabilities = []string{}
		}
		if len(c.Techniques[i].ActionCapabilities) == 0 {
			c.Techniques[i].ActionCapabilities = []string{}
		}
	}
	sort.Slice(c.Techniques, func(i, j int) bool { return c.Techniques[i].ID < c.Techniques[j].ID })
	return c.Techniques, nil
}
func Tools() ([]schema.Tool, error) {
	var out []schema.Tool
	if err := decode("tools.yaml", &out); err != nil {
		return nil, err
	}
	for i := range out {
		normalizeTool(&out[i])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func Skills() ([]schema.Skill, error) {
	var out []schema.Skill
	if err := decode("skills.yaml", &out); err != nil {
		return nil, err
	}
	for i := range out {
		normalizeSkill(&out[i])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func decode(name string, v any) error {
	b, err := files.ReadFile(name)
	if err != nil {
		return err
	}
	if err = yaml.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decode catalog %s: %w", name, err)
	}
	return nil
}
func normalizeTool(t *schema.Tool) {
	if t.Kind == "native" {
		t.DockerImage = ""
	} else if t.Kind == "" {
		t.Kind = "docker"
		t.DockerImage = "cybotainer:2026.08.9-arm64"
	} else if t.Kind == "docker" && t.DockerImage == "" {
		t.DockerImage = "cybotainer:2026.08.9-arm64"
	}
	if len(t.InputSchema) == 0 {
		t.InputSchema = json.RawMessage(`{"type":"object","additionalProperties":false}`)
	}
	if len(t.OutputSchema) == 0 {
		t.OutputSchema = json.RawMessage(`{"type":"object"}`)
	}
	d := schema.Documentation{Description: t.Description, Purpose: t.Purpose, Arguments: []schema.Argument{}, Examples: []schema.Example{{Description: "Inspect this internal adapter", Command: "cybot tool help " + t.ID}}, ExpectedOutput: "Machine-readable output parsed into cybot://schemas/result by an owning capability.", OutputSchema: "cybot://schemas/result", Limitations: []string{"The adapter is not a public execution API.", "A pinned, healthy installation is required before execution."}, RequiredPermissions: []string{"Permissions declared by the owning capability and active policy."}, RelatedCommands: []string{"cybot capability search " + t.Capabilities[0], "cybot tool doctor " + t.ID}, CommonMistakes: []string{"Running the raw tool instead of its owning capability.", "Using an unpinned container tag in a deterministic run."}, BestPractices: []string{"Lock a reviewed version before execution.", "Prefer structured JSON or JSONL output."}}
	t.Documentation = d
}
func normalizeSkill(s *schema.Skill) {
	if s.Documentation.Description == "" {
		s.Documentation.Description = s.Description
	}
	if s.Documentation.Purpose == "" {
		s.Documentation.Purpose = s.Purpose
	}
}
