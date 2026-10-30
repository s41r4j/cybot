package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/s41r4j/cybot/internal/capability"
	"github.com/s41r4j/cybot/internal/docs"
	"github.com/s41r4j/cybot/internal/integration"
	remotesource "github.com/s41r4j/cybot/internal/source"
	"github.com/s41r4j/cybot/pkg/schema"
	jsonschemas "github.com/s41r4j/cybot/schemas"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func NewCommand(version string) *cobra.Command {
	var configPath, format string
	d := doc("CYBOT capability engine and built-in cybersecurity knowledge base.", "Let AI agents discover and execute deterministic, policy-gated cybersecurity capabilities without selecting raw tools.", []schema.Argument{}, "A documented command tree or normalized cybot.result.", "cybot://schemas/result")
	d.Examples = []schema.Example{{Description: "Discover the knowledge base", Command: "cybot list --format json"}, {Description: "Inspect a capability before execution", Command: "cybot capability help asset.discover"}}
	root := documented(&cobra.Command{Use: "cybot", Short: "Deterministic cybersecurity capability layer", Version: version, SilenceUsage: true, SilenceErrors: true}, d)
	root.PersistentFlags().StringVar(&configPath, "config", "", "configuration file (warning-only policy when omitted)")
	root.PersistentFlags().StringVarP(&format, "format", "f", "json", "output format: json, yaml, or markdown")
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		switch format {
		case "json", "yaml", "markdown":
			return autoUpdatePacks(cmd, configPath)
		}
		return fmt.Errorf("unsupported format %q; use markdown, json, or yaml", format)
	}
	root.AddCommand(listCmd(&format), doctorCmd(&configPath, &format), capabilityCmd(&configPath, &format), skillCmd(&configPath, &format), toolCmd(&configPath, &format), runCmd(&configPath, &format), assetCmd(&configPath, &format), reportCmd(&configPath, &format), integrationCmd(&format), schemaCmd(&format), policyCmd(&configPath, &format), workflowCmd(&configPath, &format), sourceCmd(&configPath, &format), logsCmd(&configPath, &format), historyCmd(&configPath, &format), engagementCmd(&configPath, &format), exportCmd(&configPath, &format), patternCmd(&configPath, &format), platformCmd(&configPath, &format), memoryCmd(&configPath, &format))
	root.AddCommand(packCmd(&configPath, &format))
	ensureDocumented(root)
	return root
}

func doc(description, purpose string, args []schema.Argument, expected, schemaID string) schema.Documentation {
	return schema.Documentation{Description: description, Purpose: purpose, Arguments: args, Examples: []schema.Example{{Description: "Show complete command help", Command: "cybot help"}}, ExpectedOutput: expected, OutputSchema: schemaID, Limitations: []string{"Execution remains constrained by installed plugins and policy."}, RequiredPermissions: []string{"Read access to CYBOT configuration and data directory"}, RelatedCommands: []string{"cybot list", "cybot schema list"}, CommonMistakes: []string{"Invoking raw security tools instead of capabilities", "Treating --approve as a substitute for authorization"}, BestPractices: []string{"Query help in JSON before execution", "Restrict allowed targets and capabilities in policy"}}
}
func documented(c *cobra.Command, d schema.Documentation) *cobra.Command {
	c.Long = docs.DocumentationMarkdown(d)
	examples := []string{}
	for _, e := range d.Examples {
		if e.Command != "" {
			examples = append(examples, e.Command)
		}
	}
	c.Example = strings.Join(examples, "\n")
	return c
}
func ensureDocumented(c *cobra.Command) {
	for _, child := range c.Commands() {
		if child.Long == "" {
			d := doc("Execute or inspect `"+child.CommandPath()+"`.", "Provide a discoverable, deterministic part of the CYBOT command surface.", []schema.Argument{}, "Structured CYBOT metadata or normalized results.", "cybot://schemas/documentation")
			d.Examples = []schema.Example{{Description: "Show command usage", Command: child.CommandPath() + " --help"}}
			documented(child, d)
		}
		ensureDocumented(child)
	}
}
func write(format *string, v any) error { return docs.Write(os.Stdout, *format, v) }
func search(q string, parts ...string) bool {
	q = strings.ToLower(q)
	return strings.Contains(strings.ToLower(strings.Join(parts, " ")), q)
}

func listCmd(format *string) *cobra.Command {
	d := doc("List every discoverable CYBOT object family.", "Provide a deterministic entry point that requires no memorized commands.", nil, "Named registries and their discovery commands.", "cybot://schemas/documentation")
	d.Examples = []schema.Example{{Description: "List the knowledge base", Command: "cybot list --format yaml"}}
	return documented(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return write(format, []map[string]string{{"kind": "pack", "command": "cybot pack list"}, {"kind": "capability", "command": "cybot capability list"}, {"kind": "tool", "command": "cybot tool list"}, {"kind": "skill", "command": "cybot skill list"}, {"kind": "integration", "command": "cybot integration list"}, {"kind": "workflow", "command": "cybot workflow list"}, {"kind": "report", "command": "cybot report list"}, {"kind": "schema", "command": "cybot schema list"}, {"kind": "policy", "command": "cybot policy help"}, {"kind": "source", "command": "cybot source list"}, {"kind": "audit-log", "command": "cybot logs list"}, {"kind": "run-history", "command": "cybot history list"}})
	}}, d)
}
func doctorCmd(path, format *string) *cobra.Command {
	d := doc("Check CYBOT storage and registries.", "Verify the local runtime before capability execution.", nil, "A structured health summary.", "cybot://schemas/documentation")
	d.Examples = []schema.Example{{Description: "Check runtime health", Command: "cybot doctor"}}
	return documented(&cobra.Command{Use: "doctor", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return withRuntime(path, func(r *runtime) error {
			return write(format, map[string]any{"status": "ok", "scope": "storage-and-registries", "tool_availability": "not-checked", "database": "ready", "capabilities": len(r.capabilities.List()), "tools": len(r.tools.List()), "skills": len(r.skills.List()), "schemas": jsonschemas.Names(), "integrations": integration.Supported()})
		})
	}}, d)
}

func capabilityCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "capability", Short: "Discover capability-first security operations"}, doc("Discover and explain CYBOT capabilities.", "Keep agents at the stable capability layer instead of raw tool interfaces.", nil, "Capability definitions.", "cybot://schemas/capability"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return withRuntime(path, func(r *runtime) error {
			out := []schema.CapabilityDefinition{}
			for _, c := range r.capabilities.List() {
				out = append(out, c.Definition())
			}
			return write(format, out)
		})
	}}, &cobra.Command{Use: "search QUERY", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			out := []schema.CapabilityDefinition{}
			for _, c := range r.capabilities.List() {
				d := c.Definition()
				if search(args[0], d.ID, d.Title, d.Category, d.Documentation.Description, d.Documentation.Purpose) {
					out = append(out, d)
				}
			}
			return write(format, out)
		})
	}}, &cobra.Command{Use: "help [ID]", Args: cobra.MaximumNArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			if len(args) == 0 {
				out := []schema.CapabilityDefinition{}
				for _, item := range r.capabilities.List() {
					out = append(out, item.Definition())
				}
				return write(format, out)
			}
			c, ok := r.capabilities.Get(args[0])
			if !ok {
				return fmt.Errorf("unknown capability %q; use 'cybot capability search QUERY'", args[0])
			}
			definition := c.Definition()
			tools := []schema.Tool{}
			for _, choice := range definition.ToolChoices {
				if tool, exists := r.tools.Get(choice.ToolID); exists {
					tools = append(tools, tool)
				}
			}
			return write(format, docs.CapabilityPage{Capability: definition, Tools: tools})
		})
	}})
	p.AddCommand(capabilityPlanCmd(path, format))
	p.AddCommand(&cobra.Command{Use: "coverage", Short: "Enumerate every tool and capability with release-validation gaps", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		return withRuntime(path, func(r *runtime) error { return write(format, capability.CatalogCoverage(r.capabilities, r.tools)) })
	}})
	p.AddCommand(&cobra.Command{Use: "readiness", Short: "Audit tool availability and adapter completeness without scanning", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return withRuntime(path, func(r *runtime) error {
			return write(format, capability.InspectReadiness(cmd.Context(), r.capabilities, r.tools, r.core.Dependencies.Runner))
		})
	}})
	return p
}

func capabilityPlanCmd(path, format *string) *cobra.Command {
	var target, inputFile string
	var approved bool
	c := &cobra.Command{Use: "plan ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		input, err := readCapabilityInput(inputFile)
		if err != nil {
			return err
		}
		return withRuntime(path, func(r *runtime) error {
			plan, err := r.core.Plan(schema.RunRequest{Capability: args[0], Target: target, Input: input, Approved: approved})
			if err != nil {
				return err
			}
			return write(format, plan)
		})
	}}
	c.Flags().StringVar(&inputFile, "input-file", "", "bounded capability input to include in the plan")
	c.Flags().StringVar(&target, "target", "", "target to evaluate against policy")
	c.Flags().BoolVar(&approved, "approve", false, "include approval in policy evaluation")
	return c
}

func toolCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "tool", Short: "Manage internal tool plugins"}, doc("Discover tool metadata used internally by capabilities.", "Explain tool selection without encouraging direct raw-tool execution.", nil, "Tool definitions.", "cybot://schemas/tool"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return withRuntime(path, func(r *runtime) error { return write(format, r.tools.List()) })
	}}, &cobra.Command{Use: "search QUERY", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			out := []schema.Tool{}
			for _, v := range r.tools.List() {
				if search(args[0], v.ID, v.Title, v.Description, v.Purpose) {
					out = append(out, v)
				}
			}
			return write(format, out)
		})
	}}, &cobra.Command{Use: "help ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			v, ok := r.tools.Get(args[0])
			if !ok {
				return fmt.Errorf("unknown tool %q", args[0])
			}
			return write(format, v)
		})
	}}, toolDoctorCmd(path, format), importToolCmd(path, format))
	return p
}
func toolDoctorCmd(path, format *string) *cobra.Command {
	return &cobra.Command{Use: "doctor [ID]", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			tools := r.tools.List()
			if len(args) == 1 {
				v, ok := r.tools.Get(args[0])
				if !ok {
					return fmt.Errorf("unknown tool %q", args[0])
				}
				tools = []schema.Tool{v}
			}
			type health struct {
				ID                  string `json:"id" yaml:"id"`
				Status              string `json:"status" yaml:"status"`
				Reason              string `json:"reason" yaml:"reason"`
				Version             string `json:"version" yaml:"version"`
				VersionPinned       bool   `json:"version_pinned" yaml:"version_pinned"`
				VersionVerification string `json:"version_verification" yaml:"version_verification"`
			}
			out := []health{}
			for _, v := range tools {
				h := health{ID: v.ID, Version: v.Version, VersionPinned: v.Version != "unresolved" && !strings.HasSuffix(v.DockerImage, ":latest") && !strings.HasSuffix(v.DockerImage, ":stable"), VersionVerification: "not-checked"}
				if v.ID == "system-dns-resolver" {
					h.Status = "available"
				} else if err := r.core.Dependencies.Runner.Health(cmd.Context(), v); err != nil {
					h.Status = "unavailable"
					h.Reason = err.Error()
				} else {
					h.Status = "available"
				}
				out = append(out, h)
			}
			return write(format, out)
		})
	}}
}
func importToolCmd(path, format *string) *cobra.Command {
	return &cobra.Command{Use: "import FILE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			var v schema.Tool
			if err := decodeFile(args[0], &v); err != nil {
				return err
			}
			if err := validateTool(v); err != nil {
				return err
			}
			if err := r.tools.Upsert(v); err != nil {
				return err
			}
			if err := r.store.UpsertTool(cmd.Context(), v); err != nil {
				return err
			}
			return write(format, v)
		})
	}}
}

func skillCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "skill", Short: "Manage composable cybersecurity skills"}, doc("Discover normalized multi-capability skills.", "Compose stable capabilities into reusable security procedures.", nil, "Skill definitions.", "cybot://schemas/skill"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return withRuntime(path, func(r *runtime) error { return write(format, r.skills.List()) })
	}}, &cobra.Command{Use: "search QUERY", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			out := []schema.Skill{}
			for _, v := range r.skills.List() {
				if search(args[0], v.ID, v.Title, v.Description, v.Purpose, strings.Join(v.Tags, " ")) {
					out = append(out, v)
				}
			}
			return write(format, out)
		})
	}}, &cobra.Command{Use: "help ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			v, ok := r.skills.Get(args[0])
			if !ok {
				return fmt.Errorf("unknown skill %q", args[0])
			}
			return write(format, v)
		})
	}}, importSkillCmd(path, format), importMarkdownSkillCmd(path, format))
	return p
}
func importSkillCmd(path, format *string) *cobra.Command {
	return &cobra.Command{Use: "import FILE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			var vals []schema.Skill
			if err := decodeFile(args[0], &vals); err != nil {
				var one schema.Skill
				if e := decodeFile(args[0], &one); e != nil {
					return err
				}
				vals = []schema.Skill{one}
			}
			for _, v := range vals {
				if err := validateSkill(v); err != nil {
					return err
				}
				_ = r.skills.Upsert(v)
				if err := r.store.UpsertSkill(cmd.Context(), v); err != nil {
					return err
				}
			}
			return write(format, map[string]any{"imported": len(vals)})
		})
	}}
}
func importMarkdownSkillCmd(path, format *string) *cobra.Command {
	var capabilityID string
	c := &cobra.Command{Use: "import-markdown SOURCE", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			if _, ok := r.capabilities.Get(capabilityID); !ok {
				return fmt.Errorf("unknown mapped capability %q", capabilityID)
			}
			b, err := readInput(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			parts := strings.SplitN(strings.ReplaceAll(string(b), "\r\n", "\n"), "---\n", 3)
			if len(parts) != 3 || strings.TrimSpace(parts[0]) != "" {
				return fmt.Errorf("SKILL.md must start with YAML frontmatter")
			}
			var meta struct {
				Name        string `yaml:"name"`
				Description string `yaml:"description"`
			}
			if err = yaml.Unmarshal([]byte(parts[1]), &meta); err != nil {
				return err
			}
			if meta.Name == "" || meta.Description == "" {
				return fmt.Errorf("SKILL.md frontmatter requires name and description")
			}
			id := slug(meta.Name)
			skill := schema.Skill{ID: id, Title: meta.Name, Description: meta.Description, Purpose: "Normalize imported Agent Skill guidance behind an explicit CYBOT capability mapping.", Tags: []string{"imported", "agent-skill"}, Category: "imported", Steps: []schema.Step{{Capability: capabilityID, Input: json.RawMessage(`{}`)}}, References: []string{args[0]}, Confidence: .6, Version: "imported-v1", Author: "upstream", Content: strings.TrimSpace(parts[2]), Documentation: schema.Documentation{Description: meta.Description, Purpose: "Preserve upstream guidance while execution remains capability-controlled.", Arguments: []schema.Argument{}, Examples: []schema.Example{{Description: "Inspect imported skill", Command: "cybot skill help " + id}}, ExpectedOutput: "A normalized CYBOT skill definition.", OutputSchema: "cybot://schemas/skill", Limitations: []string{"Imported prose is advisory; it cannot bypass policy or directly execute tools."}, RequiredPermissions: []string{"Read access to the source"}, RelatedCommands: []string{"cybot capability help " + capabilityID}, CommonMistakes: []string{"Treating imported prose as executable commands"}, BestPractices: []string{"Review content and capability mapping before use"}}}
			if err = validateSkill(skill); err != nil {
				return err
			}
			_ = r.skills.Upsert(skill)
			if err = r.store.UpsertSkill(cmd.Context(), skill); err != nil {
				return err
			}
			return write(format, skill)
		})
	}}
	c.Flags().StringVar(&capabilityID, "capability", "", "required canonical capability mapping")
	_ = c.MarkFlagRequired("capability")
	return c
}
func slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	dash := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func runCmd(path, format *string) *cobra.Command {
	var target, inputFile string
	var approved bool
	c := &cobra.Command{Use: "run CAPABILITY", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		input, err := readCapabilityInput(inputFile)
		if err != nil {
			return err
		}
		return withRuntime(path, func(r *runtime) error {
			result, err := r.core.Run(cmd.Context(), schema.RunRequest{Capability: args[0], Target: target, Input: input, Approved: approved})
			return writeRunResult(cmd, *format, result, err)
		})
	}}
	c.Flags().StringVar(&target, "target", "", "authorized target")
	c.Flags().StringVar(&inputFile, "input-file", "", "bounded JSON object with capability-specific input")
	c.Flags().BoolVar(&approved, "approve", false, "confirm authorization for this execution")
	return documented(c, doc("Execute one named capability through policy and orchestration.", "Provide one deterministic execution boundary for every integration.", []schema.Argument{{Name: "CAPABILITY", Type: "string", Required: true, Description: "Canonical capability ID."}, {Name: "target", Type: "string", Required: false, Description: "Authorized target."}}, "A normalized cybot.result with decisions and next steps.", "cybot://schemas/result"))
}
func assetCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "asset", Short: "Asset capabilities"}, doc("Execute asset-focused capabilities.", "Provide consistent asset terminology and command style.", nil, "Normalized asset results.", "cybot://schemas/result"))
	var approved bool
	c := &cobra.Command{Use: "discover TARGET", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			result, err := r.core.Run(cmd.Context(), schema.RunRequest{Capability: "asset.discover", Target: args[0], Input: json.RawMessage(`{}`), Approved: approved})
			return writeRunResult(cmd, *format, result, err)
		})
	}}
	c.Flags().BoolVar(&approved, "approve", false, "confirm authorization for this execution")
	p.AddCommand(documented(c, doc("Resolve an authorized hostname into normalized assets.", "Invoke asset.discover without exposing a raw DNS tool.", []schema.Argument{{Name: "TARGET", Type: "hostname", Required: true, Description: "Policy-authorized hostname."}}, "A normalized cybot.result.", "cybot://schemas/result")))
	return p
}

func schemaCmd(format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "schema", Short: "Discover strict JSON Schemas"}, doc("List and retrieve every canonical CYBOT JSON Schema.", "Allow agents to validate data without source code or external documentation.", nil, "JSON Schema documents.", "https://json-schema.org/draft/2020-12/schema"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return write(format, jsonschemas.Names()) }}, &cobra.Command{Use: "show NAME", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		b, err := jsonschemas.Get(args[0])
		if err != nil {
			return err
		}
		var v any
		if err = json.Unmarshal(b, &v); err != nil {
			return err
		}
		return write(format, v)
	}})
	return p
}
func integrationCmd(format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "integration", Short: "Discover agent adapters"}, doc("Discover thin integrations with existing AI coding agents.", "Keep all business logic inside the shared orchestrator.", nil, "Integration definitions.", "cybot://schemas/documentation"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return write(format, integration.Definitions()) }}, &cobra.Command{Use: "help ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		for _, v := range integration.Definitions() {
			if v.Name == args[0] {
				return write(format, v)
			}
		}
		return fmt.Errorf("unknown integration %q", args[0])
	}})
	return p
}
func policyCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "policy", Short: "Explain execution policy"}, doc("Explain active target, approval, concurrency, and capability restrictions.", "Make every execution constraint discoverable before a run.", nil, "Active policy configuration.", "cybot://schemas/documentation"))
	p.AddCommand(&cobra.Command{Use: "help", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return withRuntime(path, func(r *runtime) error {
			return write(format, map[string]any{"description": "All capability execution passes through the CYBOT policy engine.", "active_policy": r.policyConfig, "safe_defaults": []string{"suggestive enforcement mode (warnings only)", "bounded timeout and concurrency", "can be switched to strict mode via config"}})
		})
	}})
	return p
}
func workflowCmd(path, format *string) *cobra.Command {
	defs := []schema.Workflow{
		{ID: "recon-phase", Description: "Phase 1-2: SCOPE + RECON — Discovery and enumeration", Capabilities: []string{"dns.enum", "asset.discover", "service.enumerate", "port.scan", "web.map", "tech.fingerprint", "cms.detect"}, Status: "not-checked", Next: "Proceed to hunt-phase with classified endpoints."},
		{ID: "hunt-phase", Description: "Phase 3: HUNT — Active vulnerability testing", Capabilities: []string{"classify.endpoint", "web.scan", "xss.detect", "sql.inject", "cors.audit", "api.audit", "dir.bruteforce", "tls.audit", "vuln.scan"}, Status: "not-checked", Next: "Proceed to validate-phase for each finding."},
		{ID: "validate-phase", Description: "Phase 4: VALIDATE — Pre-submission quality gate", Capabilities: []string{"validate.finding"}, Status: "not-checked", Next: "PASS findings proceed to report-phase."},
		{ID: "capture-phase", Description: "Phase 5: CAPTURE — Evidence collection and hygiene", Capabilities: []string{"report.generate"}, Status: "not-checked", Next: "Store sanitized evidence before reporting."},
		{ID: "report-phase", Description: "Phase 6: REPORT — Draft and submit", Capabilities: []string{"report.generate"}, Status: "not-checked", Next: "Submit after operator review."},
		{ID: "web-assessment", Description: "Complete web assessment pipeline (all 6 phases)", Capabilities: []string{"asset.discover", "dns.enum", "service.enumerate", "web.map", "classify.endpoint", "web.scan", "validate.finding", "report.generate"}, Status: "not-checked", Next: "Check each component with cybot tool doctor before execution."},
		{ID: "bug-bounty-recon", Description: "Bug bounty reconnaissance pipeline", Capabilities: []string{"dns.enum", "service.enumerate", "web.map", "tech.fingerprint", "waf.detect", "js.extract", "pattern.detect", "classify.endpoint"}, Status: "not-checked", Next: "Follow with targeted vulnerability assessment."},
		{ID: "vulnerability-assessment", Description: "Full vulnerability assessment pipeline", Capabilities: []string{"web.map", "waf.detect", "tls.audit", "vuln.scan", "cors.audit", "validate.finding", "report.generate"}, Status: "not-checked", Next: "Manual verification of critical findings recommended."},
		{ID: "enterprise-external-recon", Description: "Enterprise external attack surface recon", Capabilities: []string{"dns.enum", "asset.discover", "service.enumerate", "port.scan", "cloud.enum", "classify.endpoint"}, Status: "not-checked", Next: "Review platform catalog for target-specific chains."},
	}
	p := documented(&cobra.Command{Use: "workflow", Short: "Discover capability compositions"}, doc("Discover ordered capability compositions.", "Prevent agents from inventing one-off security procedures.", nil, "Workflow definitions.", "cybot://schemas/documentation"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error { return write(format, defs) }}, &cobra.Command{Use: "help ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		for _, v := range defs {
			if v.ID == args[0] {
				return write(format, v)
			}
		}
		return fmt.Errorf("unknown workflow %q", args[0])
	}})
	var target string
	plan := &cobra.Command{Use: "plan ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			var selected *schema.Workflow
			for i := range defs {
				if defs[i].ID == args[0] {
					selected = &defs[i]
					break
				}
			}
			if selected == nil {
				return fmt.Errorf("unknown workflow %q", args[0])
			}
			plans := []schema.ExecutionPlan{}
			for _, id := range selected.Capabilities {
				v, err := r.core.Plan(schema.RunRequest{Capability: id, Target: target, Input: json.RawMessage(`{}`)})
				if err != nil {
					return err
				}
				plans = append(plans, v)
			}
			return write(format, struct {
				Workflow schema.Workflow        `json:"workflow" yaml:"workflow"`
				Plans    []schema.ExecutionPlan `json:"plans" yaml:"plans"`
			}{*selected, plans})
		})
	}}
	plan.Flags().StringVar(&target, "target", "", "target evaluated for every workflow capability")
	p.AddCommand(plan)
	return p
}
func reportCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "report", Short: "Generate normalized run reports"}, doc("Discover and generate reports from stored normalized results.", "Keep reports reproducible and tied to a run ID.", nil, "A report or report format catalog.", "cybot://schemas/report"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return write(format, []map[string]string{{"id": "run-summary", "formats": "json,yaml,markdown", "schema": "cybot://schemas/report"}})
	}}, &cobra.Command{Use: "help ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		if args[0] != "run-summary" {
			return fmt.Errorf("unknown report %q", args[0])
		}
		return write(format, map[string]any{"id": "run-summary", "purpose": "Render one persisted normalized result.", "example": "cybot report generate RUN_ID --format markdown", "schema": "cybot://schemas/report"})
	}}, &cobra.Command{Use: "generate RUN_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			result, err := r.store.Result(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			report := schema.Report{ID: result.RunID + ":run-summary", RunID: result.RunID, Format: *format, GeneratedAt: time.Now().UTC(), Result: result}
			return write(format, report)
		})
	}})
	return p
}

func sourceCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "source", Short: "Discover curated upstream sources"}, doc("Inspect authoritative repositories and import formats used by CYBOT.", "Preserve provenance when external knowledge is normalized.", nil, "Normalized source definitions.", "cybot://schemas/source"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return withRuntime(path, func(r *runtime) error { return write(format, r.sources) })
	}}, &cobra.Command{Use: "search QUERY", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			out := []schema.Source{}
			for _, v := range r.sources {
				if search(args[0], v.ID, v.Title, v.URL, v.Kind, v.Description) {
					out = append(out, v)
				}
			}
			return write(format, out)
		})
	}}, &cobra.Command{Use: "help ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			for _, v := range r.sources {
				if v.ID == args[0] {
					return write(format, v)
				}
			}
			return fmt.Errorf("unknown source %q", args[0])
		})
	}}, &cobra.Command{Use: "refresh-plan", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return withRuntime(path, func(r *runtime) error {
			type item struct {
				ID     string `json:"id" yaml:"id"`
				URL    string `json:"url" yaml:"url"`
				Action string `json:"action" yaml:"action"`
			}
			out := []item{}
			for _, v := range r.sources {
				out = append(out, item{v.ID, v.URL, "fetch metadata, validate format, normalize, diff, require approval before activation"})
			}
			return write(format, out)
		})
	}})
	return p
}

func logsCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "logs", Short: "Query structured audit logs"}, doc("Read append-only JSONL operational events.", "Make policy decisions and run lifecycle events observable without exposing raw tool output or secrets.", nil, "Audit events.", "cybot://schemas/audit-event"))
	var limit int
	c := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return withRuntime(path, func(r *runtime) error {
			events, err := r.logs.Read(limit)
			if err != nil {
				return err
			}
			return write(format, events)
		})
	}}
	c.Flags().IntVar(&limit, "limit", 100, "maximum recent events")
	p.AddCommand(c)
	return p
}

func historyCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "history", Short: "Query normalized run history"}, doc("List and inspect persisted capability results.", "Support reproducibility, reporting, and session memory.", nil, "Normalized cybot.result objects.", "cybot://schemas/result"))
	var limit int
	list := &cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return withRuntime(path, func(r *runtime) error {
			results, err := r.store.Results(cmd.Context(), limit)
			if err != nil {
				return err
			}
			return write(format, results)
		})
	}}
	list.Flags().IntVar(&limit, "limit", 50, "maximum recent runs")
	p.AddCommand(list, &cobra.Command{Use: "show RUN_ID", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			result, err := r.store.Result(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return write(format, result)
		})
	}})
	return p
}

func engagementCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "engagement", Short: "Manage engagement workspaces"}, doc("Scaffold and manage per-target engagement folders.", "Provide structured workspace scaffolding for security assessments.", nil, "Engagement metadata.", "cybot://schemas/documentation"))
	var baseDir string
	scaffold := &cobra.Command{Use: "scaffold TARGET", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		targetName := strings.ToLower(strings.TrimSpace(args[0]))
		if err := validateDirectoryName(targetName); err != nil {
			return err
		}
		base := baseDir
		if base == "" {
			base = filepath.Join(os.Getenv("HOME"), "Targets")
		}
		dir := filepath.Join(base, targetName)
		if err := ensureDirectory(dir); err != nil {
			return fmt.Errorf("create engagement directory: %w", err)
		}
		files := map[string]string{
			"CLAUDE.md":  fmt.Sprintf("# %s\n\nEngagement target: %s\nCreated: %s\n\n## Scope\nSee scope.md\n\n## Active Policy\nSee cybot policy help\n\n## Workflow\n1. SCOPE - review scope.md\n2. RECON - cybot capability plan dns.enum --target %s\n3. HUNT - cybot run classify.endpoint --target ENDPOINT\n4. VALIDATE - cybot run validate.finding --target 'FINDING_TEXT'\n5. CAPTURE - store evidence under evidence/\n6. REPORT - cybot report generate RUN_ID --format markdown\n", targetName, targetName, time.Now().Format("2006-01-02"), targetName),
			"scope.md":   fmt.Sprintf("# Scope: %s\n\n## In-Scope Assets\n\n## Out-of-Scope\n\n## Bounty Bands / Severity Scale\n\n## Special Rules\n", targetName),
			".gitignore": "evidence/*\nreports/*\n*.log\n",
		}
		created := []string{}
		warnings := []string{}
		for _, name := range []string{".gitignore", "CLAUDE.md", "scope.md"} {
			p := filepath.Join(dir, name)
			if err := writeNewFile(p, []byte(files[name])); err != nil {
				if errors.Is(err, os.ErrExist) {
					warnings = append(warnings, "Preserved existing file: "+p)
					continue
				}
				return fmt.Errorf("write %s: %w", name, err)
			}
			created = append(created, p)
		}
		for _, sub := range []string{"findings", "evidence", "reports"} {
			p := filepath.Join(dir, sub)
			if err := ensureDirectory(p); err != nil {
				return err
			}
			created = append(created, p+"/")
		}
		return docs.Write(cmd.OutOrStdout(), *format, schema.Engagement{Name: targetName, BasePath: dir, CreatedAt: time.Now().UTC(), Files: created, Warnings: warnings})
	}}
	scaffold.Flags().StringVar(&baseDir, "base", "", "base directory for engagements (default: ~/Targets)")
	p.AddCommand(scaffold)
	return p
}

func exportCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "export", Short: "Export CYBOT knowledge for agents"}, doc("Export capabilities, skills, and patterns as agent-consumable formats.", "Make CYBOT knowledge available to AI coding agents in their native format.", nil, "Agent-native skill definitions.", "cybot://schemas/documentation"))
	var agent string
	skills := &cobra.Command{Use: "skills", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return withRuntime(path, func(r *runtime) error {
			if agent == "" {
				agent = "all"
			}
			if err := validateDirectoryName(agent); err != nil {
				return fmt.Errorf("invalid agent name: %w", err)
			}
			var out strings.Builder
			out.WriteString(fmt.Sprintf("# CYBOT Exported Skills for %s\n\n", agent))
			out.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339)))
			out.WriteString("## Available Capabilities\n\n")
			for _, c := range r.capabilities.List() {
				d := c.Definition()
				out.WriteString(fmt.Sprintf("### %s\n\n", d.Title))
				out.WriteString(fmt.Sprintf("- **ID:** `%s`\n", d.ID))
				out.WriteString(fmt.Sprintf("- **Category:** %s\n", d.Category))
				out.WriteString(fmt.Sprintf("- **Stability:** %s\n", d.Stability))
				out.WriteString(fmt.Sprintf("- **Description:** %s\n", d.Documentation.Description))
				out.WriteString(fmt.Sprintf("\n**Plan:** `cybot capability plan %s --target TARGET --approve`\n", d.ID))
				out.WriteString(fmt.Sprintf("**Run:** `cybot run %s --target TARGET --approve`\n", d.ID))
				if len(d.NextCapabilities) > 0 {
					out.WriteString(fmt.Sprintf("**Next:** %s\n", strings.Join(d.NextCapabilities, ", ")))
				}
				out.WriteString("\n")
			}
			if len(r.skills.List()) > 0 {
				out.WriteString("## Imported Skills\n\n")
				for _, s := range r.skills.List() {
					out.WriteString(fmt.Sprintf("### %s\n\n", s.Title))
					out.WriteString(fmt.Sprintf("- **ID:** `%s`\n", s.ID))
					out.WriteString(fmt.Sprintf("- **Description:** %s\n", s.Description))
					out.WriteString(fmt.Sprintf("- **Confidence:** %.0f%%\n\n", s.Confidence*100))
				}
			}
			if len(r.patterns) > 0 {
				out.WriteString("## Vulnerability Pattern Library\n\n")
				for _, p := range r.patterns {
					out.WriteString(fmt.Sprintf("### %s\n", p.Title))
					out.WriteString(fmt.Sprintf("- **Capability:** `%s`\n", p.Capability))
					out.WriteString(fmt.Sprintf("- **Detection:** %s\n", strings.Join(p.Detection, "; ")))
					out.WriteString("\n")
				}
			}
			filename, err := filepath.Abs(fmt.Sprintf("cybot-skills-%s-%s.md", agent, time.Now().Format("20060102")))
			if err != nil {
				return err
			}
			if err := writeNewFile(filename, []byte(out.String())); err != nil {
				return fmt.Errorf("export skills: %w", err)
			}
			return docs.Write(cmd.OutOrStdout(), *format, map[string]any{"exported": filename, "capabilities": len(r.capabilities.List()), "skills": len(r.skills.List()), "patterns": len(r.patterns)})
		})
	}}
	skills.Flags().StringVar(&agent, "agent", "", "target agent (opencode, claude-code, codex, all)")
	p.AddCommand(skills)
	return p
}

func patternCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "pattern", Short: "Query vulnerability pattern library"}, doc("Search vulnerability detection patterns, payloads, and bypass techniques.", "Provide structured vulnerability intelligence curated from disclosed reports.", nil, "Pattern definitions.", "cybot://schemas/documentation"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return withRuntime(path, func(r *runtime) error { return write(format, r.patterns) })
	}}, &cobra.Command{Use: "search QUERY", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			var out []schema.VulnerabilityPattern
			for _, p := range r.patterns {
				if search(args[0], p.ID, p.Title, p.Capability, strings.Join(p.Detection, " "), strings.Join(p.Triggers, " ")) {
					out = append(out, p)
				}
			}
			return write(format, out)
		})
	}}, &cobra.Command{Use: "help ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			for _, p := range r.patterns {
				if p.ID == args[0] {
					return write(format, p)
				}
			}
			return fmt.Errorf("unknown pattern %q; use 'cybot pattern search QUERY'", args[0])
		})
	}})
	return p
}

func platformCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "platform", Short: "Query enterprise attack chain intelligence"}, doc("Browse enterprise platform attack chain intelligence with CVE-to-chain mappings.", "Provide structured attack-surface intelligence for enterprise external red-team engagements.", nil, "Platform chain definitions.", "cybot://schemas/documentation"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(*cobra.Command, []string) error {
		return withRuntime(path, func(r *runtime) error { return write(format, r.platforms) })
	}}, &cobra.Command{Use: "search QUERY", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			var out []schema.PlatformChain
			for _, p := range r.platforms {
				if search(args[0], p.ID, p.Title, p.Category, p.Description) {
					out = append(out, p)
				}
			}
			return write(format, out)
		})
	}}, &cobra.Command{Use: "help ID", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			for _, p := range r.platforms {
				if p.ID == args[0] {
					return write(format, p)
				}
			}
			return fmt.Errorf("unknown platform %q; use 'cybot platform search QUERY'", args[0])
		})
	}})
	return p
}

func memoryCmd(path, format *string) *cobra.Command {
	p := documented(&cobra.Command{Use: "memory", Short: "Query cross-engagement recall"}, doc("View and manage per-target engagement memory for pattern recall across repeat targets.", "Enable intelligent skip recommendations on previously explored dead paths.", nil, "Memory entries.", "cybot://schemas/documentation"))
	p.AddCommand(&cobra.Command{Use: "list", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return withRuntime(path, func(r *runtime) error {
			targets, err := r.store.AllEngagementTargets(cmd.Context())
			if err != nil {
				return err
			}
			out := []schema.MemoryEntry{}
			for _, t := range targets {
				entries, err := r.store.EngagementMemory(cmd.Context(), t)
				if err != nil {
					return err
				}
				out = append(out, entries...)
			}
			return write(format, out)
		})
	}}, &cobra.Command{Use: "recall TARGET", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return withRuntime(path, func(r *runtime) error {
			entries, err := r.store.EngagementMemory(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return write(format, entries)
		})
	}})
	return p
}

func decodeFile(path string, v any) error {
	b, err := readInput(context.Background(), path)
	if err != nil {
		return err
	}
	parsedPath := path
	if u, e := url.Parse(path); e == nil && u.Path != "" {
		parsedPath = u.Path
	}
	if strings.EqualFold(filepath.Ext(parsedPath), ".json") {
		return json.Unmarshal(b, v)
	}
	var generic any
	if err := yaml.Unmarshal(b, &generic); err != nil {
		return err
	}
	normalized, err := json.Marshal(generic)
	if err != nil {
		return err
	}
	return json.Unmarshal(normalized, v)
}
func readInput(ctx context.Context, path string) ([]byte, error) {
	if strings.HasPrefix(path, "https://") {
		return remotesource.Fetch(ctx, path)
	}
	return os.ReadFile(path)
}
func validateTool(v schema.Tool) error {
	missing := []string{}
	if v.ID == "" {
		missing = append(missing, "id")
	}
	if v.Title == "" {
		missing = append(missing, "title")
	}
	if v.Description == "" {
		missing = append(missing, "description")
	}
	if v.Purpose == "" {
		missing = append(missing, "purpose")
	}
	if v.Version == "" {
		missing = append(missing, "version")
	}
	if v.SourceURL == "" {
		missing = append(missing, "source_url")
	}
	if v.License == "" {
		missing = append(missing, "license")
	}
	if len(v.Capabilities) == 0 {
		missing = append(missing, "capabilities")
	}
	if v.OutputFormat == "" {
		missing = append(missing, "output_format")
	}
	if v.Parser == "" {
		missing = append(missing, "parser")
	}
	if v.Risk == "" {
		missing = append(missing, "risk")
	}
	if len(v.InputSchema) == 0 {
		missing = append(missing, "input_schema")
	}
	if len(v.OutputSchema) == 0 {
		missing = append(missing, "output_schema")
	}
	if validateDocumentation(v.Documentation) != nil {
		missing = append(missing, "documentation")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("tool does not satisfy cybot://schemas/tool; missing: %s", strings.Join(missing, ", "))
	}
	switch v.Kind {
	case "native", "docker", "http", "mcp":
	default:
		return fmt.Errorf("unsupported tool kind %q", v.Kind)
	}
	return nil
}
func validateSkill(v schema.Skill) error {
	missing := []string{}
	if v.ID == "" {
		missing = append(missing, "id")
	}
	if v.Title == "" {
		missing = append(missing, "title")
	}
	if v.Description == "" {
		missing = append(missing, "description")
	}
	if v.Purpose == "" {
		missing = append(missing, "purpose")
	}
	if v.Version == "" {
		missing = append(missing, "version")
	}
	if len(v.Steps) == 0 {
		missing = append(missing, "steps")
	}
	if validateDocumentation(v.Documentation) != nil {
		missing = append(missing, "documentation")
	}
	if len(missing) > 0 {
		return fmt.Errorf("skill does not satisfy cybot://schemas/skill; missing: %s", strings.Join(missing, ", "))
	}
	return nil
}

func validateDocumentation(d schema.Documentation) error {
	if d.Description == "" || d.Purpose == "" || len(d.Examples) == 0 || d.ExpectedOutput == "" || d.OutputSchema == "" || d.Limitations == nil || d.RequiredPermissions == nil || d.RelatedCommands == nil || d.CommonMistakes == nil || d.BestPractices == nil {
		return fmt.Errorf("documentation requires every canonical section")
	}
	return nil
}

func writeRunResult(cmd *cobra.Command, format string, result schema.Result, runErr error) error {
	var outputErr error
	for _, warning := range result.Warnings {
		_, err := fmt.Fprintln(cmd.ErrOrStderr(), "Warning:", warning)
		outputErr = errors.Join(outputErr, err)
	}
	if result.RunID != "" {
		outputErr = errors.Join(outputErr, docs.Write(cmd.OutOrStdout(), format, result))
	}
	return errors.Join(runErr, outputErr)
}
