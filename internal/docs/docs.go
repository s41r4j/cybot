package docs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/s41r4j/cybot/pkg/schema"
	"gopkg.in/yaml.v3"
)

type CapabilityPage struct {
	Capability schema.CapabilityDefinition `json:"capability" yaml:"capability"`
	Tools      []schema.Tool               `json:"tools" yaml:"tools"`
}

func Write(w io.Writer, format string, v any) error {
	switch format {
	case "json":
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(v)
	case "yaml":
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		var normalized any
		if err = json.Unmarshal(b, &normalized); err != nil {
			return err
		}
		e := yaml.NewEncoder(w)
		e.SetIndent(2)
		return errors.Join(e.Encode(normalized), e.Close())
	case "markdown":
		var buffer bytes.Buffer
		if err := markdown(&buffer, v); err != nil {
			return err
		}
		_, err := io.Copy(w, &buffer)
		return err
	default:
		return fmt.Errorf("unsupported format %q; use markdown, json, or yaml", format)
	}
}
func DocumentationMarkdown(d schema.Documentation) string {
	var b strings.Builder
	section(&b, "Description", d.Description)
	section(&b, "Purpose", d.Purpose)
	b.WriteString("\n## Arguments\n\n")
	if len(d.Arguments) == 0 {
		b.WriteString("None.\n")
	} else {
		for _, a := range d.Arguments {
			req := "optional"
			if a.Required {
				req = "required"
			}
			fmt.Fprintf(&b, "- `%s` (%s, %s): %s\n", a.Name, a.Type, req, a.Description)
		}
	}
	b.WriteString("\n## Examples\n\n")
	for _, e := range d.Examples {
		fmt.Fprintf(&b, "%s\n\n", e.Description)
		if e.Command != "" {
			fmt.Fprintf(&b, "```sh\n%s\n```\n\n", e.Command)
		}
		if len(e.Output) > 0 {
			fmt.Fprintf(&b, "```json\n%s\n```\n\n", e.Output)
		}
	}
	section(&b, "Expected Output", d.ExpectedOutput)
	section(&b, "Output Schema", "`"+d.OutputSchema+"`")
	list(&b, "Limitations", d.Limitations)
	list(&b, "Required Permissions", d.RequiredPermissions)
	list(&b, "Related Commands", d.RelatedCommands)
	list(&b, "Common Mistakes", d.CommonMistakes)
	list(&b, "Best Practices", d.BestPractices)
	return b.String()
}
func markdown(w io.Writer, v any) error {
	switch x := v.(type) {
	case schema.Documentation:
		_, e := io.WriteString(w, DocumentationMarkdown(x))
		return e
	case schema.CapabilityDefinition:
		fmt.Fprintf(w, "# %s (`%s`)\n", x.Title, x.ID)
		io.WriteString(w, DocumentationMarkdown(x.Documentation))
		listWriter(w, "Workflow", workflow(x.Workflow))
		listWriter(w, "Tools Used and Selection Logic", toolChoices(x.ToolChoices))
		listWriter(w, "Assumptions", x.Assumptions)
		listWriter(w, "Verification Steps", x.VerificationSteps)
		listWriter(w, "Related Capabilities", x.RelatedCapabilities)
		listWriter(w, "Recommended Next Capabilities", x.NextCapabilities)
		fmt.Fprintf(w, "\n## Input Schema\n\n```json\n%s\n```\n\n## Output Schema\n\n```json\n%s\n```\n", x.InputSchema, x.OutputSchema)
		return nil
	case CapabilityPage:
		if err := markdown(w, x.Capability); err != nil {
			return err
		}
		fmt.Fprint(w, "\n## Tool Documentation\n\n")
		if len(x.Tools) == 0 {
			fmt.Fprintln(w, "No executable tool is selected by this capability.")
			return nil
		}
		for _, tool := range x.Tools {
			fmt.Fprintf(w, "\n### %s (`%s`)\n%s\n", tool.Title, tool.ID, DocumentationMarkdown(tool.Documentation))
		}
		return nil
	case schema.Report:
		fmt.Fprintf(w, "# CYBOT Report `%s`\n\n- Run: `%s`\n- Capability: `%s`\n- Target: `%s`\n- Status: **%s**\n- Confidence: %.2f\n\n## Summary\n\n%s\n\n## Findings\n", x.ID, x.RunID, x.Result.Capability, x.Result.Target, x.Result.Status, x.Result.Confidence, x.Result.Summary)
		if len(x.Result.Findings) == 0 {
			fmt.Fprintln(w, "\nNo findings were produced.")
		} else {
			for _, f := range x.Result.Findings {
				fmt.Fprintf(w, "\n- **%s** (%s): %s", f.Title, f.Severity, f.Description)
			}
		}
		listWriter(w, "Warnings", x.Result.Warnings)
		listWriter(w, "Unverified Observations", x.Result.Observations)
		listWriter(w, "Recommended Next Capabilities", x.Result.NextCapabilities)
		listWriter(w, "Verification Recommended", x.Result.VerificationRecommended)
		return nil
	default:
		b, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			return e
		}
		_, e = fmt.Fprintf(w, "```json\n%s\n```\n", b)
		return e
	}
}
func section(b *strings.Builder, title, body string) { fmt.Fprintf(b, "\n## %s\n\n%s\n", title, body) }
func list(b *strings.Builder, title string, items []string) {
	b.WriteString("\n## " + title + "\n\n")
	if len(items) == 0 {
		b.WriteString("None.\n")
		return
	}
	for _, v := range items {
		b.WriteString("- " + v + "\n")
	}
}
func listWriter(w io.Writer, title string, items []string) {
	fmt.Fprintf(w, "\n## %s\n\n", title)
	if len(items) == 0 {
		fmt.Fprintln(w, "None.")
		return
	}
	for _, v := range items {
		fmt.Fprintln(w, "- "+v)
	}
}
func workflow(nodes []schema.DecisionNode) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		next := n.OnSuccess
		if n.Terminal {
			next = "terminal"
		}
		out = append(out, fmt.Sprintf("`%s`: %s — condition: %s; next: %s", n.ID, n.Action, n.Condition, next))
	}
	return out
}
func toolChoices(xs []schema.ToolChoice) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, fmt.Sprintf("`%s`: %s Selected when: %s Skipped when: %s", x.ToolID, x.Reason, x.SelectedWhen, x.SkipWhen))
	}
	return out
}
