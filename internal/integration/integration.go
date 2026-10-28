// Package integration defines thin agent adapters. Business logic stays in the orchestrator.
package integration

import (
	"context"
	"github.com/s41r4j/cybot/pkg/schema"
)

type Runner interface {
	Run(context.Context, schema.RunRequest) (schema.Result, error)
}
type Adapter struct {
	Name string
	Core Runner
}

func (a Adapter) Invoke(ctx context.Context, r schema.RunRequest) (schema.Result, error) {
	return a.Core.Run(ctx, r)
}
func Supported() []string {
	return []string{"codex", "claude-code", "gemini-cli", "opencode", "kilocode", "goose", "amp", "aider", "continue", "generic-mcp"}
}

type Definition struct {
	Name          string               `json:"name" yaml:"name"`
	Description   string               `json:"description" yaml:"description"`
	Purpose       string               `json:"purpose" yaml:"purpose"`
	Transport     string               `json:"transport" yaml:"transport"`
	BusinessLogic bool                 `json:"business_logic" yaml:"business_logic"`
	Documentation schema.Documentation `json:"documentation" yaml:"documentation"`
}

func Definitions() []Definition {
	out := []Definition{}
	for _, name := range Supported() {
		out = append(out, Definition{Name: name, Description: "Thin adapter from " + name + " to the CYBOT orchestrator.", Purpose: "Expose capability discovery and execution without duplicating security logic.", Transport: "cli", BusinessLogic: false, Documentation: schema.Documentation{Description: "Thin adapter from " + name + " to CYBOT.", Purpose: "Allow the agent to discover and invoke capabilities through one deterministic contract.", Arguments: []schema.Argument{}, Examples: []schema.Example{{Description: "Discover available capabilities", Command: "cybot capability list --format json"}}, ExpectedOutput: "Machine-readable capability metadata or normalized cybot.result objects.", OutputSchema: "cybot://schemas/result", Limitations: []string{"Adapter-specific installation is not automated in this foundation."}, RequiredPermissions: []string{"Permission to execute the cybot binary"}, RelatedCommands: []string{"cybot capability list", "cybot integration help " + name}, CommonMistakes: []string{"Calling raw tools instead of CYBOT capabilities"}, BestPractices: []string{"Query capability help before constructing a run request"}}})
	}
	return out
}
