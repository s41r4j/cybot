package app

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestEveryCommandHasCompleteHelp(t *testing.T) {
	root := NewCommand("test")
	required := []string{"## Description", "## Purpose", "## Arguments", "## Examples", "## Expected Output", "## Output Schema", "## Limitations", "## Required Permissions", "## Related Commands", "## Common Mistakes", "## Best Practices"}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, heading := range required {
			if !strings.Contains(c.Long, heading) {
				t.Errorf("%s help missing %s", c.CommandPath(), heading)
			}
		}
		for _, child := range c.Commands() {
			walk(child)
		}
	}
	walk(root)
}
