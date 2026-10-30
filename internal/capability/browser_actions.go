package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/s41r4j/cybot/pkg/schema"
)

type browserAction struct {
	Action       string `json:"action"`
	Selector     string `json:"selector,omitempty"`
	Milliseconds *int   `json:"milliseconds,omitempty"`
}

func (c browserCapability) actionCommands(req schema.RunRequest) ([][]string, error) {
	var input struct {
		Target  string          `json:"target,omitempty"`
		Actions []browserAction `json:"actions,omitempty"`
	}
	data := req.Input
	if len(data) == 0 {
		data = []byte(`{}`)
	}
	if len(data) > 65536 {
		return nil, fmt.Errorf("browser input exceeds 64 KiB")
	}
	if data = bytes.TrimSpace(data); len(data) == 0 || data[0] != '{' {
		return nil, fmt.Errorf("browser input must be one JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("invalid browser input: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("browser input must contain exactly one object")
	}
	if input.Target != "" && input.Target != req.Target {
		return nil, fmt.Errorf("browser input target differs from the authorized request target")
	}
	if c.mode != "automate" && input.Actions != nil {
		return nil, fmt.Errorf("actions are supported only by web.automate")
	}
	if len(input.Actions) > 16 {
		return nil, fmt.Errorf("browser automation supports at most 16 actions")
	}
	commands := [][]string{}
	for _, action := range input.Actions {
		switch action.Action {
		case "click":
			if action.Selector == "" || len(action.Selector) > 1024 || strings.ContainsAny(action.Selector, "\x00\r\n") || strings.HasPrefix(action.Selector, "-") || strings.HasPrefix(action.Selector, "@") || action.Milliseconds != nil {
				return nil, fmt.Errorf("click requires one bounded selector; use a selector from this page rather than a prior session reference")
			}
			commands = append(commands, []string{"click", action.Selector})
		case "wait":
			if action.Selector != "" || action.Milliseconds == nil || *action.Milliseconds < 0 || *action.Milliseconds > 2000 {
				return nil, fmt.Errorf("wait requires milliseconds between 0 and 2000")
			}
			commands = append(commands, []string{"wait", strconv.Itoa(*action.Milliseconds)})
		default:
			return nil, fmt.Errorf("unsupported browser action: use click or wait")
		}
	}
	return commands, nil
}

func (c browserCapability) RequiresInputApproval(req schema.RunRequest) bool {
	actions, err := c.actionCommands(req)
	return err == nil && len(actions) > 0
}

func (c browserCapability) ValidateRequest(req schema.RunRequest) error {
	actions, err := c.actionCommands(req)
	if err != nil {
		return err
	}
	if len(actions) > 0 && !req.Approved {
		return fmt.Errorf("browser actions require explicit --approve even when policy is advisory")
	}
	return nil
}

func (c browserCapability) batchCommands(args []string, req schema.RunRequest) ([][]string, error) {
	if err := c.ValidateRequest(req); err != nil {
		return nil, err
	}
	actions, _ := c.actionCommands(req)
	commands := [][]string{}
	for i, arg := range args[3:] {
		if i == 0 {
			commands = append(commands, []string{"open", req.Target})
		} else {
			commands = append(commands, strings.Fields(arg))
		}
		if i == 1 {
			commands = append(commands, actions...)
		}
	}
	return commands, nil
}

func browserInputSchema(id string) json.RawMessage {
	if id != "web.automate" {
		return json.RawMessage(`{"type":"object","additionalProperties":false,"required":["target"],"properties":{"target":{"type":"string","format":"uri"}}}`)
	}
	return json.RawMessage(`{"type":"object","additionalProperties":false,"required":["target"],"properties":{"target":{"type":"string","format":"uri"},"actions":{"type":"array","maxItems":16,"items":{"oneOf":[{"type":"object","additionalProperties":false,"required":["action","selector"],"properties":{"action":{"const":"click"},"selector":{"type":"string","minLength":1,"maxLength":1024}}},{"type":"object","additionalProperties":false,"required":["action","milliseconds"],"properties":{"action":{"const":"wait"},"milliseconds":{"type":"integer","minimum":0,"maximum":2000}}}]}}}}`)
}
