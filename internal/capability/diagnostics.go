package capability

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/s41r4j/cybot/pkg/schema"
)

// A successful process exit and a valid report do not establish full scan
// coverage. Preserve diagnostics beside findings rather than discard either.
func applyReportDiagnostics(tool string, data []byte, result *schema.Result) {
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil || root == nil {
		return
	}
	for _, field := range []string{"error", "errors", "Error", "Errors", "Golang errors"} {
		value := bytes.TrimSpace(root[field])
		if len(value) == 0 || bytes.Equal(value, []byte("null")) || bytes.Equal(value, []byte("[]")) || bytes.Equal(value, []byte("{}")) || bytes.Equal(value, []byte(`""`)) {
			continue
		}
		result.Status = "partial"
		result.Errors = append(result.Errors, schema.RunError{Tool: tool, Code: "TOOL_REPORTED_ERRORS", Message: fmt.Sprintf("%s reported %s: %s", tool, field, value)})
		result.Warnings = append(result.Warnings, "Tool-reported errors mean scan coverage is incomplete; zero findings must not be interpreted as a clean assessment.")
	}
	if tool == "semgrep" {
		var paths map[string]json.RawMessage
		if json.Unmarshal(root["paths"], &paths) == nil {
			if scanned, exists := paths["scanned"]; exists {
				var files []string
				if json.Unmarshal(scanned, &files) != nil || len(files) == 0 {
					result.Status = "partial"
					result.Errors = append(result.Errors, schema.RunError{Tool: tool, Code: "NO_FILES_SCANNED", Message: "Semgrep did not report any scanned files."})
				}
			}
		}
	}
	if tool == "gosec" {
		var stats struct {
			Files *int `json:"files"`
		}
		if json.Unmarshal(root["Stats"], &stats) == nil && stats.Files != nil && *stats.Files == 0 {
			result.Status = "partial"
			result.Errors = append(result.Errors, schema.RunError{Tool: tool, Code: "NO_FILES_SCANNED", Message: "Gosec did not report any scanned files."})
		}
	}
	if tool == "trivy" {
		var rows []json.RawMessage
		if json.Unmarshal(root["Results"], &rows) != nil || len(rows) == 0 {
			result.Status = "partial"
			result.Warnings = append(result.Warnings, "Trivy reported no recognized scan targets; vulnerability coverage is unverified.")
		}
	}
}
