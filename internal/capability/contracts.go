package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Reject valid JSON with the wrong report shape instead of reporting a clean scan.
// Empty JSONL is legitimate for match-only tools; document tools must emit a report.
func validateReportShape(tool string, data []byte) error {
	hasString := func(record map[string]any, key string) bool {
		value, ok := record[key].(string)
		return ok && value != ""
	}
	field := map[string]string{"gosec": "Issues", "semgrep": "results", "grype": "matches", "trivy": "Results"}[tool]
	if field != "" {
		var root map[string]json.RawMessage
		if err := json.Unmarshal(data, &root); err != nil {
			return fmt.Errorf("%s: invalid report: %w", tool, err)
		}
		value, ok := root[field]
		// Trivy omits Results when no targets are recognized.
		if !ok && tool == "trivy" && string(root["SchemaVersion"]) == "2" {
			return nil
		}
		if !ok {
			return fmt.Errorf("%s: missing %s report field", tool, field)
		}
		var rows []json.RawMessage
		if err := json.Unmarshal(value, &rows); err != nil {
			return fmt.Errorf("%s: %s must be an array", tool, field)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && tool != "gosec" && tool != "trivy" {
			return fmt.Errorf("%s: null %s report field", tool, field)
		}
		for _, row := range rows {
			var shape map[string]json.RawMessage
			if json.Unmarshal(row, &shape) != nil || len(shape) == 0 {
				return fmt.Errorf("%s: malformed %s record", tool, field)
			}
			var record map[string]any
			if err := json.Unmarshal(row, &record); err != nil {
				return err
			}
			valid := true
			switch tool {
			case "semgrep":
				valid = hasString(record, "check_id") && hasString(record, "path")
			case "gosec":
				valid = (hasString(record, "rule_id") || hasString(record, "RuleID")) && hasString(record, "file")
			case "grype":
				valid = hasString(object(record["vulnerability"]), "id") && hasString(object(record["artifact"]), "name")
			case "trivy":
				valid = hasString(record, "Target")
				for name, identity := range map[string]string{"Vulnerabilities": "VulnerabilityID", "Misconfigurations": "ID", "Secrets": "RuleID"} {
					if nested, exists := record[name]; exists && nested != nil {
						entries, ok := nested.([]any)
						if !ok {
							valid = false
						}
						for _, entry := range entries {
							valid = valid && hasString(object(entry), identity)
							if name == "Misconfigurations" {
								valid = valid && hasString(object(entry), "Status")
							}
						}
					}
				}
			}
			if !valid {
				return fmt.Errorf("%s: report record lacks required identity/location fields", tool)
			}
		}
		return nil
	}
	switch tool {
	case "gitleaks":
		if len(bytes.TrimSpace(data)) == 0 {
			return fmt.Errorf("gitleaks: missing JSON report")
		}
	case "subfinder", "amass", "amass-enum", "dnsx", "naabu", "httpx", "katana", "ffuf", "nuclei", "trufflehog":
	default:
		return nil
	}
	rows, err := decodeDocuments(data)
	if err != nil {
		return err
	}
	for _, row := range rows {
		valid := false
		switch tool {
		case "subfinder", "amass", "amass-enum", "dnsx":
			valid = firstText(row, "host", "name", "domain", "input") != ""
		case "naabu":
			valid = firstText(row, "host", "ip") != "" && number(row["port"]) > 0 && number(row["port"]) <= 65535
		case "httpx", "katana", "ffuf":
			valid = firstText(row, "url", "endpoint") != "" || firstText(object(row["request"]), "url", "endpoint") != ""
		case "nuclei":
			valid = firstText(row, "template-id", "template_id") != "" && len(object(row["info"])) > 0
		case "gitleaks":
			valid = firstText(row, "RuleID", "rule_id") != ""
		case "trufflehog":
			valid = firstText(row, "DetectorName", "detector_name") != ""
		}
		if !valid {
			return fmt.Errorf("%s: unrecognized output record", tool)
		}
	}
	return nil
}
