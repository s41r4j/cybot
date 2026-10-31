package capability

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/s41r4j/cybot/pkg/schema"
)

// A failed scanner may have emitted real matches before exiting. Retain only
// output accepted by its parser. JSONL recovery stops at the first bad record;
// truncated arrays, objects and arbitrary text are never repaired into reports.
func recoverFailedOutput(tool string, captured []byte, req schema.RunRequest) (schema.Result, []byte, bool) {
	if normalization(tool) != "tool-specific" || len(bytes.TrimSpace(captured)) == 0 {
		return emptyResult(), nil, false
	}
	retained := captured
	result, err := parseTool(tool, retained, req)
	if err != nil {
		switch tool {
		case "subfinder", "dnsx", "naabu", "httpx", "katana", "ffuf", "nuclei", "trufflehog", "jsluice":
		default:
			return emptyResult(), nil, false
		}
		end := 0
		for _, line := range bytes.SplitAfter(captured, []byte("\n")) {
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 {
				if trimmed[0] != '{' || !json.Valid(trimmed) || validateReportShape(tool, trimmed) != nil {
					break
				}
			}
			end += len(line)
		}
		retained = captured[:end]
		result, err = parseTool(tool, retained, req)
	}
	if err != nil || len(result.Findings)+len(result.Assets)+len(result.Services)+len(result.Endpoints)+len(result.Observations) == 0 {
		return emptyResult(), nil, false
	}
	result.Status = "partial"
	return result, retained, true
}

func retainToolOutput(combined *schema.Result, normalized schema.Result, retained, captured []byte, id string, tool schema.Tool, req schema.RunRequest, d Dependencies, failed bool) error {
	data, mediaType, err := evidenceOutput(id, retained)
	if err != nil {
		return fmt.Errorf("redact %s evidence: %w", id, err)
	}
	ev, err := d.Evidence.Put(req.RunID, id+"-structured-output", mediaType, data)
	if err != nil {
		return err
	}
	ev.Metadata = map[string]string{"tool": id, "parser": tool.Parser, "version": tool.Version, "target": req.Target}
	if failed {
		digest := sha256.Sum256(captured)
		ev.Metadata["execution_status"] = "failed"
		ev.Metadata["coverage"] = "incomplete"
		ev.Metadata["captured_bytes"] = strconv.Itoa(len(captured))
		ev.Metadata["retained_bytes"] = strconv.Itoa(len(retained))
		ev.Metadata["captured_sha256"] = hex.EncodeToString(digest[:])
		combined.Decisions = append(combined.Decisions, schema.Decision{Stage: "output-recovery", Selected: id, Reason: "Retained parser-validated records from a failed operation; no completed-stage or negative assurance is established.", Skipped: []schema.SkippedOption{}})
	}
	for i := range normalized.Findings {
		normalized.Findings[i].EvidenceIDs = []string{ev.ID}
	}
	normalized.Evidence = append(normalized.Evidence, ev)
	mergeResult(combined, normalized)
	return nil
}
