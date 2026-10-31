package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/s41r4j/cybot/pkg/schema"
)

func parseDirsearch(data []byte, req schema.RunRequest) (schema.Result, error) {
	r := emptyResult()
	responses := 0
	complete := false
	target, err := url.Parse(strings.TrimSpace(req.Target))
	if err != nil {
		return r, err
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if complete {
			return r, fmt.Errorf("dirsearch: records after completion marker")
		}
		var row struct {
			Record  string `json:"record"`
			Engine  string `json:"engine"`
			Version string `json:"version"`
			Target  string `json:"target"`
			URL     string `json:"url,omitempty"`
			Status  int    `json:"status,omitempty"`
			Matched *bool  `json:"matched,omitempty"`
			Count   *int   `json:"count,omitempty"`
			Error   string `json:"error,omitempty"`
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if len(line) > 64*1024 || decoder.Decode(&row) != nil || decoder.Decode(new(any)) != io.EOF || row.Engine != "Dirsearch" || row.Version != "0.5.0" || row.Target != strings.TrimSpace(req.Target) {
			return r, fmt.Errorf("dirsearch: invalid source-bound progress record")
		}
		switch row.Record {
		case "response":
			actual, e := url.Parse(row.URL)
			safe, e2 := webReportURL(row.URL)
			if e != nil || e2 != nil || actual.Scheme != target.Scheme || !strings.EqualFold(actual.Host, target.Host) || !strings.HasPrefix(actual.Path, strings.TrimRight(target.Path, "/")+"/") || row.Matched == nil || row.Count != nil || row.Error != "" || row.Status < 200 || row.Status >= 500 {
				return r, fmt.Errorf("dirsearch: invalid or differently scoped response")
			}
			accepted := row.Status >= 200 && row.Status < 300 || row.Status == 301 || row.Status == 302 || row.Status == 303 || row.Status == 307 || row.Status == 308 || row.Status == 401 || row.Status == 403 || row.Status == 405
			if *row.Matched != accepted {
				return r, fmt.Errorf("dirsearch: response match differs from the configured status contract")
			}
			responses++
			if responses > 10000 {
				return r, fmt.Errorf("dirsearch: oversized wordlist report")
			}
			if accepted {
				r.Endpoints = append(r.Endpoints, schema.Endpoint{URL: safe, Method: "GET", Status: row.Status, Technology: []string{}})
			}
		case "complete":
			if row.Count == nil || *row.Count != responses || responses < 1 || row.URL != "" || row.Status != 0 || row.Matched != nil || row.Error != "" || len(r.Errors) > 0 {
				return r, fmt.Errorf("dirsearch: invalid complete-wordlist marker")
			}
			complete = true
		case "error":
			if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.]{0,79}$`).MatchString(row.Error) || row.URL != "" || row.Status != 0 || row.Matched != nil || row.Count != nil {
				return r, fmt.Errorf("dirsearch: invalid error record")
			}
			r.Errors = append(r.Errors, schema.RunError{Tool: "dirsearch", Code: "TOOL_REPORTED_ERRORS", Message: "Dirsearch reported " + row.Error + "; coverage is incomplete."})
		default:
			return r, fmt.Errorf("dirsearch: unknown progress record")
		}
	}
	if !complete {
		r.Status = "partial"
		r.Errors = append(r.Errors, schema.RunError{Tool: "dirsearch", Code: "INCOMPLETE_OUTPUT", Message: "No complete-wordlist marker; retained HTTP responses do not establish a clean scan."})
	}
	if responses > 0 {
		r.Observations = append(r.Observations, fmt.Sprintf("Observed %d anonymous GET responses using the Dirsearch library API; no vulnerability is established.", responses))
	}
	deduplicateResult(&r)
	return r, nil
}
