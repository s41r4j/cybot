package capability

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/pkg/schema"
)

func parseCORS(data []byte, req schema.RunRequest) (schema.Result, error) {
	r := emptyResult()
	var report struct {
		Schema      int    `json:"schema"`
		Engine      string `json:"engine"`
		Version     string `json:"version"`
		Target      string `json:"target"`
		Completed   bool   `json:"completed"`
		Requests    int    `json:"requests"`
		StatusCodes []int  `json:"status_codes"`
		Candidates  []struct {
			URL         string `json:"url"`
			Type        string `json:"type"`
			Credentials string `json:"credentials"`
			Origin      string `json:"origin"`
			Status      int    `json:"status_code"`
		} `json:"candidates"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if len(data) > 64*1024 || decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF {
		return r, fmt.Errorf("corscanner: missing bounded structured operation report")
	}
	if report.Schema != 1 || report.Engine != "CORScanner" || report.Version != "0.9.7" || !report.Completed || report.Target != strings.TrimSpace(req.Target) || report.Requests < 1 || report.Requests > 128 || len(report.StatusCodes) != report.Requests || report.Candidates == nil || len(report.Candidates) > 1 {
		return r, fmt.Errorf("corscanner: incomplete, unsupported or differently scoped report")
	}
	target, err := webReportURL(report.Target)
	if err != nil {
		return r, err
	}
	for _, status := range report.StatusCodes {
		if status < 200 || status >= 400 {
			return r, fmt.Errorf("corscanner: unsuccessful response cannot establish a complete policy assessment")
		}
	}
	endpoint := schema.Endpoint{URL: target, Method: "GET", Status: report.StatusCodes[len(report.StatusCodes)-1], Technology: []string{}}
	for _, candidate := range report.Candidates {
		validType := false
		switch candidate.Type {
		case "reflect_origin", "prefix_match", "suffix_match", "trust_null", "include_match", "not_escape_dot", "custom_third_parties", "special_characters_bypass", "trust_any_subdomain", "https_trust_http":
			validType = true
		}
		origin := candidate.Origin
		if origin != "null" {
			origin, err = webReportURL(origin)
		}
		if !validType || err != nil || candidate.URL != report.Target || candidate.Status != endpoint.Status || candidate.Credentials != "true" && candidate.Credentials != "false" {
			return r, fmt.Errorf("corscanner: invalid policy candidate")
		}
		endpoint.Technology = append(endpoint.Technology, "CORS candidate: "+candidate.Type)
		r.Observations = append(r.Observations, evidence.DefaultHygieneRules.SanitizeText(fmt.Sprintf("CORS policy candidate %s: origin=%s, credentials=%s. Sensitive response access and exploitability require independent review.", candidate.Type, origin, candidate.Credentials)))
	}
	r.Endpoints = append(r.Endpoints, endpoint)
	r.Observations = append(r.Observations, fmt.Sprintf("Completed %d anonymous header probes with verified TLS and no redirect following; no confirmed vulnerability is established.", report.Requests))
	r.Confidence = .8
	return r, nil
}
