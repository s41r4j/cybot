package capability

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/pkg/schema"
)

func webReportURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || len(raw) > 32768 || strings.ContainsAny(raw, "\x00\r\n\t ") {
		return "", fmt.Errorf("report does not contain a bounded HTTP(S) URL")
	}
	return evidence.SanitizeURL(raw), nil
}

// FFUF's JSONL results omit the HTTP method. The locked adapter uses its
// default GET request and does not accept an operator method override.
func parseFFUF(data []byte, req schema.RunRequest) (schema.Result, error) {
	r, err := parseEndpoints(data, req)
	if err != nil {
		return r, err
	}
	for i := range r.Endpoints {
		if r.Endpoints[i].Method == "" {
			r.Endpoints[i].Method = "GET"
		}
	}
	return r, nil
}

func parseWhatWeb(data []byte, _ schema.RunRequest) (schema.Result, error) {
	var docs []map[string]any
	if err := json.Unmarshal(data, &docs); err != nil || len(docs) == 0 {
		return emptyResult(), fmt.Errorf("whatweb: missing response report; zero targets cannot establish a clean fingerprint")
	}
	r := emptyResult()
	for _, doc := range docs {
		target, err := webReportURL(text(doc["target"]))
		status, validStatus := doc["http_status"].(float64)
		plugins, validPlugins := doc["plugins"].(map[string]any)
		if err != nil || !validStatus || status != float64(int(status)) || status < 100 || status > 599 || !validPlugins {
			return emptyResult(), fmt.Errorf("whatweb: malformed response URL, HTTP status or plugin map")
		}
		techs := []string{}
		for name, raw := range plugins {
			plugin, ok := raw.(map[string]any)
			if !ok || name == "" || len(name) > 256 || strings.ContainsAny(name, "\r\n\x00") {
				return emptyResult(), fmt.Errorf("whatweb: malformed plugin identity")
			}
			if name == "IP" || name == "Country" || name == "Title" {
				continue
			}
			versions := texts(plugin["version"])
			if len(versions) == 0 {
				techs = append(techs, evidence.RedactText(name))
			}
			for _, version := range versions {
				techs = append(techs, evidence.RedactText(name+"/"+version))
			}
		}
		techs = unique(techs, func(s string) string { return s })
		sort.Strings(techs)
		r.Endpoints = append(r.Endpoints, schema.Endpoint{URL: target, Method: "GET", Status: int(status), Technology: techs})
	}
	r.Summary = fmt.Sprintf("Retained technology signature candidates from %d HTTP response(s); no vulnerabilities were tested.", len(r.Endpoints))
	r.Confidence = .75
	return r, nil
}

func parseWafw00f(data []byte, _ schema.RunRequest) (schema.Result, error) {
	var docs []map[string]any
	if err := json.Unmarshal(data, &docs); err != nil || len(docs) == 0 {
		return emptyResult(), fmt.Errorf("wafw00f: no completed target report; unreachable input cannot establish absence of a WAF")
	}
	r := emptyResult()
	indices := map[string]int{}
	for _, doc := range docs {
		target, err := webReportURL(text(doc["url"]))
		detected, ok := doc["detected"].(bool)
		firewall, manufacturer := text(doc["firewall"]), text(doc["manufacturer"])
		if err != nil || !ok || firewall == "" || manufacturer == "" || (detected && firewall == "None") || (!detected && firewall != "None") {
			return emptyResult(), fmt.Errorf("wafw00f: malformed target or explicit detection state")
		}
		techs := []string{}
		if detected {
			techs = append(techs, evidence.RedactText("WAF:"+firewall+" ("+manufacturer+")"))
		}
		if index, exists := indices[target]; exists {
			r.Endpoints[index].Technology = unique(append(r.Endpoints[index].Technology, techs...), func(s string) string { return s })
		} else {
			indices[target] = len(r.Endpoints)
			r.Endpoints = append(r.Endpoints, schema.Endpoint{URL: target, Method: "GET", Technology: techs})
		}
	}
	r.Summary = "Retained WAF signature candidates; a signature does not establish a bypass or vulnerability."
	r.Confidence = .75
	return r, nil
}

var gobusterRecord = regexp.MustCompile(`^(\S+)\s+\(Status: ([1-5][0-9]{2})\)(?: \[Size: [0-9]+\])?(?: \[--> [^\r\n]*\])?$`)

func parseGobuster(data []byte, _ schema.RunRequest) (schema.Result, error) {
	r := emptyResult()
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 65536)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		count++
		if count > 16384 {
			return emptyResult(), fmt.Errorf("gobuster: result count exceeds the bounded report limit")
		}
		match := gobusterRecord.FindStringSubmatch(line)
		if match == nil {
			return emptyResult(), fmt.Errorf("gobuster: unexpected output instead of expanded URL/status records")
		}
		target, err := webReportURL(match[1])
		if err != nil {
			return emptyResult(), err
		}
		status, _ := strconv.Atoi(match[2])
		r.Endpoints = append(r.Endpoints, schema.Endpoint{URL: target, Method: "GET", Status: status, Technology: []string{}})
	}
	if err := scanner.Err(); err != nil {
		return emptyResult(), fmt.Errorf("gobuster: result record exceeds its limit: %w", err)
	}
	r.Summary = fmt.Sprintf("Observed %d HTTP content-discovery response(s); no vulnerabilities were tested.", len(r.Endpoints))
	r.Confidence = .8
	return r, nil
}
