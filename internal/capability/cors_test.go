package capability

import (
	"encoding/json"
	"testing"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestCORSRequiresCompleteStructuredHeaderEvidence(t *testing.T) {
	req := schema.RunRequest{Target: "https://fixture.invalid"}
	base := map[string]any{"schema": 1, "engine": "CORScanner", "version": "0.9.7", "target": req.Target, "completed": true, "requests": 1, "status_codes": []int{200}, "candidates": []any{}}
	data, _ := json.Marshal(base)
	r, err := parseCORS(data, req)
	if err != nil || len(r.Findings) != 0 || len(r.Endpoints) != 1 {
		t.Fatal("complete neutral report rejected", r, err)
	}
	base["candidates"] = []any{map[string]any{"url": req.Target, "type": "reflect_origin", "credentials": "true", "origin": "https://evil.invalid", "status_code": 200}}
	data, _ = json.Marshal(base)
	r, err = parseCORS(data, req)
	if err != nil || len(r.Findings) != 0 || !hasTechnology(r, "CORS candidate: reflect_origin") {
		t.Fatal("header match became vulnerability or was lost", r, err)
	}
	for _, invalid := range []string{"Target is not vulnerable", "https://fixture.invalid is vulnerable", "connection failed", `{}`, `{"schema":1}`} {
		if _, err := parseCORS([]byte(invalid), req); err == nil {
			t.Fatal("unstructured/empty report accepted", invalid)
		}
	}
	for key, value := range map[string]any{"completed": false, "requests": 0, "target": "https://other.invalid", "version": "1.0.0", "status_codes": []int{500}, "candidates": nil} {
		copy := map[string]any{}
		for k, v := range base {
			copy[k] = v
		}
		copy[key] = value
		data, _ = json.Marshal(copy)
		if _, err := parseCORS(data, req); err == nil {
			t.Fatal("incomplete report accepted", key)
		}
	}
}
