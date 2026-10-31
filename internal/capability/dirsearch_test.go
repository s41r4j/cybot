package capability

import (
	"strings"
	"testing"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestDirsearchNeedsResponseEvidenceAndCompletionMarker(t *testing.T) {
	req := schema.RunRequest{Target: "http://fixture.invalid"}
	response := `{"record":"response","engine":"Dirsearch","version":"0.5.0","target":"http://fixture.invalid","url":"http://fixture.invalid/admin","status":200,"matched":true}`
	complete := `{"record":"complete","engine":"Dirsearch","version":"0.5.0","target":"http://fixture.invalid","count":1}`
	r, err := parseTool("dirsearch", []byte(response+"\n"+complete), req)
	if err != nil || len(r.Errors) != 0 || len(r.Endpoints) != 1 || len(r.Findings) != 0 {
		t.Fatal("real response contract failed", r, err)
	}
	r, err = parseTool("dirsearch", []byte(response), req)
	if err != nil || r.Status != "partial" || len(r.Errors) == 0 || len(r.Endpoints) != 1 {
		t.Fatal("missing completion accepted", r, err)
	}
	for _, invalid := range []string{complete, response + "\n" + strings.ReplaceAll(complete, `"count":1`, `"count":2`), strings.ReplaceAll(response, "/admin", "/admin"+`","unexpected":"field`), strings.ReplaceAll(response, `"matched":true`, `"matched":false`), strings.ReplaceAll(response, `"url":"http://fixture.invalid`, `"url":"http://other.invalid`)} {
		if _, err := parseTool("dirsearch", []byte(invalid), req); err == nil {
			t.Fatal("invalid progress accepted", invalid)
		}
	}
	r, retained, ok := recoverFailedOutput("dirsearch", []byte(response+"\n"+`{"record":"truncated`), req)
	if !ok || len(r.Endpoints) != 1 || strings.Contains(string(retained), "truncated") || r.Status != "partial" {
		t.Fatal("valid prefix was lost or malformed tail retained", r, ok)
	}
}
