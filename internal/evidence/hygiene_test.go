package evidence

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestCredentialsAreRedactedAcrossFormats(t *testing.T) {
	fixtures := []string{
		`"password=FAKE_SENTINEL"`,
		`{"Authorization":"Bearer FAKE_SENTINEL","x-api-key":"FAKE_SENTINEL","Cookie":"session=FAKE_SENTINEL"}`,
		`[{"name":"Authorization","value":"Bearer FAKE_SENTINEL"},{"name":"X-API-Key","value":"FAKE_SENTINEL"}]`,
		`{"log":{"entries":[{"request":{"url":"https://example.test/?token=FAKE_SENTINEL&ok=1","queryString":[{"name":"access_token","value":"FAKE_SENTINEL"}],"cookies":[{"name":"session","value":"FAKE_SENTINEL"}],"postData":{"text":"FAKE_SENTINEL"}},"response":{"content":{"text":"FAKE_SENTINEL"}}}]}}`,
		`{"Raw":"FAKE_SENTINEL","nested":{"Secret":"FAKE_SENTINEL"},"command":["open https://example.test/?token=FAKE_SENTINEL"]}`,
		`{"content":"FAKE_SENTINEL","nested":{"postData":["FAKE_SENTINEL"]},"Redacted":"FAKE_SENTINEL"}`,
	}
	for _, input := range fixtures {
		out, err := DefaultHygieneRules.SanitizeJSON([]byte(input))
		if err != nil || !json.Valid(out) {
			t.Fatalf("invalid sanitized JSON: %v", err)
		}
		if strings.Contains(string(out), "FAKE_SENTINEL") {
			t.Fatalf("leaked credential: %s", out)
		}
	}
	for _, input := range []string{"password=FAKE_SENTINEL", `SECRET: "FAKE_SENTINEL"`, "Authorization: Bearer FAKE_SENTINEL", "https://user:FAKE_SENTINEL@example.test/", "HTTPS://user:FAKE_SENTINEL@example.test/", "ssh://user:FAKE_SENTINEL@example.test/"} {
		if strings.Contains(DefaultHygieneRules.SanitizeText(input), "FAKE_SENTINEL") {
			t.Fatalf("text leaked: %s", input)
		}
	}
	if _, err := DefaultHygieneRules.SanitizeHeaders([]byte("invalid JSON")); err == nil {
		t.Fatal("malformed headers silently accepted")
	}
}

func TestRedactionPreservesLargeNumericIdentifiers(t *testing.T) {
	b, err := DefaultHygieneRules.SanitizeJSON([]byte(`{"id":9007199254740993,"secret":"fixture"}`))
	if err != nil || !strings.Contains(string(b), "9007199254740993") {
		t.Fatalf("numeric identifier changed: %s %v", b, err)
	}
}

func TestStoredEvidenceHashMatchesRedactedBytes(t *testing.T) {
	store := New(t.TempDir())
	ev, err := store.Put("run", "fixture", "application/json", []byte(`{"secret":"FAKE_SENTINEL","ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(ev.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "FAKE_SENTINEL") {
		t.Fatal("raw secret persisted")
	}
	if ev.SHA256 != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Fatal("hash does not identify stored bytes")
	}
	info, err := os.Stat(ev.Path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows FileMode reports writable/read-only bits, not the NTFS ACL.
	// The redaction/hash assertions above still run on every platform.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("permissions %o", info.Mode().Perm())
	}
	if _, err := store.Put("../escape", "fixture", "text/plain", []byte("test")); err == nil {
		t.Fatal("accepted traversal run ID")
	}
}
