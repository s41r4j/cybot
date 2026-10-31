package capability

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestLiveWebDirsearch(t *testing.T) {
	d := liveWebDeps(t)
	words := filepath.Join(t.TempDir(), "words.txt")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(words, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := liveCapability(t, "dir.bruteforce")
	c.steps = c.steps[2:]
	c.steps[0].Required = true
	c.steps[0].Args = func(target string, req schema.RunRequest) []string {
		return replaceArgument(dirsearchArgs(target, req), "-w", words)
	}
	server := fixtureHTTP(t)
	write("admin\nmissing-fixture\n")
	r, err := c.Run(context.Background(), liveRequest(server.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) != 0 || len(r.Evidence) != 1 || len(r.Endpoints) != 1 || r.Endpoints[0].URL != server.URL+"/admin" {
		t.Fatalf("Dirsearch positive failed: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
	write("missing-fixture\n")
	r, err = c.Run(context.Background(), liveRequest(server.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Endpoints) != 0 || len(r.Evidence) != 1 {
		t.Fatalf("Dirsearch negative failed: %+v %v", r, err)
	}
	server.Close()
	r, err = c.Run(context.Background(), liveRequest(server.URL), d)
	if err == nil || len(r.Errors) == 0 || r.Status != "partial" {
		t.Fatalf("closed target became clean: %+v %v", r, err)
	}
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			fmt.Fprint(w, "match")
			return
		}
		http.Error(w, "fixture error", 500)
	}))
	defer broken.Close()
	write("admin\nfailed\n")
	r, err = c.Run(context.Background(), liveRequest(broken.URL), d)
	if err == nil || r.Status != "partial" || len(r.Errors) == 0 || len(r.Endpoints) != 1 || len(r.Evidence) != 1 || r.Evidence[0].Metadata["coverage"] != "incomplete" {
		t.Fatalf("earlier response lost after request failure: %+v %v", r, err)
	}
	requireToolFailure(t, d, "dirsearch", replaceArgument(dirsearchArgs(broken.URL, schema.RunRequest{}), "-w", words+".absent"))
	certifyOperation(t, "dirsearch", "", []operationCase{
		passedCase("positive", "Real Dirsearch API retains /admin HTTP 200 and excludes 404 without vulnerability claims."),
		passedCase("negative", "A complete all-missing wordlist produces zero matching endpoints."),
		passedCase("failure", "Closed target and missing wordlist fail explicitly; an HTTP failure retains an earlier genuine response as incomplete."),
	})
}

func TestLiveWebDirsearchBoundaries(t *testing.T) {
	d := liveWebDeps(t)
	words := filepath.Join(t.TempDir(), "words.txt")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(words, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := liveCapability(t, "dir.bruteforce")
	c.steps = c.steps[2:]
	c.steps[0].Required = true
	c.steps[0].Args = func(target string, req schema.RunRequest) []string {
		return replaceArgument(dirsearchArgs(target, req), "-w", words)
	}
	var outside atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { outside.Add(1); fmt.Fprint(w, "outside") }))
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
	defer redirect.Close()
	write("admin\n")
	r, err := c.Run(context.Background(), liveRequest(redirect.URL), d)
	if err != nil || len(r.Errors) != 0 || outside.Load() != 0 || len(r.Endpoints) != 1 || r.Endpoints[0].Status != 302 {
		t.Fatalf("Dirsearch followed redirect: %+v %v", r, err)
	}
	write(other.URL + "/outside\n")
	r, err = c.Run(context.Background(), liveRequest(redirect.URL), d)
	if err == nil || len(r.Errors) == 0 || outside.Load() != 0 {
		t.Fatal("wordlist escaped origin", r, err)
	}
	write("../outside\n")
	r, err = c.Run(context.Background(), liveRequest(redirect.URL+"/sub/"), d)
	if err == nil || len(r.Errors) == 0 || outside.Load() != 0 {
		t.Fatal("wordlist escaped requested base path", r, err)
	}
	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, strings.Repeat("x", 2*1024*1024)) }))
	defer large.Close()
	write("admin\n")
	r, err = c.Run(context.Background(), liveRequest(large.URL), d)
	if err == nil || len(r.Errors) == 0 {
		t.Fatal("oversized response accepted", r, err)
	}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "trusted fixture") }))
	defer tls.Close()
	r, err = c.Run(context.Background(), liveRequest(tls.URL), d)
	if err == nil || len(r.Errors) == 0 {
		t.Fatal("untrusted TLS accepted", r, err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tls.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REQUESTS_CA_BUNDLE", ca)
	r, err = c.Run(context.Background(), liveRequest(tls.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Endpoints) != 1 {
		t.Fatal("trusted TLS failed", r, err)
	}
}
