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

func liveWebDeps(t *testing.T) Dependencies {
	t.Helper()
	if os.Getenv("CYBOT_LIVE_WEB") != "1" {
		t.Skip("requires isolated web toolbox")
	}
	return liveDeps(t)
}

func hasTechnology(r schema.Result, value string) bool {
	for _, ep := range r.Endpoints {
		for _, technology := range ep.Technology {
			if strings.Contains(technology, value) {
				return true
			}
		}
	}
	return false
}

func TestLiveWebFingerprint(t *testing.T) {
	d := liveWebDeps(t)
	positive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.2.0")
		fmt.Fprint(w, "<html><title>Fixture</title></html>")
	}))
	defer positive.Close()
	c := liveCapability(t, "tech.fingerprint")
	r, err := c.Run(context.Background(), liveRequest(positive.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 2 || !hasTechnology(r, "PHP/8.2.0") || len(r.Findings) != 0 {
		t.Fatalf("fingerprint lost actual version: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
	negative := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "plain fixture") }))
	r, err = c.Run(context.Background(), liveRequest(negative.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 2 || hasTechnology(r, "PHP") || len(r.Findings) != 0 {
		t.Fatalf("neutral page invented fingerprint: %+v %v", r, err)
	}
	negative.Close()
	r, err = c.Run(context.Background(), liveRequest(negative.URL), d)
	if err == nil && r.Status != "partial" || len(r.Errors) == 0 {
		t.Fatalf("closed target accepted: %+v %v", r, err)
	}
	certifyOperation(t, "whatweb", "tech.fingerprint", []operationCase{
		passedCase("positive", "Both engines execute and retain PHP/8.2.0 from a local response header without inventing a vulnerability."),
		passedCase("negative", "A neutral local page yields no PHP signature or vulnerability."),
		passedCase("failure", "A closed loopback target produces an explicit incomplete/error result."),
	})
}

func TestLiveWebWAF(t *testing.T) {
	d := liveWebDeps(t)
	c := liveCapability(t, "waf.detect")
	positive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "cloudflare")
		fmt.Fprint(w, "local fixture")
	}))
	defer positive.Close()
	r, err := c.Run(context.Background(), liveRequest(positive.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 1 || !hasTechnology(r, "Cloudflare") || len(r.Findings) != 0 {
		t.Fatalf("WAF positive failed: %+v %v", r, err)
	}
	negative := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "neutral fixture") }))
	r, err = c.Run(context.Background(), liveRequest(negative.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 1 || len(r.Endpoints) != 1 || len(r.Endpoints[0].Technology) != 0 || len(r.Findings) != 0 {
		t.Fatalf("WAF negative failed: %+v %v", r, err)
	}
	negative.Close()
	r, err = c.Run(context.Background(), liveRequest(negative.URL), d)
	if err == nil && r.Status != "partial" || len(r.Errors) == 0 {
		t.Fatalf("unreachable target established no WAF: %+v %v", r, err)
	}
	certifyOperation(t, "wafw00f", "waf.detect", []operationCase{
		passedCase("positive", "Real WAFW00F identifies the loopback Cloudflare header signature as a candidate, without a vulnerability finding."),
		passedCase("negative", "A neutral reachable server yields an explicit negative report and no invented WAF."),
		passedCase("failure", "A closed loopback target cannot be reported as a clean negative."),
	})
}

func TestLiveWebVerifiedTLS(t *testing.T) {
	d := liveWebDeps(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "trusted local fixture") }))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "fixture-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"tech.fingerprint", "waf.detect", "cors.audit"} {
		t.Run(id, func(t *testing.T) {
			c := liveCapability(t, id)
			// HTTPx is independently tested; this control covers the two patched engines.
			c.steps = c.steps[:1]
			r, err := c.Run(context.Background(), liveRequest(server.URL), d)
			if err == nil && r.Status != "partial" || len(r.Errors) == 0 {
				t.Fatalf("untrusted TLS was accepted: %+v %v", r, err)
			}
			t.Setenv("SSL_CERT_FILE", ca)
			t.Setenv("REQUESTS_CA_BUNDLE", ca)
			r, err = c.Run(context.Background(), liveRequest(server.URL), d)
			if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 1 || len(r.Endpoints) != 1 {
				t.Fatalf("explicit trusted CA failed: %+v %v", r, err)
			}
		})
	}
}

func TestLiveWebDoesNotFollowRedirects(t *testing.T) {
	d := liveWebDeps(t)
	var followed atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		fmt.Fprint(w, "outside requested origin")
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	defer redirect.Close()
	for _, id := range []string{"tech.fingerprint", "waf.detect", "cors.audit"} {
		c := liveCapability(t, id)
		c.steps = c.steps[:1]
		r, err := c.Run(context.Background(), liveRequest(redirect.URL), d)
		if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 1 {
			t.Fatalf("redirect response handling failed: %+v %v", r, err)
		}
		if followed.Load() != 0 {
			t.Fatal("fingerprint engine followed a redirect outside requested origin", id)
		}
	}
}

func TestLiveWebDirectoryDiscovery(t *testing.T) {
	d := liveWebDeps(t)
	server := fixtureHTTP(t)
	words := filepath.Join(t.TempDir(), "words.txt")
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(words, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := liveCapability(t, "dir.bruteforce")
	c.steps[0].Args = func(target string, r schema.RunRequest) []string {
		return replaceArgument(gobusterArgs(target, r), "-w", words)
	}
	c.steps[1].Args = func(target string, r schema.RunRequest) []string {
		return replaceArgument(ffufArgs(target, r), "-w", words)
	}
	write("admin\nmissing-fixture\n")
	r, err := c.Run(context.Background(), liveRequest(server.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 2 || len(r.Endpoints) != 1 || r.Endpoints[0].URL != server.URL+"/admin" || r.Endpoints[0].Status != 200 || len(r.Findings) != 0 {
		t.Fatalf("directory discovery failed: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
	write("missing-fixture\n")
	r, err = c.Run(context.Background(), liveRequest(server.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Evidence) != 2 || len(r.Endpoints) != 0 {
		t.Fatalf("missing path invented: %+v %v", r, err)
	}
	requireToolFailure(t, d, "gobuster", replaceArgument(gobusterArgs(server.URL, schema.RunRequest{}), "-w", words+".absent"))
	// Upstream Gobuster may exit zero despite individual request failures.
	// Keep its independently observed matches, but never call the scan complete.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken-fixture" {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		if r.URL.Path == "/admin" || r.URL.Path == "/" {
			fmt.Fprint(w, "fixture")
			return
		}
		http.NotFound(w, r)
	}))
	defer broken.Close()
	write("admin\nbroken-fixture\n")
	partial := c
	partial.steps = partial.steps[:1]
	r, err = partial.Run(context.Background(), liveRequest(broken.URL), d)
	if err != nil || r.Status != "partial" || len(r.Errors) == 0 || len(r.Endpoints) != 1 || r.Endpoints[0].URL != broken.URL+"/admin" {
		t.Fatalf("Gobuster request failures lost partial matches or became clean: %+v %v", r, err)
	}
	certifyOperation(t, "gobuster", "dir.bruteforce", []operationCase{
		passedCase("positive", "Both real directory engines discover /admin HTTP 200 and exclude nonexistent HTTP 404 paths."),
		passedCase("negative", "An all-missing fixture wordlist yields zero endpoints with both engines complete."),
		passedCase("failure", "Real Gobuster rejects a nonexistent wordlist; zero-exit request errors retain genuine matches as incomplete."),
	})
}
