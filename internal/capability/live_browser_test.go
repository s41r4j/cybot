package capability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLiveBrowserOperations(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_BROWSER") != "1" {
		t.Skip("requires isolated installed browser profile")
	}
	d := liveDeps(t)
	var outsideRequests atomic.Int64
	var clicks atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { outsideRequests.Add(1); fmt.Fprint(w, "outside fixture") }))
	defer outside.Close()
	// A different hostname is deliberately outside the browser's allowed domain.
	outsideURL := strings.Replace(outside.URL, "127.0.0.1", "localhost", 1)
	positive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/clicked-observed" {
			clicks.Add(1)
			return
		}
		if r.URL.Path == "/api/fixture" {
			w.WriteHeader(201)
			fmt.Fprint(w, "fixture response")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><title>CYBOT browser fixture</title><body><button id="fixture-button" data-cybot="fixture click" onclick="document.body.insertAdjacentHTML('beforeend','<a href=&quot;/clicked-fixture&quot;>Clicked link</a>');fetch('/clicked-observed')">Fixture control</button><script>document.body.insertAdjacentHTML('beforeend','<a href="/rendered-fixture">Rendered link</a>');fetch('/api/fixture',{method:'POST'});fetch(%q).catch(()=>{});</script></body></html>`, outsideURL+"/out-of-scope-fixture")
	}))
	defer positive.Close()
	negative := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><title>Neutral page</title><body>Plain fixture</body></html>")
	}))
	defer negative.Close()
	r := NewRegistry()
	if err := RegisterBuiltins(r); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"web.browse", "web.automate", "web.har"} {
		t.Run(id, func(t *testing.T) {
			c, _ := r.Get(id)
			request := liveRequest(positive.URL)
			if id == "web.automate" {
				request.Input = json.RawMessage(`{"actions":[{"action":"click","selector":"button[data-cybot=\"fixture click\"]"},{"action":"wait","milliseconds":100}]}`)
			}
			result, err := c.Run(context.Background(), request, d)
			if err != nil || len(result.Errors) != 0 || len(result.Evidence) != 1 || len(result.Findings) != 0 {
				t.Fatalf("browser positive failed: %+v %v", result, err)
			}
			found := false
			if id == "web.har" {
				for _, ep := range result.Endpoints {
					found = found || ep.URL == positive.URL+"/api/fixture" && ep.Method == "POST" && ep.Status == 201
				}
			} else {
				for _, ep := range result.Endpoints {
					found = found || ep.URL == positive.URL+"/rendered-fixture"
				}
			}
			if !found {
				t.Fatalf("browser lost actual rendered/network endpoint: %+v", result)
			}
			if id == "web.automate" && !strings.Contains(strings.Join(result.Observations, "\n"), "role=button name=Fixture control") {
				t.Fatalf("interactive controls lost: %+v", result)
			}
			if id == "web.automate" {
				clicked := false
				for _, ep := range result.Endpoints {
					clicked = clicked || ep.URL == positive.URL+"/clicked-fixture"
				}
				if !clicked || clicks.Load() != 1 {
					t.Fatalf("approved click was not executed exactly once: %+v, clicks=%d", result, clicks.Load())
				}
			}
			if outsideRequests.Load() != 0 {
				t.Fatal("browser sent requests outside the allowed hostname")
			}
			validateFixtureResult(t, result)
			result, err = c.Run(context.Background(), liveRequest(negative.URL), d)
			if err != nil || len(result.Errors) != 0 || len(result.Findings) != 0 || len(result.Evidence) != 1 {
				t.Fatalf("neutral browser failed: %+v %v", result, err)
			}
			for _, ep := range result.Endpoints {
				if strings.Contains(ep.URL, "rendered-fixture") || strings.Contains(ep.URL, "api/fixture") {
					t.Fatal("neutral page invented an endpoint", ep)
				}
			}
			if id == "web.automate" && len(result.Observations) != 0 {
				t.Fatal("neutral page invented interactive controls", result.Observations)
			}
			closed := httptest.NewServer(http.NotFoundHandler())
			closedURL := closed.URL
			closed.Close()
			result, err = c.Run(context.Background(), liveRequest(closedURL), d)
			if err == nil && result.Status != "partial" {
				t.Fatalf("closed target reported successful: %+v", result)
			}
			certifyCapability(t, "agent-browser", id, []operationCase{
				passedCase("positive", "Installed Chromium executes fixture JavaScript; rendered links, interactive controls or POST/201 network records are retained according to the capability. Requests to a different hostname are blocked."),
				passedCase("negative", "A neutral reachable page produces no invented rendered links, controls or fixture API requests."),
				passedCase("failure", "A closed loopback target produces an incomplete/error result; each owned browser session is explicitly closed."),
			})
		})
	}
	if !t.Failed() {
		certifyOperation(t, "agent-browser", "", []operationCase{
			passedCase("positive", "All three browser adapters execute installed Chromium against generated loopback JavaScript/network/control fixtures."),
			passedCase("negative", "Neutral fixtures produce no invented results; hostname restrictions block outside-domain requests."),
			passedCase("failure", "Closed loopback targets fail explicitly and owned-session cleanup is confirmed by the CLI."),
		})
	}
}

func TestLiveBrowserSessionIsolation(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_BROWSER") != "1" {
		t.Skip("requires isolated installed browser profile")
	}
	d := liveDeps(t)
	var leaked atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/state-leaked" {
			leaked.Add(1)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><script>if(localStorage.getItem('cybot-fixture'))fetch('/state-leaked');localStorage.setItem('cybot-fixture','synthetic-value');</script></body></html>`)
	}))
	defer server.Close()
	r := NewRegistry()
	if err := RegisterBuiltins(r); err != nil {
		t.Fatal(err)
	}
	c, _ := r.Get("web.browse")
	for range 2 {
		result, err := c.Run(context.Background(), liveRequest(server.URL), d)
		if err != nil || len(result.Errors) != 0 {
			t.Fatalf("session fixture failed: %+v %v", result, err)
		}
	}
	if leaked.Load() != 0 {
		t.Fatal("browser reused a prior run's local storage")
	}
}

func TestLiveBrowserRejectsUntrustedTLS(t *testing.T) {
	if os.Getenv("CYBOT_LIVE_BROWSER") != "1" {
		t.Skip("requires isolated installed browser profile")
	}
	d := liveDeps(t)
	var reached atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached.Add(1); fmt.Fprint(w, "untrusted fixture") }))
	defer server.Close()
	r := NewRegistry()
	if err := RegisterBuiltins(r); err != nil {
		t.Fatal(err)
	}
	c, _ := r.Get("web.browse")
	result, err := c.Run(context.Background(), liveRequest(server.URL), d)
	if err == nil && result.Status != "partial" || reached.Load() != 0 {
		t.Fatalf("browser accepted an untrusted TLS endpoint: %+v %v requests=%d", result, err, reached.Load())
	}
}
