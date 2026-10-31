package capability

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestLiveWebCORS(t *testing.T) {
	d := liveWebDeps(t)
	c := liveCapability(t, "cors.audit")
	var origins atomic.Int64
	positive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			origins.Add(1)
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		fmt.Fprint(w, "synthetic public response")
	}))
	defer positive.Close()
	r, err := c.Run(context.Background(), liveRequest(positive.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) != 0 || len(r.Evidence) != 1 || !hasTechnology(r, "CORS candidate: reflect_origin") || origins.Load() != 1 {
		t.Fatalf("real reflected headers lost or promoted: %+v %v requests=%d", r, err, origins.Load())
	}
	validateFixtureResult(t, r)
	var negativeRequests atomic.Int64
	negative := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		negativeRequests.Add(1)
		fmt.Fprint(w, "neutral fixture")
	}))
	r, err = c.Run(context.Background(), liveRequest(negative.URL), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) != 0 || len(r.Evidence) != 1 || len(r.Endpoints) != 1 || len(r.Endpoints[0].Technology) != 0 || negativeRequests.Load() < 10 {
		t.Fatalf("neutral target not fully probed: %+v %v count=%d", r, err, negativeRequests.Load())
	}
	negative.Close()
	r, err = c.Run(context.Background(), liveRequest(negative.URL), d)
	if err == nil || len(r.Errors) == 0 || len(r.Findings) != 0 || len(r.Evidence) != 0 {
		t.Fatalf("transport failure reported as clean: %+v %v", r, err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "fixture failure", 500) }))
	defer bad.Close()
	r, err = c.Run(context.Background(), liveRequest(bad.URL), d)
	if err == nil || len(r.Errors) == 0 || len(r.Findings) != 0 {
		t.Fatalf("HTTP error established negative assurance: %+v %v", r, err)
	}
	certifyOperation(t, "corscanner", "cors.audit", []operationCase{
		passedCase("positive", "Real sequential CORScanner retains reflected Origin/credential header candidates from a loopback server without claiming exploitability."),
		passedCase("negative", "Full sequential check list against a neutral reachable server produces no policy candidate or vulnerability."),
		passedCase("failure", "Closed target and HTTP 500 cannot produce a complete negative assessment."),
	})
}
