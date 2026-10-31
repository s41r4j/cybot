package capability

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"encoding/json"

	"github.com/s41r4j/cybot/pkg/schema"
)

func TestLiveWebTLSProtocols(t *testing.T) {
	if testing.Short() {
		t.Skip("real TLS protocol negotiation")
	}
	if os.Getenv("CYBOT_LIVE_WEB") != "1" {
		t.Skip("requires installed web-profile TLS engine")
	}
	d := liveDeps(t)
	d.Timeout = 90 * time.Second
	server := func(weak bool) *httptest.Server {
		t.Helper()
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Owned CYBOT TLS fixture"))
		}))
		s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
		if weak {
			s.TLS.MinVersion, s.TLS.MaxVersion = tls.VersionTLS10, tls.VersionTLS12
			s.TLS.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
		}
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	c := liveCapability(t, "tls.audit")
	request := func(target string) schema.RunRequest {
		req := liveRequest(target)
		req.Input = json.RawMessage(`{"checks":"protocols"}`)
		return req
	}
	weak := server(true)
	target := strings.TrimPrefix(weak.URL, "https://")
	r, err := c.Run(context.Background(), request(target), d)
	found := false
	for _, finding := range r.Findings {
		found = found || finding.Title == "TLS1" || finding.Title == "TLS1_1"
	}
	if err != nil || len(r.Errors) != 0 || r.Status == "partial" || !found || len(r.Evidence) != 1 {
		t.Fatalf("real legacy TLS protocols were missed: %+v %v", r, err)
	}
	validateFixtureResult(t, r)
	modern := server(false)
	r, err = c.Run(context.Background(), request(strings.TrimPrefix(modern.URL, "https://")), d)
	if err != nil || len(r.Errors) != 0 || len(r.Findings) != 0 || r.Status == "partial" || len(r.Evidence) != 1 {
		t.Fatalf("modern protocol fixture produced a false issue: %+v %v", r, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().String()
	_ = listener.Close()
	r, err = c.Run(context.Background(), request(closed), d)
	if err == nil && r.Status != "partial" && len(r.Errors) == 0 {
		t.Fatalf("closed TLS endpoint was reported clean: %+v", r)
	}
	certifyOperation(t, "testssl", "tls.audit", []operationCase{
		passedCase("positive", "Real TestSSL protocol mode detects deprecated TLS 1.0/1.1 offered by an owned TLS fixture."),
		passedCase("negative", "TLS 1.2/1.3-only fixture produces protocol observations with no invented vulnerability findings."),
		passedCase("failure", "A closed loopback TLS endpoint fails explicitly; no clean assessment is established."),
	})
}
