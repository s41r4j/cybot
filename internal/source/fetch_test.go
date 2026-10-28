package source

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestFetchRejectsUnsafeURLsBeforeNetwork(t *testing.T) {
	for _, v := range []string{"http://example.com/x", "file:///tmp/x", "https://localhost/x", "relative.yaml"} {
		if _, err := Fetch(context.Background(), v); err == nil {
			t.Errorf("accepted unsafe URL %q", v)
		}
	}
}

func TestPublicDialConnectsToValidatedIPWithoutResolvingAgain(t *testing.T) {
	lookups, dials := 0, 0
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		if lookups > 1 {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		dials++
		if address != "203.0.113.10:443" {
			t.Fatalf("dialed an unvalidated hostname/address: %s", address)
		}
		return nil, errors.New("fixture connection refused")
	}
	_, _ = publicDial(lookup, dial)(context.Background(), "tcp", "fixture.invalid:443")
	if lookups != 1 || dials != 1 {
		t.Fatalf("lookup/dial count %d/%d", lookups, dials)
	}
}

func TestPublicDialRejectsPrivateOrMixedAnswersBeforeDialing(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1", "169.254.169.254", "10.0.0.1", "100.64.0.1", "224.0.0.1", "0.1.2.3"} {
		t.Run(address, func(t *testing.T) {
			lookup := func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}, {IP: net.ParseIP(address)}}, nil
			}
			dial := func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("dialed a forbidden DNS answer")
				return nil, nil
			}
			if _, err := publicDial(lookup, dial)(context.Background(), "tcp", "fixture.invalid:443"); err == nil {
				t.Fatal("accepted unsafe answer")
			}
		})
	}
}
