package policy

import (
	"github.com/s41r4j/cybot/pkg/schema"
	"testing"
)

func TestPolicyRequiresApprovalAndScopesTarget(t *testing.T) {
	e := New(Config{AllowedTargets: []string{"*.example.com"}, BlockedTargets: []string{"admin.example.com"}, ApprovalRequired: true, AllowedCapabilities: []string{"asset.*"}})
	tests := []struct {
		name    string
		request schema.RunRequest
		allowed bool
	}{
		{"approval", schema.RunRequest{Capability: "asset.discover", Target: "api.example.com"}, false},
		{"allowed", schema.RunRequest{Capability: "asset.discover", Target: "api.example.com", Approved: true}, true},
		{"blocked", schema.RunRequest{Capability: "asset.discover", Target: "admin.example.com", Approved: true}, false},
		{"capability", schema.RunRequest{Capability: "web.map", Target: "api.example.com", Approved: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.Evaluate(tt.request).Allowed; got != tt.allowed {
				t.Fatalf("allowed=%v want %v", got, tt.allowed)
			}
		})
	}
}

func TestEmptyBlocklistDoesNotBlockEverything(t *testing.T) {
	e := New(Config{AllowedCapabilities: []string{"*"}})
	if decision := e.Evaluate(schema.RunRequest{Capability: "asset.discover", Target: "example.com", Approved: true}); !decision.Allowed {
		t.Fatalf("empty blocklist denied target: %#v", decision)
	}
}

func TestTypedResourcesCannotReuseHostnameAuthorization(t *testing.T) {
	e := New(Config{AllowedTargets: []string{"eth0", "fixture.invalid", "*.invalid"}, EnforcementMode: "strict"})
	for _, target := range []string{"interface://eth0", "local://fixture.invalid"} {
		if err := e.Authorize(schema.RunRequest{Capability: "fixture.run", Target: target, Approved: true}); err == nil {
			t.Fatalf("typed resource reused hostname authorization: %s", target)
		}
	}
	e = New(Config{AllowedTargets: []string{"interface://eth0"}, EnforcementMode: "strict"})
	if err := e.Authorize(schema.RunRequest{Capability: "fixture.run", Target: "interface://eth0", Approved: true}); err != nil {
		t.Fatal(err)
	}
}
