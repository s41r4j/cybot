package policy

import (
	"github.com/s41r4j/cybot/pkg/schema"
	"os"
	"path/filepath"
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

func TestLocalScopeResolvesSymlinksAndRelativePaths(t *testing.T) {
	root := t.TempDir()
	allowed, outside := filepath.Join(root, "allowed"), filepath.Join(root, "outside")
	for _, dir := range []string{allowed, outside} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	safe, secret := filepath.Join(allowed, "safe.go"), filepath.Join(outside, "private.go")
	for _, path := range []string{safe, secret} {
		if err := os.WriteFile(path, []byte("package fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	e := New(Config{EnforcementMode: "strict", AllowedTargets: []string{filepath.Join(allowed, "*")}})
	request := schema.RunRequest{Capability: "code.audit", Target: safe, Approved: true}
	if err := e.Authorize(request); err != nil {
		t.Fatal("allowed regular file was denied", err)
	}
	link := filepath.Join(allowed, "link.go")
	if err := os.Symlink(secret, link); err != nil {
		t.Skip("symlink creation unavailable on this host", err)
	}
	request.Target = link
	if err := e.Authorize(request); err == nil {
		t.Fatal("allowed pathname authorized a different, out-of-scope file")
	}
	request.Target = filepath.Join(allowed, "..", "outside", "private.go")
	if err := e.Authorize(request); err == nil {
		t.Fatal("relative traversal escaped local scope")
	}
}

func TestHostnameScopeDoesNotAuthorizeMatchingLocalFilename(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("api.example.com", []byte("local fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	e := New(Config{EnforcementMode: "strict", AllowedTargets: []string{"*.example.com"}})
	if err := e.Authorize(schema.RunRequest{Capability: "code.audit", Target: "./api.example.com", Approved: true}); err == nil {
		t.Fatal("hostname approval was reused for a local file")
	}
	if err := e.Authorize(schema.RunRequest{Capability: "asset.discover", Target: "api.example.com", Approved: true}); err != nil {
		t.Fatal("local filename changed network scope interpretation", err)
	}
	e = New(Config{EnforcementMode: "strict", AllowedTargets: []string{"./api.example.com"}})
	if err := e.Authorize(schema.RunRequest{Capability: "code.audit", Target: "./api.example.com", Approved: true}); err != nil {
		t.Fatal("explicit relative file scope was denied", err)
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
