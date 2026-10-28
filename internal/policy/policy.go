package policy

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/s41r4j/cybot/pkg/schema"
)

type Config struct {
	AllowedTargets      []string      `json:"allowed_targets" yaml:"allowed_targets"`
	BlockedTargets      []string      `json:"blocked_targets" yaml:"blocked_targets"`
	ApprovalRequired    bool          `json:"approval_required" yaml:"approval_required"`
	MaxRate             int           `json:"max_rate" yaml:"max_rate"`
	Concurrency         int           `json:"concurrency" yaml:"concurrency"`
	Timeout             time.Duration `json:"timeout" yaml:"timeout"`
	AllowedCapabilities []string      `json:"allowed_capabilities" yaml:"allowed_capabilities"`
	EnforcementMode     string        `json:"enforcement_mode" yaml:"enforcement_mode"`
}

type Decision struct {
	Allowed          bool     `json:"allowed"`
	RequiresApproval bool     `json:"requires_approval"`
	Reason           string   `json:"reason"`
	Warnings         []string `json:"warnings,omitempty"`
}

type Engine struct{ config Config }

func New(c Config) *Engine {
	if c.Concurrency < 1 {
		c.Concurrency = 2
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Minute
	}
	if c.EnforcementMode != "strict" {
		c.EnforcementMode = "suggestive"
	}
	return &Engine{config: c}
}

func (e *Engine) Config() Config { return e.config }

func (e *Engine) Evaluate(req schema.RunRequest) Decision {
	d := e.evaluate(req)
	if !d.Allowed && e.config.EnforcementMode == "suggestive" {
		d.Warnings = []string{"policy advisory: " + d.Reason}
	}
	return d
}

func (e *Engine) evaluate(req schema.RunRequest) Decision {
	if !matchesAny(req.Capability, e.config.AllowedCapabilities) {
		return Decision{Reason: "capability is not allowed by policy"}
	}
	if req.Target != "" {
		t := canonicalTarget(req.Target)
		if len(e.config.BlockedTargets) > 0 && matchesAny(t, e.config.BlockedTargets) {
			return Decision{Reason: "target is blocked by policy"}
		}
		if len(e.config.AllowedTargets) > 0 && !matchesAny(t, e.config.AllowedTargets) {
			return Decision{Reason: "target is outside the allowed scope"}
		}
	}
	if e.config.ApprovalRequired && !req.Approved {
		return Decision{RequiresApproval: true, Reason: "explicit approval is missing"}
	}
	return Decision{Allowed: true, Reason: "allowed"}
}

func (e *Engine) Authorize(req schema.RunRequest) error {
	d := e.Evaluate(req)
	if e.config.EnforcementMode == "suggestive" {
		return nil
	}
	if !d.Allowed {
		if d.RequiresApproval {
			return fmt.Errorf("policy denied: %s (pass --approve after confirming authorization)", d.Reason)
		}
		return fmt.Errorf("policy denied: %s", d.Reason)
	}
	return nil
}

func canonicalTarget(s string) string {
	s = strings.TrimSpace(s)
	if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
		if u.Scheme != "http" && u.Scheme != "https" {
			// Preserve the resource kind. Allowing example.com must never also
			// authorize local://example.com or interface://example.com.
			return strings.ToLower(s)
		}
		return strings.ToLower(u.Hostname())
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func matchesAny(value string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if p != "*" && strings.Contains(value, "://") && !strings.Contains(p, "://") {
			continue
		}
		if p == "*" || p == value {
			return true
		}
		if ok, _ := filepath.Match(p, value); ok {
			return true
		}
		if strings.HasPrefix(p, "*.") && strings.HasSuffix(value, p[1:]) {
			return true
		}
	}
	return false
}
