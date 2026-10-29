package policy

import (
	"fmt"
	"net"
	"net/url"
	"os"
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
		if filesystemTarget(req) {
			logical, err := filepath.Abs(req.Target)
			if err != nil {
				return Decision{Reason: "local target cannot be made absolute for scope validation"}
			}
			resolved, err := filepath.EvalSymlinks(logical)
			if err != nil {
				return Decision{Reason: "local target cannot be resolved for scope validation"}
			}
			if len(e.config.BlockedTargets) > 0 && (matchesPaths(resolved, e.config.BlockedTargets) || matchesPaths(logical, e.config.BlockedTargets)) {
				return Decision{Reason: "local target is blocked by policy"}
			}
			if len(e.config.AllowedTargets) > 0 && !matchesPaths(resolved, e.config.AllowedTargets) {
				return Decision{Reason: "resolved local target is outside the allowed scope"}
			}
		} else {
			t := canonicalTarget(req.Target)
			if len(e.config.BlockedTargets) > 0 && matchesAny(t, e.config.BlockedTargets) {
				return Decision{Reason: "target is blocked by policy"}
			}
			if len(e.config.AllowedTargets) > 0 && !matchesAny(t, e.config.AllowedTargets) {
				return Decision{Reason: "target is outside the allowed scope"}
			}
		}
	}
	if e.config.ApprovalRequired && !req.Approved {
		return Decision{RequiresApproval: true, Reason: "explicit approval is missing"}
	}
	return Decision{Allowed: true, Reason: "allowed"}
}

func filesystemTarget(req schema.RunRequest) bool {
	switch req.Capability {
	case "code.audit", "secret.scan", "dependency.scan", "cloud.review", "js.analyse", "js.extract", "hash.crack", "pattern.detect":
		return true
	case "container.scan", "credential.harvest":
		_, err := os.Stat(req.Target)
		return err == nil
	default:
		return false
	}
}

func matchesPaths(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		// Hostname patterns must not grant filesystem access to similarly
		// named local files. Relative file scopes must explicitly name a path.
		if strings.Contains(pattern, "://") || (!filepath.IsAbs(pattern) && pattern != "." && pattern != ".." && !strings.ContainsAny(pattern, `/\`)) {
			continue
		}
		abs, err := filepath.Abs(pattern)
		if err != nil {
			continue
		}
		if matched, _ := filepath.Match(abs, value); matched {
			return true
		}
		// Resolve the non-glob prefix so explicitly scoped symlink directories
		// work, while links from an allowed tree into an unallowed tree fail.
		prefix, suffix := abs, ""
		if wildcard := strings.IndexAny(abs, "*?["); wildcard >= 0 {
			separator := strings.LastIndexAny(abs[:wildcard], `/\`)
			if separator < 0 {
				continue
			}
			prefix, suffix = abs[:separator+1], abs[separator+1:]
		}
		if resolved, err := filepath.EvalSymlinks(prefix); err == nil {
			abs = filepath.Join(resolved, suffix)
		}
		if value == abs {
			return true
		}
		if matched, _ := filepath.Match(abs, value); matched {
			return true
		}
	}
	return false
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
