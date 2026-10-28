package capability

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/pkg/schema"
)

type Dependencies struct {
	Tools      *registry.ToolRegistry
	Runner     execution.Runner
	Evidence   *evidence.Store
	Timeout    time.Duration
	LoadResult func(context.Context, string) (schema.Result, error)
}
type Capability interface {
	ID() string
	Definition() schema.CapabilityDefinition
	Run(context.Context, schema.RunRequest, Dependencies) (schema.Result, error)
}

// ValidateTarget shares runtime target checks with planning without running tools.
func ValidateTarget(c Capability, target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("target is required")
	}
	switch c.(type) {
	case AssetDiscover:
		return validateHostname(target)
	case externalCapability:
		if err := validateCapabilityTarget(c.ID(), target); err != nil {
			return err
		}
		valid := 0
		var scopeErr error
		for _, step := range c.(externalCapability).steps {
			if err := validateStepTarget(step.ID, target); err != nil {
				if step.Required {
					return err
				}
				scopeErr = err
			} else {
				valid++
			}
		}
		if valid == 0 && scopeErr != nil {
			return scopeErr
		}
	case browserCapability, ZAPBaseline:
		return validateBrowserTarget(target)
	}
	return nil
}

type Registry struct {
	mu     sync.RWMutex
	values map[string]Capability
}

func NewRegistry() *Registry { return &Registry{values: map[string]Capability{}} }
func (r *Registry) Register(c Capability) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.ID() == "" {
		return fmt.Errorf("capability: empty id")
	}
	if _, ok := r.values[c.ID()]; ok {
		return fmt.Errorf("capability %q already registered", c.ID())
	}
	r.values[c.ID()] = c
	return nil
}
func (r *Registry) Get(id string) (Capability, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.values[id]
	return v, ok
}
func (r *Registry) List() []Capability {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.values))
	for id := range r.values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Capability, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.values[id])
	}
	return out
}

// CommandCapability is a declarative adapter from a registered tool to a normalized result.
type CommandCapability struct {
	Metadata schema.CapabilityDefinition
	ToolID   string
	Args     func(schema.RunRequest) []string
	Parse    func([]byte, schema.RunRequest) (schema.Result, error)
}

func (c CommandCapability) ID() string                              { return c.Metadata.ID }
func (c CommandCapability) Definition() schema.CapabilityDefinition { return c.Metadata }
func (c CommandCapability) Run(ctx context.Context, req schema.RunRequest, d Dependencies) (schema.Result, error) {
	tool, ok := d.Tools.Get(c.ToolID)
	if !ok {
		return schema.Result{}, fmt.Errorf("required tool %q is not registered", c.ToolID)
	}
	out, err := d.Runner.Run(ctx, execution.Spec{Tool: tool, Args: c.Args(req), Timeout: d.Timeout, Retries: 1, Network: tool.RequiresNetwork})
	if err != nil {
		return schema.Result{}, err
	}
	result, err := c.Parse(out.Stdout, req)
	if err != nil {
		return schema.Result{}, fmt.Errorf("normalize %s output: %w", c.ToolID, err)
	}
	ev, err := d.Evidence.Put(req.RunID, "terminal-log", "text/plain", out.Stdout)
	if err != nil {
		return schema.Result{}, err
	}
	result.Evidence = append(result.Evidence, ev)
	return result, nil
}
