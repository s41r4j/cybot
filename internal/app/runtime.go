package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/s41r4j/cybot/catalog"
	"github.com/s41r4j/cybot/internal/capability"
	"github.com/s41r4j/cybot/internal/config"
	"github.com/s41r4j/cybot/internal/evidence"
	"github.com/s41r4j/cybot/internal/execution"
	"github.com/s41r4j/cybot/internal/memory"
	"github.com/s41r4j/cybot/internal/orchestrator"
	"github.com/s41r4j/cybot/internal/policy"
	"github.com/s41r4j/cybot/internal/registry"
	"github.com/s41r4j/cybot/internal/telemetry"
	"github.com/s41r4j/cybot/pkg/schema"
)

type runtime struct {
	core         *orchestrator.Orchestrator
	skills       *registry.SkillRegistry
	tools        *registry.ToolRegistry
	capabilities *capability.Registry
	store        *memory.Store
	policyConfig policy.Config
	sources      []schema.Source
	patterns     []schema.VulnerabilityPattern
	platforms    []schema.PlatformChain
	severities   []schema.SeverityMapping
	logs         *telemetry.Logger
}

func newRuntime(configPath string) (*runtime, error) {
	c, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	dbPath, evidencePath, err := c.Prepare()
	if err != nil {
		return nil, err
	}
	store, err := memory.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open memory: %w", err)
	}
	skills := registry.NewSkills()
	tools := registry.NewTools()
	curatedSkills, err := catalog.Skills()
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("load curated skills: %w", err)
	}
	for _, v := range curatedSkills {
		if err := skills.Upsert(v); err != nil {
			store.Close()
			return nil, fmt.Errorf("register skill: %w", err)
		}
	}
	storedSkills, err := store.Skills(context.Background())
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("load skills: %w", err)
	}
	for _, v := range storedSkills {
		if err := skills.Upsert(v); err != nil {
			store.Close()
			return nil, fmt.Errorf("register skill: %w", err)
		}
	}
	curatedTools, err := catalog.Tools()
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("load curated tools: %w", err)
	}
	for _, v := range curatedTools {
		if os.Getenv("CYBOT_TOOLBOX_INTERNAL") == "1" && v.ID != "zap" {
			v.Kind = "native"
			v.DockerImage = ""
		}
		if err := tools.Upsert(v); err != nil {
			store.Close()
			return nil, fmt.Errorf("register tool: %w", err)
		}
	}
	storedTools, err := store.Tools(context.Background())
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("load tools: %w", err)
	}
	for _, v := range capability.BuiltinTools() {
		if err := tools.Upsert(v); err != nil {
			store.Close()
			return nil, fmt.Errorf("register tool: %w", err)
		}
	}
	for _, v := range storedTools {
		if err := tools.Upsert(v); err != nil {
			store.Close()
			return nil, fmt.Errorf("register tool: %w", err)
		}
	}
	sources, err := catalog.Sources()
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("load catalog sources: %w", err)
	}
	caps := capability.NewRegistry()
	if err = capability.RegisterBuiltins(caps); err != nil {
		store.Close()
		return nil, err
	}
	runner := execution.NewBounded(execution.LocalRunner{}, c.Policy.Concurrency, c.Policy.MaxRate)
	deps := capability.Dependencies{Tools: tools, Runner: runner, Evidence: evidence.New(evidencePath), Timeout: c.Policy.Timeout, LoadResult: store.Result}
	logs := telemetry.New(filepath.Join(filepath.Dir(dbPath), "cybot.log.jsonl"))
	core := &orchestrator.Orchestrator{Capabilities: caps, Policy: policy.New(c.Policy), Dependencies: deps, Memory: store, Audit: logs}
	patterns, err := catalog.Patterns()
	if err != nil {
		store.Close()
		return nil, err
	}
	platforms, err := catalog.Platforms()
	if err != nil {
		store.Close()
		return nil, err
	}
	severities, err := catalog.SeverityMappings()
	if err != nil {
		store.Close()
		return nil, err
	}
	return &runtime{core: core, skills: skills, tools: tools, capabilities: caps, store: store, policyConfig: c.Policy, sources: sources, patterns: patterns, platforms: platforms, severities: severities, logs: logs}, nil
}
func withRuntime(path *string, fn func(*runtime) error) error {
	r, err := newRuntime(*path)
	if err != nil {
		return err
	}
	return errors.Join(fn(r), r.store.Close())
}
