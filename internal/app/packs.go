package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s41r4j/cybot/internal/capability"
	"github.com/s41r4j/cybot/internal/config"
	"github.com/s41r4j/cybot/internal/docs"
	"github.com/s41r4j/cybot/internal/packs"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func withPacks(path string, fn func(*packs.Store, config.Config) error) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	db, _, err := c.Prepare()
	if err != nil {
		return err
	}
	s, err := packs.Open(filepath.Join(filepath.Dir(db), "packs.db"))
	if err != nil {
		return err
	}
	return errors.Join(fn(s, c), s.Close())
}

func packCmd(configPath, format *string) *cobra.Command {
	p := &cobra.Command{Use: "pack", Short: "Install, update and adapt versioned prompt packs"}
	output := func(c *cobra.Command, value any) error { return docs.Write(c.OutOrStdout(), *format, value) }
	command := func(use, description string, args cobra.PositionalArgs, fn func(*cobra.Command, []string, *packs.Store, config.Config) error) *cobra.Command {
		return &cobra.Command{Use: use, Short: description, Args: args, RunE: func(c *cobra.Command, a []string) error {
			return withPacks(*configPath, func(s *packs.Store, cfg config.Config) error { return fn(c, a, s, cfg) })
		}}
	}
	p.AddCommand(&cobra.Command{Use: "catalog", Short: "Show bundled packs available for offline installation", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		r, err := packs.Bundled()
		if err != nil {
			return err
		}
		return output(c, []map[string]any{{"id": r.PackID, "repository": r.Repository, "revision": r.Commit, "phases": len(r.Phases), "install": "cybot pack install " + r.Repository + " --bundled"}})
	}})
	var bundled bool
	var ref string
	install := command("install REPOSITORY", "Install a GitHub prompt pack; stage updates to an installed pack", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		repo, err := packs.Repository(a[0])
		if err != nil {
			return err
		}
		var r packs.Revision
		if bundled {
			if repo != packs.BuiltinRepository || ref != "main" {
				return fmt.Errorf("bundled installation supports %s at its recorded main revision", packs.BuiltinRepository)
			}
			r, err = packs.Bundled()
		} else {
			result, err := s.Install(c.Context(), repo, ref, packs.GitHub{})
			if err != nil {
				return err
			}
			return output(c, result)
		}
		if err != nil {
			return err
		}
		result, err := s.Stage(c.Context(), r, ref)
		if err != nil {
			return err
		}
		return output(c, result)
	})
	install.Flags().BoolVar(&bundled, "bundled", false, "install the bundled immutable snapshot without network access")
	install.Flags().StringVar(&ref, "ref", "main", "upstream branch, tag or commit to track")
	p.AddCommand(install)
	p.AddCommand(packUpdateCommand(configPath, format), packWatchCommand(configPath))
	p.AddCommand(command("list", "List installed packs and active/candidate revisions", cobra.NoArgs, func(c *cobra.Command, _ []string, s *packs.Store, _ config.Config) error {
		v, err := s.List(c.Context())
		if err != nil {
			return err
		}
		return output(c, v)
	}))
	var showRevision string
	show := command("show PACK", "Inspect the phase manifest and capability mappings", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		v, err := s.Plan(c.Context(), a[0], showRevision)
		if err != nil {
			return err
		}
		return output(c, v)
	})
	show.Aliases = []string{"plan"}
	show.Flags().StringVar(&showRevision, "revision", "", "inspect a stored revision (default active)")
	p.AddCommand(show)
	p.AddCommand(command("history PACK", "List immutable downloaded revisions", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		v, err := s.History(c.Context(), a[0])
		if err != nil {
			return err
		}
		return output(c, v)
	}))
	p.AddCommand(command("events PACK", "Show recent pack lifecycle events", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		v, err := s.Events(c.Context(), a[0])
		if err != nil {
			return err
		}
		return output(c, v)
	}))
	p.AddCommand(command("sync PACK", "Download and stage the latest upstream revision", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		v, err := s.Sync(c.Context(), a[0], packs.GitHub{})
		if err != nil {
			return err
		}
		return output(c, v)
	}))
	var due bool
	check := command("check-updates [PACK]", "Check upstream commits without downloading or activating prompts", cobra.MaximumNArgs(1), func(c *cobra.Command, a []string, s *packs.Store, cfg config.Config) error {
		items, err := s.List(c.Context())
		if err != nil {
			return err
		}
		if len(a) == 1 {
			item, err := s.Get(c.Context(), a[0])
			if err != nil {
				return err
			}
			items = []packs.Pack{item}
		}
		var interval time.Duration
		if due {
			interval = cfg.Packs.UpdateInterval
		}
		out := []packs.Check{}
		failures := []error{}
		for _, item := range items {
			result, err := s.Check(c.Context(), item.ID, packs.GitHub{}, interval)
			out = append(out, result)
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", item.ID, err))
			}
		}
		return errors.Join(output(c, out), errors.Join(failures...))
	})
	check.Flags().BoolVar(&due, "due", false, "skip successful checks newer than packs.update_interval")
	p.AddCommand(check)
	var diffRevision string
	diff := command("diff PACK", "Compare staged files and identify local override conflicts", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		v, err := s.Diff(c.Context(), a[0], diffRevision)
		if err != nil {
			return err
		}
		return output(c, v)
	})
	diff.Flags().StringVar(&diffRevision, "revision", "", "compare a stored revision (default candidate or active)")
	p.AddCommand(diff)
	var activateRevision string
	activate := command("activate PACK", "Atomically activate a stored revision after conflict checks", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		v, err := s.Activate(c.Context(), a[0], activateRevision, false)
		if err != nil {
			return err
		}
		return output(c, v)
	})
	activate.Flags().StringVar(&activateRevision, "revision", "", "exact stored commit SHA")
	_ = activate.MarkFlagRequired("revision")
	p.AddCommand(activate)
	p.AddCommand(command("rollback PACK", "Restore the previous active revision", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		v, err := s.Activate(c.Context(), a[0], "", true)
		if err != nil {
			return err
		}
		return output(c, v)
	}))
	var renderRevision, contextFile, renderOutput string
	var strict bool
	render := command("render PACK PHASE", "Render advisory phase guidance with explicit context", cobra.ExactArgs(2), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		values, err := packContext(contextFile)
		if err != nil {
			return err
		}
		r, err := s.Revision(c.Context(), a[0], renderRevision)
		if err != nil {
			return err
		}
		os, err := s.Overrides(c.Context(), a[0], r.Commit)
		if err != nil {
			return err
		}
		v, err := packs.Render(r, a[1], values, os)
		if err != nil {
			return err
		}
		if strict && len(v.Unresolved) > 0 {
			return fmt.Errorf("unresolved inputs: %s", strings.Join(v.Unresolved, ", "))
		}
		if renderOutput != "" {
			return savePackOutput(renderOutput, []byte(v.Content))
		}
		return output(c, v)
	})
	render.Flags().StringVar(&renderRevision, "revision", "", "render a stored revision (default active)")
	render.Flags().StringVar(&contextFile, "context", "", "YAML/JSON string map of runtime variables; use secret references, not secret values")
	render.Flags().StringVar(&renderOutput, "output", "", "write Markdown to a new file")
	render.Flags().BoolVar(&strict, "strict", false, "fail rendering if any required input or placeholder is unresolved")
	p.AddCommand(render)
	var overrideFile, overrideRevision string
	override := command("override PACK PHASE", "Save local prompt/mapping overrides against an exact source revision", cobra.ExactArgs(2), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		var o packs.Override
		if err := packDecode(overrideFile, &o); err != nil {
			return err
		}
		if o.PhaseID != "" && o.PhaseID != a[1] {
			return fmt.Errorf("override phase ID differs from command")
		}
		o.PhaseID = a[1]
		if o.Content == nil && o.Capabilities == nil {
			return fmt.Errorf("override requires content or capabilities")
		}
		if o.Capabilities != nil {
			registry := capability.NewRegistry()
			if err := capability.RegisterBuiltins(registry); err != nil {
				return err
			}
			for _, id := range *o.Capabilities {
				if _, ok := registry.Get(id); !ok {
					return fmt.Errorf("unknown mapped capability %q", id)
				}
			}
		}
		if err := s.SetOverride(c.Context(), a[0], overrideRevision, o); err != nil {
			return err
		}
		v, err := s.Overrides(c.Context(), a[0], overrideRevision)
		if err != nil {
			return err
		}
		return output(c, v)
	})
	override.Flags().StringVar(&overrideFile, "file", "", "JSON file with optional content and capabilities fields")
	_ = override.MarkFlagRequired("file")
	override.Flags().StringVar(&overrideRevision, "revision", "", "base revision, including a staged revision when resolving a conflict")
	p.AddCommand(override)
	var listOverrideRevision, removeOverrideRevision string
	listOverrides := command("overrides PACK", "List local overrides and their base hashes", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		v, err := s.Overrides(c.Context(), a[0], listOverrideRevision)
		if err != nil {
			return err
		}
		return output(c, v)
	})
	listOverrides.Flags().StringVar(&listOverrideRevision, "revision", "", "stored revision (default active)")
	p.AddCommand(listOverrides)
	removeOverride := command("remove-override PACK PHASE", "Remove a local override", cobra.ExactArgs(2), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		if err := s.RemoveOverride(c.Context(), a[0], a[1], removeOverrideRevision); err != nil {
			return err
		}
		return output(c, map[string]string{"removed": a[1]})
	})
	removeOverride.Flags().StringVar(&removeOverrideRevision, "revision", "", "stored revision (default active)")
	p.AddCommand(removeOverride)
	var exportRevision, exportOutput string
	export := command("export PACK", "Export a complete source snapshot, license, manifest and overrides as JSON", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		r, err := s.Revision(c.Context(), a[0], exportRevision)
		if err != nil {
			return err
		}
		os, err := s.Overrides(c.Context(), a[0], r.Commit)
		if err != nil {
			return err
		}
		v := struct {
			Revision  packs.Revision   `json:"revision"`
			Overrides []packs.Override `json:"overrides"`
		}{r, os}
		if exportOutput == "" {
			return output(c, v)
		}
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		return savePackOutput(exportOutput, append(b, '\n'))
	})
	export.Flags().StringVar(&exportRevision, "revision", "", "export a stored revision (default active)")
	export.Flags().StringVar(&exportOutput, "output", "", "write JSON to a new file")
	p.AddCommand(export)
	// Run metadata freezes the active revision, local overrides and context.
	runs := &cobra.Command{Use: "run", Short: "Track pinned engagements and evidence-backed phase handoffs"}
	var runContext string
	start := command("start PACK", "Start an engagement pinned to the active pack and overrides", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		values, err := packContext(runContext)
		if err != nil {
			return err
		}
		v, err := s.StartRun(c.Context(), a[0], values)
		if err != nil {
			return err
		}
		return output(c, v)
	})
	start.Flags().StringVar(&runContext, "context", "", "YAML/JSON string map containing target and explicit scope")
	_ = start.MarkFlagRequired("context")
	runs.AddCommand(start)
	runs.AddCommand(command("show RUN_ID", "Inspect pinned context and phase records", cobra.ExactArgs(1), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		v, err := s.Run(c.Context(), a[0])
		if err != nil {
			return err
		}
		return output(c, v)
	}))
	runs.AddCommand(command("render RUN_ID PHASE", "Render using the engagement's frozen revision, context and overrides", cobra.ExactArgs(2), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		v, err := s.RenderRun(c.Context(), a[0], a[1])
		if err != nil {
			return err
		}
		return output(c, v)
	}))
	var status, reason string
	var artifacts []string
	record := command("record RUN_ID PHASE", "Record phase status, reason and hashed handoff files", cobra.ExactArgs(2), func(c *cobra.Command, a []string, s *packs.Store, _ config.Config) error {
		entry := packs.PhaseRecord{PhaseID: a[1], Status: status, Reason: reason, Artifacts: []packs.Artifact{}}
		for _, value := range artifacts {
			name, filename, ok := strings.Cut(value, "=")
			if !ok {
				return fmt.Errorf("artifact must be NAME=PATH")
			}
			artifact, err := packs.Evidence(name, filename)
			if err != nil {
				return err
			}
			entry.Artifacts = append(entry.Artifacts, artifact)
		}
		v, err := s.Record(c.Context(), a[0], entry)
		if err != nil {
			return err
		}
		return output(c, v)
	})
	record.Flags().StringVar(&status, "status", "", "completed, partial, blocked or skipped (optional phases only)")
	_ = record.MarkFlagRequired("status")
	record.Flags().StringVar(&reason, "reason", "", "what was tested, achieved or blocked")
	_ = record.MarkFlagRequired("reason")
	record.Flags().StringArrayVar(&artifacts, "artifact", nil, "named handoff file, NAME=PATH; repeat for each artifact")
	runs.AddCommand(record)
	p.AddCommand(runs)
	return p
}

func packRead(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, packs.MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > packs.MaxFileBytes {
		return nil, fmt.Errorf("input exceeds 1 MiB")
	}
	return b, nil
}
func packDecode(filename string, out any) error {
	b, err := packRead(filename)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected one JSON object")
	}
	return nil
}
func packContext(filename string) (map[string]string, error) {
	values := map[string]string{}
	if filename == "" {
		return values, nil
	}
	b, err := packRead(filename)
	if err != nil {
		return nil, err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	if err = d.Decode(&values); err != nil {
		return nil, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("expected one context document")
	}
	if values == nil {
		return nil, fmt.Errorf("context must be a string map")
	}
	return values, nil
}
func savePackOutput(filename string, b []byte) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(b)
	return errors.Join(writeErr, f.Close())
}
