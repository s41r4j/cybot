package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/s41r4j/cybot/internal/config"
	"github.com/s41r4j/cybot/internal/docs"
	"github.com/s41r4j/cybot/internal/packs"
	"github.com/spf13/cobra"
)

// Automatic maintenance runs before consumers read their active snapshot. Pack
// management commands are excluded so rollback, conflict resolution and offline
// inspection cannot unexpectedly trigger an update.
func autoUpdatePacks(cmd *cobra.Command, configPath string) error {
	return autoUpdatePacksWith(cmd, configPath, packs.GitHub{})
}

func autoUpdatePacksWith(cmd *cobra.Command, configPath string, g packs.GitHub) error {
	if cmd.Name() == "help" || cmd.Name() == "completion" {
		return nil
	}
	for parent := cmd; parent != nil; parent = parent.Parent() {
		if parent.Name() == "pack" {
			consumer := cmd.Parent() == parent && (cmd.Name() == "list" || cmd.Name() == "show" || cmd.Name() == "render")
			consumer = consumer || (cmd.Name() == "start" && cmd.Parent() != nil && cmd.Parent().Name() == "run")
			if !consumer {
				return nil
			}
		}
	}
	if os.Getenv("CYBOT_PACK_AUTO_UPDATE") == "0" {
		return nil
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if !cfg.Packs.AutoUpdate {
		return nil
	}
	filename := filepath.Join(cfg.DataDir, "packs.db")
	if _, err = os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "Prompt pack maintenance:", err)
		return nil
	}
	s, err := packs.Open(filename)
	if err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "Prompt pack maintenance:", err)
		return nil
	}
	defer s.Close()
	// Bound total startup work even when many sources are registered. A watcher
	// or explicit pack update can finish additional sources independently.
	ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Packs.UpdateTimeout)
	defer cancel()
	results, updateErr := s.Updates(ctx, g, cfg.Packs.UpdateInterval, cfg.Packs.UpdateTimeout)
	for _, result := range results {
		if result.Status == "updated" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Updated prompt pack %s to %s (previous %s retained).\n", result.PackID, result.Active, result.Previous)
		}
	}
	for _, result := range results {
		if result.Status == "rolled-back" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Restored prompt pack %s to %s: %s\n", result.PackID, result.Active, result.Error)
		}
	}
	if updateErr != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "Prompt pack update deferred; using installed data:", updateErr)
	}
	return nil
}

func packUpdateCommand(configPath, format *string) *cobra.Command {
	var due bool
	cmd := &cobra.Command{Use: "update [PACK]", Short: "Check, validate and automatically activate latest prompts, keeping a fallback", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		return withPacks(*configPath, func(s *packs.Store, cfg config.Config) error {
			var interval time.Duration
			if due {
				interval = cfg.Packs.UpdateInterval
			}
			if len(args) == 0 {
				out, err := s.Updates(cmd.Context(), packs.GitHub{}, interval, cfg.Packs.UpdateTimeout)
				return errors.Join(docs.Write(cmd.OutOrStdout(), *format, out), err)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), cfg.Packs.UpdateTimeout)
			defer cancel()
			out, err := s.Update(ctx, args[0], packs.GitHub{}, interval)
			return errors.Join(docs.Write(cmd.OutOrStdout(), *format, out), err)
		})
	}}
	cmd.Flags().BoolVar(&due, "due", false, "only check sources whose update interval has elapsed")
	return cmd
}

func packWatchCommand(configPath *string) *cobra.Command {
	var once bool
	var interval time.Duration
	cmd := &cobra.Command{Use: "watch", Short: "Continuously keep installed prompt packs updated", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("interval") && interval <= 0 {
			return fmt.Errorf("watch interval must be positive")
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return withPacks(*configPath, func(s *packs.Store, cfg config.Config) error {
			poll := interval
			if poll == 0 {
				poll = min(cfg.Packs.UpdateInterval, 15*time.Minute)
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			for {
				if ctx.Err() != nil {
					return nil
				}
				out, err := s.Updates(ctx, packs.GitHub{}, cfg.Packs.UpdateInterval, cfg.Packs.UpdateTimeout)
				if ctx.Err() != nil {
					return nil
				}
				for _, result := range out {
					if once || result.Status == "updated" || result.Error != "" {
						if e := encoder.Encode(result); e != nil {
							return e
						}
					}
				}
				if once {
					return err
				}
				if err != nil {
					fmt.Fprintln(cmd.ErrOrStderr(), "Prompt pack watch:", err)
				}
				timer := time.NewTimer(poll)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil
				case <-timer.C:
				}
			}
		})
	}}
	cmd.Flags().BoolVar(&once, "once", false, "perform one due maintenance pass and exit")
	cmd.Flags().DurationVar(&interval, "interval", 0, "poll frequency (default the smaller of update_interval and 15m)")
	return cmd
}
