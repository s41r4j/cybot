package packs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/s41r4j/cybot/internal/capability"
	"github.com/google/uuid"
)

type UpdateResult struct {
	PackID    string `json:"pack_id"`
	Status    string `json:"status"`
	Active    string `json:"active_revision"`
	Previous  string `json:"previous_revision,omitempty"`
	Available string `json:"available_revision,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Health checks the local integration contract, without executing any prompt or
// scanner. Private upstream services remain declared integration gaps.
func Health(r Revision, os []Override) error {
	if err := r.Validate(); err != nil {
		return err
	}
	registry := capability.NewRegistry()
	if err := capability.RegisterBuiltins(registry); err != nil {
		return err
	}
	for _, phase := range r.Phases {
		p, _, err := effective(r, phase.ID, os)
		if err != nil {
			return err
		}
		for _, id := range p.Capabilities {
			if _, ok := registry.Get(id); !ok {
				return fmt.Errorf("phase %s maps unknown capability %q", p.ID, id)
			}
		}
		if _, err = Render(r, p.ID, map[string]string{"target": "health-check.invalid", "scope": "offline render validation only"}, os); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) acquireUpdate(ctx context.Context, id string) (string, bool, error) {
	owner := uuid.NewString()
	now := time.Now().Unix()
	expires := now + 300
	if deadline, ok := ctx.Deadline(); ok {
		expires = deadline.Unix() + 5
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO pack_update_leases(pack_id,owner,expires_at) VALUES(?,?,?) ON CONFLICT(pack_id) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at WHERE pack_update_leases.expires_at<=?`, id, owner, expires, now)
	if err != nil {
		return "", false, err
	}
	n, err := result.RowsAffected()
	return owner, n == 1, err
}

// Update resolves the tracked ref once and only activates a complete, healthy
// revision. The activation compares the active pointer to prevent races with a
// manual rollback or activation in another CLI process.
func (s *Store) Update(ctx context.Context, id string, g GitHub, due time.Duration) (out UpdateResult, err error) {
	p, err := s.Get(ctx, id)
	if err != nil {
		return out, err
	}
	out = UpdateResult{PackID: id, Status: "failed", Active: p.Active, Previous: p.Previous, Available: p.Available}
	owner, acquired, err := s.acquireUpdate(ctx, id)
	if err != nil {
		return out, err
	}
	if !acquired {
		out.Status = "locked"
		return out, nil
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err != nil {
			out.Error = err.Error()
			if saveErr := s.recordCheck(cleanup, id, out.Available, err); saveErr != nil {
				err = errors.Join(err, fmt.Errorf("record update error: %w", saveErr))
				out.Error = err.Error()
			}
		}
		_, releaseErr := s.db.ExecContext(cleanup, "DELETE FROM pack_update_leases WHERE pack_id=? AND owner=?", id, owner)
		if releaseErr != nil {
			err = errors.Join(err, fmt.Errorf("release update lease: %w", releaseErr))
			out.Error = err.Error()
		}
	}()
	active, healthErr := s.Revision(ctx, id, p.Active)
	if healthErr == nil {
		var local []Override
		local, healthErr = s.Overrides(ctx, id, p.Active)
		if healthErr == nil {
			healthErr = Health(active, local)
		}
	}
	if healthErr != nil {
		if p.Previous == "" {
			return out, fmt.Errorf("installed revision is unhealthy and no fallback is available: %w", healthErr)
		}
		fallback, e := s.activate(ctx, id, "", true, p.Active, true)
		if e != nil {
			return out, errors.Join(healthErr, fmt.Errorf("fallback failed: %w", e))
		}
		out.Status = "rolled-back"
		out.Active, out.Previous = fallback.Active, fallback.Previous
		out.Error = fmt.Sprintf("restored previous revision after local validation failed: %v", healthErr)
		return out, nil
	}
	check, err := s.Check(ctx, id, g, due)
	if err != nil {
		return out, err
	}
	out.Available = check.Available
	if check.Skipped && p.LastError != "" {
		out.Status = "retry-later"
		out.Error = p.LastError
		return out, nil
	}
	if !check.UpdateAvailable {
		out.Status = "up-to-date"
		if check.Skipped {
			out.Status = "skipped"
		}
		return out, nil
	}
	if check.Available == p.RejectedRevision {
		out.Status = "held-after-rollback"
		return out, nil
	}
	// Failed checks use a shorter retry interval; cached failure metadata must not
	// trigger repeated downloads on every command before the next retry is due.
	r, err := s.Revision(ctx, id, check.Available)
	if errors.Is(err, sql.ErrNoRows) {
		r, err = g.Fetch(ctx, p.Repository, check.Available)
	}
	if err != nil {
		return out, err
	}
	if _, err = s.Stage(ctx, r, p.Ref); err != nil {
		return out, err
	}
	os, err := s.Overrides(ctx, id, r.Commit)
	if err != nil {
		return out, err
	}
	if err = Health(r, os); err != nil {
		out.Status = "blocked"
		return out, err
	}
	activated, err := s.activate(ctx, id, r.Commit, false, p.Active, true)
	if err != nil {
		out.Status = "blocked"
		return out, err
	}
	out.Active, out.Previous = activated.Active, activated.Previous
	out.Status = "updated"
	return out, nil
}

// Updates gives each pack its own timeout so one unavailable source does not
// prevent the remaining registered packs from being checked.
func (s *Store) Updates(ctx context.Context, g GitHub, due, timeout time.Duration) ([]UpdateResult, error) {
	items, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := []UpdateResult{}
	failures := []error{}
	for _, item := range items {
		if err = ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		packCtx, cancel := context.WithTimeout(ctx, timeout)
		result, updateErr := s.Update(packCtx, item.ID, g, due)
		cancel()
		out = append(out, result)
		if updateErr != nil {
			failures = append(failures, fmt.Errorf("%s: %w", item.ID, updateErr))
		}
	}
	return out, errors.Join(failures...)
}

// Retain active + one previous revision, a staged candidate, and any revision
// pinned by an engagement. Pinned history is required for reproducible fallback.
func prune(ctx context.Context, tx *sql.Tx, p Pack) error {
	keep := map[string]bool{p.Active: true, p.Previous: true, p.Candidate: true}
	rows, err := tx.QueryContext(ctx, "SELECT body FROM pack_runs")
	if err != nil {
		return err
	}
	for rows.Next() {
		var b []byte
		var run Run
		if err = rows.Scan(&b); err == nil {
			err = json.Unmarshal(b, &run)
		}
		if err != nil {
			rows.Close()
			return err
		}
		if run.PackID == p.ID {
			keep[run.Revision] = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.QueryContext(ctx, "SELECT revision FROM pack_revisions WHERE pack_id=?", p.ID)
	if err != nil {
		return err
	}
	remove := []string{}
	for rows.Next() {
		var sha string
		if err = rows.Scan(&sha); err != nil {
			rows.Close()
			return err
		}
		if !keep[sha] {
			remove = append(remove, sha)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, sha := range remove {
		if _, err = tx.ExecContext(ctx, "DELETE FROM pack_overrides WHERE pack_id=? AND revision=?", p.ID, sha); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM pack_revisions WHERE pack_id=? AND revision=?", p.ID, sha); err != nil {
			return err
		}
	}
	return nil
}
