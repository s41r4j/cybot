package memory

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/s41r4j/cybot/pkg/schema"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err = s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) migrate(ctx context.Context) error {
	const q = `
CREATE TABLE IF NOT EXISTS skills(id TEXT PRIMARY KEY, body JSON NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tools(id TEXT PRIMARY KEY, body JSON NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, capability TEXT NOT NULL, target TEXT, status TEXT NOT NULL, body JSON NOT NULL, started_at TEXT NOT NULL, finished_at TEXT);
CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, type TEXT NOT NULL, path TEXT, sha256 TEXT NOT NULL, body JSON NOT NULL);
CREATE TABLE IF NOT EXISTS findings(id TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, severity TEXT NOT NULL, body JSON NOT NULL, PRIMARY KEY(id,run_id));
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, body JSON NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, run_id TEXT REFERENCES runs(id), body JSON NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS engagement_memory(target TEXT NOT NULL, capability TEXT NOT NULL, status TEXT NOT NULL, findings INTEGER NOT NULL DEFAULT 0, last_run_at TEXT, PRIMARY KEY(target,capability));`
	_, err := s.db.ExecContext(ctx, q)
	return err
}
func (s *Store) SaveResult(ctx context.Context, r schema.Result) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO runs(id,capability,target,status,body,started_at,finished_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,body=excluded.body,finished_at=excluded.finished_at`, r.RunID, r.Capability, r.Target, r.Status, body, r.StartedAt.Format(time.RFC3339Nano), r.FinishedAt.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	for _, e := range r.Evidence {
		b, _ := json.Marshal(e)
		if _, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO artifacts(id,run_id,type,path,sha256,body) VALUES(?,?,?,?,?,?)`, e.ID, r.RunID, e.Type, e.Path, e.SHA256, b); err != nil {
			return err
		}
	}
	for _, f := range r.Findings {
		b, _ := json.Marshal(f)
		if _, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO findings(id,run_id,severity,body) VALUES(?,?,?,?)`, f.ID, r.RunID, f.Severity, b); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO engagement_memory(target,capability,status,findings,last_run_at) VALUES(?,?,?,?,?) ON CONFLICT(target,capability) DO UPDATE SET status=excluded.status,findings=excluded.findings,last_run_at=excluded.last_run_at`, r.Target, r.Capability, r.Status, len(r.Findings), r.FinishedAt.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Result(ctx context.Context, id string) (schema.Result, error) {
	var b []byte
	if err := s.db.QueryRowContext(ctx, `SELECT body FROM runs WHERE id=?`, id).Scan(&b); err != nil {
		return schema.Result{}, err
	}
	var r schema.Result
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("decode run: %w", err)
	}
	return r, nil
}
func (s *Store) Results(ctx context.Context, limit int) ([]schema.Result, error) {
	if limit < 1 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT body FROM runs ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []schema.Result{}
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var r schema.Result
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) UpsertSkill(ctx context.Context, v schema.Skill) error {
	return s.upsert(ctx, "skills", v.ID, v)
}
func (s *Store) UpsertTool(ctx context.Context, v schema.Tool) error {
	return s.upsert(ctx, "tools", v.ID, v)
}
func (s *Store) Skills(ctx context.Context) ([]schema.Skill, error) {
	var out []schema.Skill
	return out, s.list(ctx, "skills", func(b []byte) error {
		var v schema.Skill
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		out = append(out, v)
		return nil
	})
}
func (s *Store) Tools(ctx context.Context) ([]schema.Tool, error) {
	var out []schema.Tool
	return out, s.list(ctx, "tools", func(b []byte) error {
		var v schema.Tool
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		out = append(out, v)
		return nil
	})
}
func (s *Store) list(ctx context.Context, table string, decode func([]byte) error) error {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("SELECT body FROM %s ORDER BY id", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return err
		}
		if err := decode(b); err != nil {
			return err
		}
	}
	return rows.Err()
}
func (s *Store) upsert(ctx context.Context, table, id string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	q := fmt.Sprintf("INSERT INTO %s(id,body,updated_at) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body,updated_at=excluded.updated_at", table)
	_, err = s.db.ExecContext(ctx, q, id, b, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) RecordEngagementMemory(ctx context.Context, target, capability, status string, findings int) error {
	q := `INSERT INTO engagement_memory(target,capability,status,findings,last_run_at) VALUES(?,?,?,?,?) ON CONFLICT(target,capability) DO UPDATE SET status=excluded.status,findings=excluded.findings,last_run_at=excluded.last_run_at`
	_, err := s.db.ExecContext(ctx, q, target, capability, status, findings, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) EngagementMemory(ctx context.Context, target string) ([]schema.MemoryEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target,capability,status,findings,COALESCE(last_run_at,'') FROM engagement_memory WHERE target=? ORDER BY last_run_at DESC`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []schema.MemoryEntry{}
	for rows.Next() {
		var e schema.MemoryEntry
		var ts string
		if err := rows.Scan(&e.Target, &e.Capability, &e.Status, &e.Findings, &ts); err != nil {
			return nil, err
		}
		if ts != "" {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				e.LastRunAt = t
			}
		}
		e.EstimateSkip = e.Status == "completed" && e.Findings == 0
		if e.EstimateSkip {
			e.SkipReason = "previously explored with zero findings on this target stack"
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) AllEngagementTargets(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT target FROM engagement_memory ORDER BY target`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
