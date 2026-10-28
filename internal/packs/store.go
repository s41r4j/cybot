package packs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }
type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func Open(filename string) (*Store, error) {
	// Create with restricted permissions before SQLite opens WAL sidecars.
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filename+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS pack_sources(id TEXT PRIMARY KEY, body JSON NOT NULL);
CREATE TABLE IF NOT EXISTS pack_revisions(pack_id TEXT NOT NULL REFERENCES pack_sources(id), revision TEXT NOT NULL, body JSON NOT NULL, PRIMARY KEY(pack_id,revision));
CREATE TABLE IF NOT EXISTS pack_overrides(pack_id TEXT NOT NULL, revision TEXT NOT NULL, phase_id TEXT NOT NULL, body JSON NOT NULL, PRIMARY KEY(pack_id,revision,phase_id), FOREIGN KEY(pack_id,revision) REFERENCES pack_revisions(pack_id,revision));
CREATE TABLE IF NOT EXISTS pack_runs(id TEXT PRIMARY KEY, body JSON NOT NULL);
CREATE TABLE IF NOT EXISTS pack_events(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, pack_id TEXT NOT NULL, action TEXT NOT NULL, revision TEXT NOT NULL);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS pack_update_leases(pack_id TEXT PRIMARY KEY REFERENCES pack_sources(id), owner TEXT NOT NULL, expires_at INTEGER NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func readPack(ctx context.Context, q queryer, id string) (Pack, error) {
	var p Pack
	var b []byte
	if err := q.QueryRowContext(ctx, "SELECT body FROM pack_sources WHERE id=?", id).Scan(&b); err != nil {
		return p, err
	}
	err := json.Unmarshal(b, &p)
	return p, err
}
func readRevision(ctx context.Context, q queryer, id, revision string) (Revision, error) {
	var r Revision
	var b []byte
	if err := q.QueryRowContext(ctx, "SELECT body FROM pack_revisions WHERE pack_id=? AND revision=?", id, revision).Scan(&b); err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	return r, r.Validate()
}
func savePack(ctx context.Context, tx *sql.Tx, p Pack) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO pack_sources(id,body) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET body=excluded.body", p.ID, b)
	return err
}
func event(ctx context.Context, tx *sql.Tx, id, action, revision string) error {
	_, err := tx.ExecContext(ctx, "INSERT INTO pack_events(at,pack_id,action,revision) VALUES(?,?,?,?)", time.Now().UTC().Format(time.RFC3339Nano), id, action, revision)
	return err
}

func (s *Store) Get(ctx context.Context, id string) (Pack, error) { return readPack(ctx, s.db, id) }
func (s *Store) Revision(ctx context.Context, id, revision string) (Revision, error) {
	if revision == "" {
		p, err := s.Get(ctx, id)
		if err != nil {
			return Revision{}, err
		}
		revision = p.Active
	}
	return readRevision(ctx, s.db, id, revision)
}
func (s *Store) List(ctx context.Context) ([]Pack, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT body FROM pack_sources ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Pack{}
	for rows.Next() {
		var p Pack
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Stage commits a complete validated snapshot. Initial installation activates it;
// subsequent imports only stage it, preserving the last working revision.
func (s *Store) Stage(ctx context.Context, r Revision, ref string) (Pack, error) {
	if err := r.Validate(); err != nil {
		return Pack{}, err
	}
	if ref == "" {
		return Pack{}, fmt.Errorf("source ref is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Pack{}, err
	}
	defer tx.Rollback()
	p, err := readPack(ctx, tx, r.PackID)
	initial := errors.Is(err, sql.ErrNoRows)
	if err != nil && !initial {
		return p, err
	}
	if initial {
		p = Pack{ID: r.PackID, Repository: r.Repository, Ref: ref, Active: r.Commit}
	} else if p.Repository != r.Repository || p.Ref != ref {
		return p, fmt.Errorf("source identity/ref differs from installed pack")
	}
	if !initial && p.Active != r.Commit {
		p.Candidate = r.Commit
	} else {
		p.Candidate = ""
	}
	if err = savePack(ctx, tx, p); err != nil {
		return p, err
	}
	old, err := readRevision(ctx, tx, r.PackID, r.Commit)
	if err == nil {
		d := Compare(old, r, nil)
		if len(d.Added)+len(d.Changed)+len(d.Removed) != 0 {
			return p, fmt.Errorf("immutable revision content mismatch")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		b, e := json.Marshal(r)
		if e != nil {
			return p, e
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO pack_revisions(pack_id,revision,body) VALUES(?,?,?)", r.PackID, r.Commit, b); err != nil {
			return p, err
		}
		if !initial {
			if _, err = tx.ExecContext(ctx, "INSERT INTO pack_overrides(pack_id,revision,phase_id,body) SELECT pack_id,?,phase_id,body FROM pack_overrides WHERE pack_id=? AND revision=?", r.Commit, p.ID, p.Active); err != nil {
				return p, err
			}
		}
	} else {
		return p, err
	}
	action := "staged"
	if initial {
		action = "installed"
	}
	if err = event(ctx, tx, p.ID, action, r.Commit); err != nil {
		return p, err
	}
	if err = prune(ctx, tx, p); err != nil {
		return p, err
	}
	return p, tx.Commit()
}

func overrides(ctx context.Context, tx *sql.Tx, id, revision string) ([]Override, error) {
	rows, err := tx.QueryContext(ctx, "SELECT body FROM pack_overrides WHERE pack_id=? AND revision=? ORDER BY phase_id", id, revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Override{}
	for rows.Next() {
		var o Override
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
func (s *Store) Overrides(ctx context.Context, id string, revisions ...string) ([]Override, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	p, err := readPack(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	revision := p.Active
	if len(revisions) > 0 && revisions[0] != "" {
		revision = revisions[0]
	}
	if _, err = readRevision(ctx, tx, id, revision); err != nil {
		return nil, err
	}
	return overrides(ctx, tx, id, revision)
}

func (s *Store) SetOverride(ctx context.Context, id, revision string, o Override) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := readPack(ctx, tx, id)
	if err != nil {
		return err
	}
	if revision == "" {
		revision = p.Active
	}
	r, err := readRevision(ctx, tx, id, revision)
	if err != nil {
		return err
	}
	_, f, err := r.Phase(o.PhaseID)
	if err != nil {
		return err
	}
	if o.BaseHash != "" && o.BaseHash != f.SHA256 {
		return fmt.Errorf("override base hash does not match selected revision")
	}
	if o.Content != nil && (len(*o.Content) > MaxFileBytes || *o.Content == "") {
		return fmt.Errorf("override content must be nonempty and at most 1 MiB")
	}
	o.BaseHash = f.SHA256
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO pack_overrides(pack_id,revision,phase_id,body) VALUES(?,?,?,?) ON CONFLICT(pack_id,revision,phase_id) DO UPDATE SET body=excluded.body", id, revision, o.PhaseID, b); err != nil {
		return err
	}
	if err = event(ctx, tx, id, "override:"+o.PhaseID, revision); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RemoveOverride(ctx context.Context, id, phase string, revisions ...string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := readPack(ctx, tx, id)
	if err != nil {
		return err
	}
	revision := p.Active
	if len(revisions) > 0 && revisions[0] != "" {
		revision = revisions[0]
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM pack_overrides WHERE pack_id=? AND revision=? AND phase_id=?", id, revision, phase)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("override not found")
	}
	if err = event(ctx, tx, id, "remove-override:"+phase, revision); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Diff(ctx context.Context, id, revision string) (Diff, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Diff{}, err
	}
	defer tx.Rollback()
	p, err := readPack(ctx, tx, id)
	if err != nil {
		return Diff{}, err
	}
	if revision == "" {
		revision = p.Candidate
	}
	if revision == "" {
		revision = p.Active
	}
	a, err := readRevision(ctx, tx, id, p.Active)
	if err != nil {
		return Diff{}, err
	}
	b, err := readRevision(ctx, tx, id, revision)
	if err != nil {
		return Diff{}, err
	}
	os, err := overrides(ctx, tx, id, revision)
	if err != nil {
		return Diff{}, err
	}
	return Compare(a, b, os), nil
}

func (s *Store) Activate(ctx context.Context, id, revision string, rollback bool) (Pack, error) {
	return s.activate(ctx, id, revision, rollback, "", false)
}

func (s *Store) activate(ctx context.Context, id, revision string, rollback bool, expected string, automatic bool) (Pack, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Pack{}, err
	}
	defer tx.Rollback()
	p, err := readPack(ctx, tx, id)
	if err != nil {
		return p, err
	}
	if automatic && p.Active != expected {
		return p, fmt.Errorf("active revision changed during update; preserving the newer selection")
	}
	if automatic && revision != "" && p.RejectedRevision == revision {
		return p, fmt.Errorf("revision was rolled back; automatic reactivation is held")
	}
	if rollback {
		revision = p.Previous
	}
	if revision == "" {
		return p, fmt.Errorf("revision is required (or no previous revision exists)")
	}
	r, err := readRevision(ctx, tx, id, revision)
	if err != nil {
		return p, err
	}
	os, err := overrides(ctx, tx, id, revision)
	if err != nil {
		return p, err
	}
	d := Compare(Revision{}, r, os)
	if len(d.Conflicts) > 0 {
		return p, fmt.Errorf("resolve or remove overrides before activation: %v", d.Conflicts)
	}
	if err = Health(r, os); err != nil {
		return p, err
	}
	if p.Active != revision {
		if rollback {
			p.RejectedRevision = p.Active
		} else if !automatic && p.RejectedRevision == revision {
			p.RejectedRevision = ""
		}
		p.Previous, p.Active = p.Active, revision
	}
	if p.Candidate == revision {
		p.Candidate = ""
	}
	if err = savePack(ctx, tx, p); err != nil {
		return p, err
	}
	action := "activated"
	if rollback {
		action = "rolled-back"
	}
	if err = event(ctx, tx, id, action, revision); err != nil {
		return p, err
	}
	if err = prune(ctx, tx, p); err != nil {
		return p, err
	}
	return p, tx.Commit()
}

type RevisionInfo struct {
	Commit     string    `json:"commit"`
	FetchedAt  time.Time `json:"fetched_at"`
	PhaseCount int       `json:"phase_count"`
}

func (s *Store) History(ctx context.Context, id string) ([]RevisionInfo, error) {
	if _, err := s.Get(ctx, id); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT body FROM pack_revisions WHERE pack_id=? ORDER BY rowid DESC", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RevisionInfo{}
	for rows.Next() {
		var r Revision
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		out = append(out, RevisionInfo{r.Commit, r.FetchedAt, len(r.Phases)})
	}
	return out, rows.Err()
}

type Event struct {
	ID       int64  `json:"id"`
	At       string `json:"at"`
	PackID   string `json:"pack_id"`
	Action   string `json:"action"`
	Revision string `json:"revision"`
}

func (s *Store) Events(ctx context.Context, id string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,at,pack_id,action,revision FROM pack_events WHERE pack_id=? ORDER BY id DESC LIMIT 100", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.At, &e.PackID, &e.Action, &e.Revision); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
