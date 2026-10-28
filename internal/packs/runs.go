package packs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Artifact struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type PhaseRecord struct {
	PhaseID     string     `json:"phase_id"`
	Status      string     `json:"status"`
	Reason      string     `json:"reason"`
	Artifacts   []Artifact `json:"artifacts"`
	At          time.Time  `json:"at"`
	Attestation string     `json:"attestation"`
}
type Run struct {
	ID        string            `json:"id"`
	PackID    string            `json:"pack_id"`
	Revision  string            `json:"revision"`
	StartedAt time.Time         `json:"started_at"`
	Context   map[string]string `json:"context"`
	Overrides []Override        `json:"overrides"`
	Records   []PhaseRecord     `json:"records"`
}

func (s *Store) StartRun(ctx context.Context, id string, values map[string]string) (Run, error) {
	if strings.TrimSpace(values["target"]) == "" || strings.TrimSpace(values["scope"]) == "" {
		return Run{}, fmt.Errorf("engagement context requires target and explicit scope")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, err
	}
	defer tx.Rollback()
	p, err := readPack(ctx, tx, id)
	if err != nil {
		return Run{}, err
	}
	r, err := readRevision(ctx, tx, id, p.Active)
	if err != nil {
		return Run{}, err
	}
	os, err := overrides(ctx, tx, id, r.Commit)
	if err != nil {
		return Run{}, err
	}
	if d := Compare(Revision{}, r, os); len(d.Conflicts) > 0 {
		return Run{}, fmt.Errorf("override conflicts: %v", d.Conflicts)
	}
	run := Run{ID: uuid.NewString(), PackID: id, Revision: r.Commit, StartedAt: time.Now().UTC(), Context: values, Overrides: os, Records: []PhaseRecord{}}
	b, err := json.Marshal(run)
	if err != nil {
		return run, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO pack_runs(id,body) VALUES(?,?)", run.ID, b); err != nil {
		return run, err
	}
	if err = event(ctx, tx, id, "run-started:"+run.ID, r.Commit); err != nil {
		return run, err
	}
	return run, tx.Commit()
}

func readRun(ctx context.Context, q queryer, id string) (Run, error) {
	var run Run
	var b []byte
	if err := q.QueryRowContext(ctx, "SELECT body FROM pack_runs WHERE id=?", id).Scan(&b); err != nil {
		return run, err
	}
	err := json.Unmarshal(b, &run)
	return run, err
}
func (s *Store) Run(ctx context.Context, id string) (Run, error) { return readRun(ctx, s.db, id) }
func (s *Store) RenderRun(ctx context.Context, id, phase string) (Rendered, error) {
	run, err := s.Run(ctx, id)
	if err != nil {
		return Rendered{}, err
	}
	r, err := s.Revision(ctx, run.PackID, run.Revision)
	if err != nil {
		return Rendered{}, err
	}
	return Render(r, phase, run.Context, run.Overrides)
}

func Evidence(name, filename string) (Artifact, error) {
	if strings.TrimSpace(name) == "" {
		return Artifact{}, fmt.Errorf("artifact name is required")
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return Artifact{}, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return Artifact{}, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > MaxPackBytes {
		return Artifact{}, fmt.Errorf("artifact must be a nonempty regular file at most 8 MiB")
	}
	f, err := os.Open(abs)
	if err != nil {
		return Artifact{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxPackBytes+1))
	if err != nil {
		return Artifact{}, err
	}
	if len(b) > MaxPackBytes {
		return Artifact{}, fmt.Errorf("artifact too large")
	}
	return Artifact{Name: name, Path: abs, SHA256: Hash(string(b))}, nil
}

func (s *Store) Record(ctx context.Context, id string, record PhaseRecord) (Run, error) {
	if record.Status != "completed" && record.Status != "partial" && record.Status != "blocked" && record.Status != "skipped" {
		return Run{}, fmt.Errorf("status must be completed, partial, blocked or skipped")
	}
	if strings.TrimSpace(record.Reason) == "" {
		return Run{}, fmt.Errorf("a reason is required")
	}
	// Hash the current files inside the backend as well as at the CLI boundary.
	seen := map[string]bool{}
	for i, a := range record.Artifacts {
		if seen[a.Name] {
			return Run{}, fmt.Errorf("duplicate artifact name %s", a.Name)
		}
		seen[a.Name] = true
		verified, err := Evidence(a.Name, a.Path)
		if err != nil {
			return Run{}, err
		}
		if a.SHA256 != "" && a.SHA256 != verified.SHA256 {
			return Run{}, fmt.Errorf("artifact changed: %s", a.Name)
		}
		record.Artifacts[i] = verified
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Run{}, err
	}
	defer tx.Rollback()
	run, err := readRun(ctx, tx, id)
	if err != nil {
		return run, err
	}
	r, err := readRevision(ctx, tx, run.PackID, run.Revision)
	if err != nil {
		return run, err
	}
	p, _, err := effective(r, record.PhaseID, run.Overrides)
	if err != nil {
		return run, err
	}
	if record.Status == "skipped" && !p.Optional {
		return run, fmt.Errorf("required phase cannot be skipped; record blocked or partial with its reason")
	}
	if record.Status == "completed" {
		latest := map[string]string{}
		for _, v := range run.Records {
			latest[v.PhaseID] = v.Status
		}
		for _, dep := range p.Dependencies {
			if latest[dep] != "completed" {
				return run, fmt.Errorf("dependency %s is not completed", dep)
			}
		}
		for _, name := range p.ExpectedArtifacts {
			if !seen[name] {
				return run, fmt.Errorf("completed phase requires artifact %q", name)
			}
		}
	}
	record.At = time.Now().UTC()
	record.Attestation = "operator-recorded; independent verification not certified"
	if record.Artifacts == nil {
		record.Artifacts = []Artifact{}
	}
	run.Records = append(run.Records, record)
	b, err := json.Marshal(run)
	if err != nil {
		return run, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE pack_runs SET body=? WHERE id=?", b, id); err != nil {
		return run, err
	}
	if err = event(ctx, tx, run.PackID, "phase-recorded:"+id+":"+record.PhaseID+":"+record.Status, run.Revision); err != nil {
		return run, err
	}
	return run, tx.Commit()
}
