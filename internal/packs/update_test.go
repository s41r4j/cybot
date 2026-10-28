package packs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAutoUpdateRetentionAndRollbackHold(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	r1 := fixture(t, "a", "first")
	mustStage(t, s, r1)
	for _, v := range []string{"b", "c", "d"} {
		r := fixture(t, v, "new "+v)
		requests := []string{}
		out, err := s.Update(ctx, BuiltinID, githubFixture(r, "", &requests), 0)
		if err != nil || out.Status != "updated" || out.Active != r.Commit {
			t.Fatalf("update: %+v %v", out, err)
		}
		h, err := s.History(ctx, BuiltinID)
		if err != nil || len(h) != 2 {
			t.Fatalf("expected active + one previous: %+v %v", h, err)
		}
	}
	p, err := s.Activate(ctx, BuiltinID, "", true)
	if err != nil || p.Active != strings.Repeat("c", 40) || p.RejectedRevision != strings.Repeat("d", 40) {
		t.Fatalf("rollback: %+v %v", p, err)
	}
	requests := []string{}
	out, err := s.Update(ctx, BuiltinID, githubFixture(fixture(t, "d", "new d"), "", &requests), 0)
	if err != nil || out.Status != "held-after-rollback" || len(requests) != 1 {
		t.Fatalf("rollback was undone: %+v %v", out, err)
	}
	out, err = s.Update(ctx, BuiltinID, githubFixture(fixture(t, "e", "fixed upstream"), "", &requests), 0)
	if err != nil || out.Status != "updated" || out.Previous != strings.Repeat("c", 40) {
		t.Fatalf("next upstream fix: %+v %v", out, err)
	}
}

func TestRetentionPreservesPinnedEngagement(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	r1 := fixture(t, "a", "first")
	mustStage(t, s, r1)
	run, err := s.StartRun(ctx, BuiltinID, map[string]string{"target": "lab.example", "scope": "lab.example only"})
	if err != nil {
		t.Fatal(err)
	}
	requests := []string{}
	for _, v := range []string{"b", "c", "d"} {
		if _, err = s.Update(ctx, BuiltinID, githubFixture(fixture(t, v, "new "+v), "", &requests), 0); err != nil {
			t.Fatal(err)
		}
	}
	h, err := s.History(ctx, BuiltinID)
	if err != nil || len(h) != 3 {
		t.Fatalf("pinned + active + previous: %+v %v", h, err)
	}
	rendered, err := s.RenderRun(ctx, run.ID, phase0)
	if err != nil || rendered.Revision != r1.Commit {
		t.Fatal("pinned revision pruned", err)
	}
	if _, err = s.Revision(ctx, BuiltinID, strings.Repeat("b", 40)); err == nil {
		t.Fatal("unreferenced history retained")
	}
}

func TestUpdateConflictAndRetryBackoff(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	r1, r2 := fixture(t, "a", "first"), fixture(t, "b", "changed")
	mustStage(t, s, r1)
	local := "local {{target}} {{scope}}"
	if err := s.SetOverride(ctx, BuiltinID, "", Override{PhaseID: phase0, Content: &local}); err != nil {
		t.Fatal(err)
	}
	requests := []string{}
	g := githubFixture(r2, "", &requests)
	out, err := s.Update(ctx, BuiltinID, g, 0)
	if err == nil || out.Status != "blocked" {
		t.Fatalf("conflict activated: %+v %v", out, err)
	}
	p, _ := s.Get(ctx, BuiltinID)
	if p.Active != r1.Commit || p.Candidate != r2.Commit || p.LastError == "" {
		t.Fatal("conflict lost working revision", p)
	}
	n := len(requests)
	out, err = s.Update(ctx, BuiltinID, g, 24*time.Hour)
	if err != nil || out.Status != "retry-later" || len(requests) != n {
		t.Fatalf("failed update hammered source: %+v %v", out, err)
	}
	if err = s.SetOverride(ctx, BuiltinID, r2.Commit, Override{PhaseID: phase0, Content: &local}); err != nil {
		t.Fatal(err)
	}
	out, err = s.Update(ctx, BuiltinID, g, 0)
	if err != nil || out.Status != "updated" {
		t.Fatalf("resolved conflict: %+v %v", out, err)
	}
}

func TestInterruptedAutomaticUpdateKeepsWorkingVersion(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	r1, r2 := fixture(t, "a", "first"), fixture(t, "b", "changed")
	mustStage(t, s, r1)
	requests := []string{}
	out, err := s.Update(ctx, BuiltinID, githubFixture(r2, "phases/"+phase1+".md", &requests), 0)
	if err == nil || out.Status != "failed" {
		t.Fatal("accepted interrupted download", out, err)
	}
	p, _ := s.Get(ctx, BuiltinID)
	h, _ := s.History(ctx, BuiltinID)
	if p.Active != r1.Commit || p.Candidate != "" || len(h) != 1 {
		t.Fatalf("failed update changed snapshots: %+v %+v", p, h)
	}
}

func TestUnhealthyActiveAutomaticallyFallsBack(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	r1, r2 := fixture(t, "a", "first"), fixture(t, "b", "new")
	mustStage(t, s, r1)
	mustStage(t, s, r2)
	if _, err := s.Activate(ctx, BuiltinID, r2.Commit, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE pack_revisions SET body=? WHERE pack_id=? AND revision=?", `{"corrupt":true}`, BuiltinID, r2.Commit); err != nil {
		t.Fatal(err)
	}
	g := GitHub{Get: func(context.Context, string) ([]byte, error) {
		t.Fatal("fallback should precede network")
		return nil, nil
	}}
	out, err := s.Update(ctx, BuiltinID, g, 0)
	if err != nil || out.Status != "rolled-back" || out.Active != r1.Commit {
		t.Fatalf("automatic fallback: %+v %v", out, err)
	}
	p, _ := s.Get(ctx, BuiltinID)
	if p.RejectedRevision != r2.Commit {
		t.Fatal("bad active not held after fallback")
	}
}

func TestUpdateLeaseAcrossProcessesAndExpiry(t *testing.T) {
	ctx := context.Background()
	file := filepath.Join(t.TempDir(), "packs.db")
	a, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	mustStage(t, a, fixture(t, "a", "first"))
	b, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	owner, ok, err := a.acquireUpdate(ctx, BuiltinID)
	if err != nil || !ok {
		t.Fatal("acquire", err)
	}
	g := GitHub{Get: func(context.Context, string) ([]byte, error) { t.Fatal("competing updater fetched"); return nil, nil }}
	out, err := b.Update(ctx, BuiltinID, g, 0)
	if err != nil || out.Status != "locked" {
		t.Fatal("lease did not serialize updaters", out, err)
	}
	if _, err = a.db.Exec("UPDATE pack_update_leases SET expires_at=0 WHERE owner=?", owner); err != nil {
		t.Fatal(err)
	}
	requests := []string{}
	out, err = b.Update(ctx, BuiltinID, githubFixture(fixture(t, "b", "next"), "", &requests), 0)
	if err != nil || out.Status != "updated" {
		t.Fatal("expired lease blocked recovery", out, err)
	}
}

func TestManualRollbackWinsRaceWithUpdate(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	r1, r2, r3 := fixture(t, "a", "first"), fixture(t, "b", "second"), fixture(t, "c", "third")
	mustStage(t, s, r1)
	mustStage(t, s, r2)
	if _, err := s.Activate(ctx, BuiltinID, r2.Commit, false); err != nil {
		t.Fatal(err)
	}
	requests := []string{}
	base := githubFixture(r3, "", &requests)
	rolledBack := false
	g := GitHub{Get: func(ctx context.Context, u string) ([]byte, error) {
		if !rolledBack && strings.HasPrefix(u, "https://raw.githubusercontent.com/") {
			rolledBack = true
			if _, err := s.Activate(ctx, BuiltinID, "", true); err != nil {
				t.Fatal(err)
			}
		}
		return base.Get(ctx, u)
	}}
	if _, err := s.Update(ctx, BuiltinID, g, 0); err == nil {
		t.Fatal("updater overwrote concurrent manual rollback")
	}
	p, _ := s.Get(ctx, BuiltinID)
	if p.Active != r1.Commit {
		t.Fatal("lost manual rollback", p)
	}
}

func TestBundleInstallDoesNotClaimAnUpstreamCheck(t *testing.T) {
	s := openFixture(t)
	p := mustStage(t, s, fixture(t, "a", "bundled"))
	if !p.CheckedAt.IsZero() || p.Available != "" {
		t.Fatal("offline installation claims latest upstream", p)
	}
}

func TestPromptAndSkillLayouts(t *testing.T) {
	r, err := NewRevision("example/prompt-library", strings.Repeat("a", 40), []File{{Path: "LICENSE.md", Content: "MIT"}, {Path: "prompts/review/code.md", Content: "# Code review\n{{target}}"}, {Path: "skills/security/SKILL.md", Content: "---\nname: security\n---\n# Security skill"}})
	if err != nil || len(r.Phases) != 2 {
		t.Fatalf("generic layouts: %+v %v", r.Phases, err)
	}
	for _, p := range r.Phases {
		if len(p.Dependencies) != 0 {
			t.Fatal("independent skills were serialized")
		}
	}
	requests := []string{}
	got, err := githubFixture(r, "", &requests).Fetch(context.Background(), r.Repository, r.Commit)
	if err != nil || len(got.Phases) != 2 {
		t.Fatal("generic GitHub fetch", err)
	}
}

func TestManifestDefinesActualGraphAndMappings(t *testing.T) {
	m := Manifest{SchemaVersion: 1, Phases: []Phase{{ID: "discover", Path: "guides/start.md", Capabilities: []string{"asset.discover"}}, {ID: "review", Path: "guides/check.md", Dependencies: []string{"discover"}, Capabilities: []string{"web.map"}}}, Documents: []string{"docs/context.md"}}
	b, _ := json.Marshal(m)
	files := []File{{Path: ManifestPath, Content: string(b)}, {Path: "LICENSE", Content: "MIT"}, {Path: "guides/start.md", Content: "# Start\n{{target}} {{scope}}"}, {Path: "guides/check.md", Content: "# Check"}, {Path: "docs/context.md", Content: "# Context"}}
	r, err := NewRevision("example/custom-workflow", strings.Repeat("a", 40), files)
	if err != nil {
		t.Fatal(err)
	}
	if err = Health(r, nil); err != nil {
		t.Fatal(err)
	}
	if r.Phases[1].Dependencies[0] != "discover" || r.Phases[0].Capabilities[0] != "asset.discover" {
		t.Fatal("manifest graph lost")
	}
	requests := []string{}
	fetched, err := githubFixture(r, "", &requests).Fetch(context.Background(), r.Repository, r.Commit)
	if err != nil || len(fetched.Files) != 5 {
		t.Fatal("manifest fetch", err)
	}
	r.Phases[0].Capabilities = []string{"web.scan"}
	if err = r.Validate(); err == nil {
		t.Fatal("accepted metadata differing from original manifest")
	}
}

func TestMalformedManifestPathsDependenciesAndUnknownMappings(t *testing.T) {
	for _, raw := range []string{`{"schema_version":99,"phases":[{"id":"a","path":"prompts/a.md"}]}`, `{"schema_version":1,"phases":[{"id":"a","path":"../escape.md"}]}`, `{"schema_version":1,"phases":[{"id":"a","path":"a.md","dependencies":["b"]},{"id":"b","path":"b.md"}]}`, `{"schema_version":1,"phases":[{"id":"a","path":"a.md","command":"sh"}]}`} {
		if _, err := parseManifest(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	m := Manifest{SchemaVersion: 1, Phases: []Phase{{ID: "bad", Path: "prompts/a.md", Capabilities: []string{"unknown.raw"}}}}
	b, _ := json.Marshal(m)
	r, err := NewRevision("example/library", strings.Repeat("a", 40), []File{{Path: "LICENSE", Content: "MIT"}, {Path: ManifestPath, Content: string(b)}, {Path: "prompts/a.md", Content: "# A"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = Health(r, nil); err == nil {
		t.Fatal("health accepted nonexistent capability")
	}
}

func TestUpdateMigrationKeepsExistingDatabaseAndOverrides(t *testing.T) {
	file := filepath.Join(t.TempDir(), "packs.db")
	s, err := Open(file)
	if err != nil {
		t.Fatal(err)
	}
	p := mustStage(t, s, fixture(t, "a", "old"))
	local := "old local"
	if err = s.SetOverride(context.Background(), p.ID, "", Override{PhaseID: phase0, Content: &local}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DROP TABLE pack_update_leases"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	localOverrides, err := s.Overrides(context.Background(), p.ID)
	if err != nil || len(localOverrides) != 1 || *localOverrides[0].Content != local {
		t.Fatal("migration lost data", err)
	}
	if info, err := os.Stat(file); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("database permissions changed", err)
	}
}
