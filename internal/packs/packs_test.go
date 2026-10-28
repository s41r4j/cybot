package packs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s41r4j/cybot/internal/capability"
)

const phase0 = "phase-00-recon"
const phase1 = "phase-01-access"

func fixture(t *testing.T, version, content string) Revision {
	t.Helper()
	r, err := NewRevision(BuiltinRepository, strings.Repeat(version, 40), []File{
		{Path: "LICENSE", Content: "MIT fixture"}, {Path: "README.md", Content: "Fixture readme"},
		{Path: "phases/" + phase0 + ".md", Content: "# Recon\nTarget {{target}}; scope {{scope}}\n" + content},
		{Path: "phases/" + phase1 + ".md", Content: "# Access\n{{target}} {{scope}}"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func openFixture(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "packs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func mustStage(t *testing.T, s *Store, r Revision) Pack {
	t.Helper()
	p, err := s.Stage(context.Background(), r, "main")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBundledSnapshotAndCapabilityMappings(t *testing.T) {
	r, err := Bundled()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Phases) != 14 || len(r.Files) != 18 {
		t.Fatalf("unexpected bundled inventory: %d phases / %d files", len(r.Phases), len(r.Files))
	}
	registry := capability.NewRegistry()
	if err := capability.RegisterBuiltins(registry); err != nil {
		t.Fatal(err)
	}
	for _, p := range r.Phases {
		for _, id := range p.Capabilities {
			if _, ok := registry.Get(id); !ok {
				t.Errorf("phase %s maps missing capability %s", p.ID, id)
			}
		}
	}
	p, _, _ := r.Phase("phase-05a-scope")
	if len(p.Dependencies) != 1 || p.Dependencies[0] != "phase-03-closeout" {
		t.Fatalf("optional branches block critical hunt: %+v", p)
	}
	p, _, _ = r.Phase("phase-04b-browser-walk")
	if !p.Optional || p.Dependencies[0] != "phase-04a-scope" {
		t.Fatal("browser branch lacks scope dependency")
	}
}

func TestStagingActivationRollbackAndPersistence(t *testing.T) {
	ctx := context.Background()
	filename := filepath.Join(t.TempDir(), "packs.db")
	s, err := Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	r1, r2 := fixture(t, "a", "first"), fixture(t, "b", "second")
	mustStage(t, s, r1)
	p := mustStage(t, s, r2)
	if p.Active != r1.Commit || p.Candidate != r2.Commit {
		t.Fatalf("sync activated unreviewed candidate: %+v", p)
	}
	d, err := s.Diff(ctx, BuiltinID, "")
	if err != nil || len(d.Changed) != 1 {
		t.Fatalf("diff: %+v %v", d, err)
	}
	p, err = s.Activate(ctx, BuiltinID, r2.Commit, false)
	if err != nil || p.Previous != r1.Commit || p.Candidate != "" {
		t.Fatalf("activate: %+v %v", p, err)
	}
	p, err = s.Activate(ctx, BuiltinID, "", true)
	if err != nil || p.Active != r1.Commit {
		t.Fatalf("rollback: %+v %v", p, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	p, err = s.Get(ctx, BuiltinID)
	if err != nil || p.Active != r1.Commit {
		t.Fatalf("reopen: %+v %v", p, err)
	}
	h, err := s.History(ctx, BuiltinID)
	if err != nil || len(h) != 2 {
		t.Fatalf("history: %v %v", h, err)
	}
	if info, err := os.Stat(filename); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("database permissions: %v %v", info, err)
	}
}

func TestOverrideConflictsAndPinnedEngagement(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	r1 := fixture(t, "a", "old upstream")
	r2 := fixture(t, "b", "new upstream")
	mustStage(t, s, r1)
	local := "Local {{target}} within {{scope}}"
	if err := s.SetOverride(ctx, BuiltinID, "", Override{PhaseID: phase0, Content: &local}); err != nil {
		t.Fatal(err)
	}
	run, err := s.StartRun(ctx, BuiltinID, map[string]string{"target": "lab.example", "scope": "lab.example only"})
	if err != nil {
		t.Fatal(err)
	}
	mustStage(t, s, r2)
	d, err := s.Diff(ctx, BuiltinID, "")
	if err != nil || len(d.Conflicts) != 1 {
		t.Fatalf("conflict: %+v %v", d, err)
	}
	if _, err = s.Activate(ctx, BuiltinID, r2.Commit, false); err == nil {
		t.Fatal("activated conflicting override")
	}
	if err = s.RemoveOverride(ctx, BuiltinID, phase0, r2.Commit); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Activate(ctx, BuiltinID, r2.Commit, false); err != nil {
		t.Fatal(err)
	}
	rendered, err := s.RenderRun(ctx, run.ID, phase0)
	if err != nil {
		t.Fatal(err)
	}
	if rendered.Revision != r1.Commit || !strings.Contains(rendered.Content, "Local lab.example within lab.example only") {
		t.Fatalf("run lost pinned prompt/override: %+v", rendered)
	}
	if !rendered.PlaceholdersResolved {
		t.Fatal(rendered.Unresolved)
	}
}

func TestRevisionValidationAndImmutableContent(t *testing.T) {
	s := openFixture(t)
	r := fixture(t, "a", "old")
	mustStage(t, s, r)
	changed := fixture(t, "a", "modified at same commit")
	if _, err := s.Stage(context.Background(), changed, "main"); err == nil {
		t.Fatal("overwrote immutable revision")
	}
	bad := fixture(t, "b", "bad")
	bad.Files[0].SHA256 = strings.Repeat("0", 64)
	if _, err := s.Stage(context.Background(), bad, "main"); err == nil {
		t.Fatal("accepted corrupt hash")
	}
	r.Files = append(r.Files, File{Path: "../escape.md", Content: "bad", SHA256: Hash("bad")})
	if err := r.Validate(); err == nil {
		t.Fatal("accepted traversal")
	}
	p, err := s.Get(context.Background(), BuiltinID)
	if err != nil || p.Candidate != "" || p.Active != strings.Repeat("a", 40) {
		t.Fatalf("failed update changed state: %+v %v", p, err)
	}
}

func TestCandidateOverrideRebaseAndRollbackIsolation(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	r1, r2 := fixture(t, "a", "first"), fixture(t, "b", "changed")
	mustStage(t, s, r1)
	original, replacement := "original local {{target}} {{scope}}", "updated local {{target}} {{scope}}"
	if err := s.SetOverride(ctx, BuiltinID, r1.Commit, Override{PhaseID: phase0, Content: &original}); err != nil {
		t.Fatal(err)
	}
	mustStage(t, s, r2)
	if err := s.SetOverride(ctx, BuiltinID, r2.Commit, Override{PhaseID: phase0, Content: &replacement}); err != nil {
		t.Fatal(err)
	}
	os, err := s.Overrides(ctx, BuiltinID)
	if err != nil || len(os) != 1 || *os[0].Content != original {
		t.Fatalf("candidate edit changed active override: %+v %v", os, err)
	}
	if _, err = s.Plan(ctx, BuiltinID, ""); err != nil {
		t.Fatal("candidate edit broke active rendering", err)
	}
	if _, err = s.Activate(ctx, BuiltinID, r2.Commit, false); err != nil {
		t.Fatal(err)
	}
	os, err = s.Overrides(ctx, BuiltinID)
	if err != nil || *os[0].Content != replacement {
		t.Fatal("activation lost candidate override", err)
	}
	if _, err = s.Activate(ctx, BuiltinID, "", true); err != nil {
		t.Fatal(err)
	}
	os, err = s.Overrides(ctx, BuiltinID)
	if err != nil || *os[0].Content != original {
		t.Fatal("rollback lost original override", err)
	}
}

func TestAddedAndRemovedPhasesKeepConflictVisible(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	before := fixture(t, "a", "test")
	mustStage(t, s, before)
	local := "local access guidance"
	if err := s.SetOverride(ctx, BuiltinID, "", Override{PhaseID: phase1, Content: &local}); err != nil {
		t.Fatal(err)
	}
	files := []File{}
	for _, f := range before.Files {
		if f.Path != "phases/"+phase1+".md" {
			files = append(files, f)
		}
	}
	files = append(files, File{Path: "phases/phase-11-new-stage.md", Content: "# A new upstream stage"})
	after, err := NewRevision(BuiltinRepository, strings.Repeat("b", 40), files)
	if err != nil {
		t.Fatal(err)
	}
	mustStage(t, s, after)
	d, err := s.Diff(ctx, BuiltinID, "")
	if err != nil || len(d.Added) != 1 || len(d.Removed) != 1 || len(d.Conflicts) != 1 {
		t.Fatalf("lost upstream removal: %+v %v", d, err)
	}
	if _, err = s.Activate(ctx, BuiltinID, after.Commit, false); err == nil {
		t.Fatal("activated deleted override")
	}
	p, _, err := after.Phase("phase-11-new-stage")
	if err != nil || !strings.Contains(strings.Join(p.IntegrationGaps, " "), "no curated CYBOT mapping") {
		t.Fatal("new phase misrepresented", err)
	}
}

func TestFetchRejectsWrongBlobHash(t *testing.T) {
	r := fixture(t, "a", "fixture")
	requests := []string{}
	fixtureClient := githubFixture(r, "", &requests)
	g := GitHub{Get: func(ctx context.Context, u string) ([]byte, error) {
		b, err := fixtureClient.Get(ctx, u)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(u, "https://raw.githubusercontent.com/") {
			b[0] ^= 1
		}
		return b, nil
	}}
	if _, err := g.Fetch(context.Background(), BuiltinRepository, r.Commit); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatal("accepted wrong immutable bytes", err)
	}
}

func TestRenderLiteralValuesAndMissingPlaceholders(t *testing.T) {
	r := fixture(t, "a", "$YOUR_WORKSPACE_ROOT ${YOUR_OTHER:?missing} <YOUR_CDP_HOST> <ACCOUNT_PASSWORD>")
	values := map[string]string{"target": "$(touch /tmp/should-never-run) {{scope}}", "scope": "exact", "YOUR_WORKSPACE_ROOT": "/tmp/work"}
	v, err := Render(r, phase0, values, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.Content, "$(touch /tmp/should-never-run) {{scope}}") {
		t.Fatal("context was recursively evaluated")
	}
	if strings.Join(v.Unresolved, ",") != "ACCOUNT_PASSWORD,YOUR_CDP_HOST,YOUR_OTHER" || v.PlaceholdersResolved {
		t.Fatalf("missing inputs: %v", v.Unresolved)
	}
	if v.RenderedSHA256 != Hash(v.Content) || v.ExecutionMode != "agent-guidance" {
		t.Fatal("invalid rendered provenance")
	}
}

func TestRunHandoffGatesAndEvidenceTampering(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	mustStage(t, s, fixture(t, "a", "test"))
	run, err := s.StartRun(ctx, BuiltinID, map[string]string{"target": "lab.example", "scope": "exact lab.example"})
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "summary.md")
	if err = os.WriteFile(f, []byte("observed local fixture evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := Evidence("phase-summary", f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Evidence("coverage-and-evidence", f)
	entry := PhaseRecord{PhaseID: phase1, Status: "completed", Reason: "fixture", Artifacts: []Artifact{a, b}}
	if _, err = s.Record(ctx, run.ID, entry); err == nil {
		t.Fatal("completed without dependency")
	}
	entry.PhaseID = phase0
	entry.Artifacts = nil
	if _, err = s.Record(ctx, run.ID, entry); err == nil {
		t.Fatal("completed without artifacts")
	}
	entry.Artifacts = []Artifact{a, b}
	if _, err = s.Record(ctx, run.ID, entry); err != nil {
		t.Fatal(err)
	}
	entry.PhaseID = phase1
	if _, err = s.Record(ctx, run.ID, entry); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Record(ctx, run.ID, entry); err == nil {
		t.Fatal("accepted stale evidence hashes")
	}
	run, err = s.Run(ctx, run.ID)
	if err != nil || len(run.Records) != 2 {
		t.Fatalf("bad persisted records: %+v %v", run, err)
	}
	if !strings.Contains(run.Records[1].Attestation, "not certified") {
		t.Fatal("record misrepresents independent verification")
	}
}

func githubFixture(r Revision, failFile string, requests *[]string) GitHub {
	return GitHub{Get: func(_ context.Context, u string) ([]byte, error) {
		*requests = append(*requests, u)
		if strings.Contains(u, "/commits/") {
			return json.Marshal(map[string]string{"sha": r.Commit})
		}
		if strings.Contains(u, "/git/trees/") {
			tree := []map[string]any{}
			for _, f := range r.Files {
				tree = append(tree, map[string]any{"path": f.Path, "type": "blob", "mode": "100644", "size": len(f.Content), "sha": GitBlobHash([]byte(f.Content))})
			}
			return json.Marshal(map[string]any{"tree": tree})
		}
		if !strings.Contains(u, "/"+r.Commit+"/") {
			return nil, fmt.Errorf("unpinned fetch %s", u)
		}
		for _, f := range r.Files {
			if strings.HasSuffix(u, "/"+f.Path) {
				if f.Path == failFile {
					return nil, errors.New("interrupted download")
				}
				return []byte(f.Content), nil
			}
		}
		return nil, fmt.Errorf("unexpected URL %s", u)
	}}
}

func TestGitHubSyncPinnedAndInterruptedDownloadAtomicity(t *testing.T) {
	ctx := context.Background()
	s := openFixture(t)
	r1, r2 := fixture(t, "a", "first"), fixture(t, "b", "second")
	mustStage(t, s, r1)
	requests := []string{}
	g := githubFixture(r2, "phases/"+phase1+".md", &requests)
	if _, err := s.Sync(ctx, BuiltinID, g); err == nil {
		t.Fatal("accepted partial download")
	}
	p, err := s.Get(ctx, BuiltinID)
	if err != nil || p.Active != r1.Commit || p.Candidate != "" || p.LastError == "" {
		t.Fatalf("partial fetch modified working revision: %+v %v", p, err)
	}
	h, _ := s.History(ctx, BuiltinID)
	if len(h) != 1 {
		t.Fatal("partial revision persisted")
	}
	g = githubFixture(r2, "", &requests)
	p, err = s.Sync(ctx, BuiltinID, g)
	if err != nil || p.Active != r1.Commit || p.Candidate != r2.Commit {
		t.Fatalf("sync: %+v %v", p, err)
	}
	before := len(requests)
	if _, err = s.Sync(ctx, BuiltinID, g); err != nil {
		t.Fatal(err)
	}
	if len(requests) != before+1 {
		t.Fatal("repeat sync downloaded an immutable stored revision again")
	}
	check, err := s.Check(ctx, BuiltinID, g, 24*time.Hour)
	if err != nil || !check.Skipped || !check.UpdateAvailable {
		t.Fatalf("due check: %+v %v", check, err)
	}
}

func TestGitHubRejectsMalformedTreesAndRefs(t *testing.T) {
	for _, body := range []string{`{"truncated":true}`, `{"tree":[{"path":"phases/phase-00-recon.md","mode":"120000","type":"blob","size":8}]}`, `{"tree":[{"path":"README.md","mode":"100644","type":"blob","size":99999999}]}`} {
		g := GitHub{Get: func(context.Context, string) ([]byte, error) { return []byte(body), nil }}
		if _, err := g.Fetch(context.Background(), BuiltinRepository, strings.Repeat("a", 40)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	for _, repo := range []string{"https://evil.example/a/b", "../repo", "a/../b", "owner/repo?x=1"} {
		if _, err := Repository(repo); err == nil {
			t.Errorf("accepted %s", repo)
		}
	}
	g := GitHub{Get: func(context.Context, string) ([]byte, error) {
		t.Fatal("network called for mutable commit")
		return nil, nil
	}}
	if _, err := g.Fetch(context.Background(), BuiltinRepository, "main"); err == nil {
		t.Fatal("accepted mutable file fetch")
	}
}
