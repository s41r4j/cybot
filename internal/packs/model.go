// Package packs manages immutable upstream prompt revisions and local adaptations.
// Prompt text is data: this package never executes commands found in a prompt.
package packs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const BuiltinID = "mdpsec-bounty"
const BuiltinRepository = "mdpsec/bug-bounty-hunting-prompts"
const AdapterVersion = 1
const MaxFileBytes = 1 << 20
const MaxPackBytes = 8 << 20

var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var commitPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)
var phasePattern = regexp.MustCompile(`^phases/phase-[0-9]{2}[a-z]?-[a-z0-9-]+\.md$`)

type Pack struct {
	ID               string    `json:"id"`
	Repository       string    `json:"repository"`
	Ref              string    `json:"ref"`
	Active           string    `json:"active_revision"`
	Previous         string    `json:"previous_revision,omitempty"`
	Candidate        string    `json:"candidate_revision,omitempty"`
	Available        string    `json:"available_revision,omitempty"`
	CheckedAt        time.Time `json:"checked_at"`
	LastError        string    `json:"last_error,omitempty"`
	RejectedRevision string    `json:"rejected_revision,omitempty"`
}

type File struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Content string `json:"content"`
}

type Phase struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Path              string   `json:"path"`
	Dependencies      []string `json:"dependencies"`
	Capabilities      []string `json:"capabilities"`
	RequiredInputs    []string `json:"required_inputs"`
	ExpectedArtifacts []string `json:"expected_artifacts"`
	IntegrationGaps   []string `json:"integration_gaps"`
	Optional          bool     `json:"optional"`
}

type Revision struct {
	PackID         string    `json:"pack_id"`
	Repository     string    `json:"repository"`
	Commit         string    `json:"commit"`
	FetchedAt      time.Time `json:"fetched_at"`
	AdapterVersion int       `json:"adapter_version"`
	Files          []File    `json:"files"`
	Phases         []Phase   `json:"phases"`
}

type Override struct {
	PhaseID      string    `json:"phase_id"`
	BaseHash     string    `json:"base_sha256"`
	Content      *string   `json:"content,omitempty"`
	Capabilities *[]string `json:"capabilities,omitempty"`
}

type Diff struct {
	PackID    string   `json:"pack_id"`
	From      string   `json:"from"`
	To        string   `json:"to"`
	Added     []string `json:"added"`
	Changed   []string `json:"changed"`
	Removed   []string `json:"removed"`
	Conflicts []string `json:"conflicts"`
}

func Repository(value string) (string, error) {
	value = strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(value, "https://github.com/"), "/"), ".git")
	if !repoPattern.MatchString(value) {
		return "", fmt.Errorf("expected a GitHub owner/repository")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." {
			return "", fmt.Errorf("invalid repository")
		}
	}
	return strings.ToLower(value), nil
}

func ID(repository string) string {
	if repository == BuiltinRepository {
		return BuiltinID
	}
	return strings.ReplaceAll(repository, "/", "--")
}

func Hash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func allowedFile(p string) bool {
	return safeSourcePath(p) && (p == ManifestPath || p == "README.md" || p == "ADAPTATION.md" || p == "SECURITY.md" || licensePath(p) || promptPath(p))
}

func NewRevision(repository, commit string, files []File) (Revision, error) {
	r := Revision{PackID: ID(repository), Repository: repository, Commit: commit, FetchedAt: time.Now().UTC(), AdapterVersion: AdapterVersion, Files: files, Phases: []Phase{}}
	sort.Slice(r.Files, func(i, j int) bool { return r.Files[i].Path < r.Files[j].Path })
	m, err := manifestIn(r.Files)
	if err != nil {
		return r, err
	}
	for i := range r.Files {
		f := &r.Files[i]
		f.SHA256 = Hash(f.Content)
		if m != nil || !promptPath(f.Path) {
			continue
		}
		p := defaultPhase(*f)
		if repository == BuiltinRepository {
			adapt(&p)
		} else {
			p.IntegrationGaps = append(p.IntegrationGaps, "No curated CYBOT mapping; guidance only.")
		}
		r.Phases = append(r.Phases, p)
	}
	if m != nil {
		for _, p := range m.Phases {
			r.Phases = append(r.Phases, normalizePhase(p))
		}
		return r, r.Validate()
	}
	// Order is explicit in the persisted manifest. Optional browser branches do
	// not become mandatory dependencies for the critical-hunt branch.
	previous := ""
	for i := range r.Phases {
		if previous != "" && phasePattern.MatchString(r.Phases[i].Path) {
			r.Phases[i].Dependencies = []string{previous}
		}
		if r.Phases[i].ID == "phase-04b-browser-walk" && repository == BuiltinRepository {
			r.Phases[i].Dependencies = []string{"phase-04a-scope"}
		}
		if !r.Phases[i].Optional {
			previous = r.Phases[i].ID
		}
	}
	return r, r.Validate()
}

func adapt(p *Phase) {
	switch p.ID {
	case "phase-00-recon":
		p.Capabilities = []string{"asset.discover", "web.map", "js.analyse"}
	case "phase-01-access":
		p.Capabilities = []string{"web.browse"}
		p.IntegrationGaps = append(p.IntegrationGaps, "Researcher accounts, mailbox/MFA and browser lease management.")
	case "phase-02-sweep":
		p.Capabilities = []string{"web.map", "web.scan", "api.audit"}
		p.IntegrationGaps = append(p.IntegrationGaps, "Endpoint eligibility ledger and 47-row coverage validator.")
	case "phase-03-closeout":
		p.IntegrationGaps = append(p.IntegrationGaps, "Resource lease cleanup and sweep handoff validation.")
	case "phase-04a-scope":
		p.Optional = true
	case "phase-04b-browser-walk":
		p.Optional = true
		p.Capabilities = []string{"web.browse", "web.har"}
	case "phase-05a-scope":
	case "phase-05b-critical":
		p.Capabilities = []string{"web.scan", "api.audit"}
		p.IntegrationGaps = append(p.IntegrationGaps, "Agent-led hypothesis testing and controlled proof runtime.")
	case "phase-06-triage", "phase-07-validate-escalate", "phase-08-verify-escalate", "phase-08a-independent-escalation", "phase-09-triage-gate", "phase-10-self-duplicate-check":
		p.IntegrationGaps = append(p.IntegrationGaps, "Independent live evidence review and report/duplicate validation; no automatic verification claim.")
	default:
		p.IntegrationGaps = append(p.IntegrationGaps, "New upstream phase has no curated CYBOT mapping; guidance only.")
	}
}

func (r Revision) Validate() error {
	repo, err := Repository(r.Repository)
	if err != nil || repo != r.Repository || r.PackID != ID(repo) || !commitPattern.MatchString(r.Commit) || r.AdapterVersion != AdapterVersion {
		return fmt.Errorf("invalid pack provenance or adapter version")
	}
	seen := map[string]bool{}
	total := 0
	m, err := manifestIn(r.Files)
	if err != nil {
		return err
	}
	declared := declaredFiles(m)
	hasLicense := false
	for _, f := range r.Files {
		if (!allowedFile(f.Path) && !declared[f.Path]) || seen[f.Path] || f.Content == "" || len(f.Content) > MaxFileBytes || f.SHA256 != Hash(f.Content) {
			return fmt.Errorf("invalid pack file %q", f.Path)
		}
		seen[f.Path] = true
		if licensePath(f.Path) {
			hasLicense = true
		}
		total += len(f.Content)
	}
	if total > MaxPackBytes || len(r.Files) > 128 || !hasLicense || len(r.Phases) == 0 {
		return fmt.Errorf("pack requires a root license and prompts within size limits")
	}
	for p := range declared {
		if !seen[p] {
			return fmt.Errorf("manifest file %q is missing", p)
		}
	}
	phaseIDs := map[string]bool{}
	phasePaths := map[string]bool{}
	for _, p := range r.Phases {
		if !phaseIDPattern.MatchString(p.ID) || !markdownPath(p.Path) || !seen[p.Path] || phaseIDs[p.ID] || phasePaths[p.Path] {
			return fmt.Errorf("invalid phase %q", p.ID)
		}
		for _, dep := range p.Dependencies {
			if !phaseIDs[dep] {
				return fmt.Errorf("invalid phase dependency %q", dep)
			}
		}
		phaseIDs[p.ID] = true
		phasePaths[p.Path] = true
	}
	if m != nil {
		if len(m.Phases) != len(r.Phases) {
			return fmt.Errorf("manifest phase count mismatch")
		}
		for i, p := range m.Phases {
			if !reflect.DeepEqual(normalizePhase(p), r.Phases[i]) {
				return fmt.Errorf("manifest phase identity mismatch")
			}
		}
	}
	for name := range seen {
		if m == nil && promptPath(name) && !phasePaths[name] {
			return fmt.Errorf("unmapped phase %q", name)
		}
	}
	return nil
}

func (r Revision) Phase(id string) (Phase, File, error) {
	for _, p := range r.Phases {
		if p.ID == id {
			for _, f := range r.Files {
				if f.Path == p.Path {
					return p, f, nil
				}
			}
		}
	}
	return Phase{}, File{}, fmt.Errorf("unknown phase %q", id)
}

func Compare(old, next Revision, overrides []Override) Diff {
	d := Diff{PackID: next.PackID, From: old.Commit, To: next.Commit, Added: []string{}, Changed: []string{}, Removed: []string{}, Conflicts: []string{}}
	before := map[string]string{}
	after := map[string]string{}
	for _, f := range old.Files {
		before[f.Path] = f.SHA256
	}
	for _, f := range next.Files {
		after[f.Path] = f.SHA256
		if before[f.Path] == "" {
			d.Added = append(d.Added, f.Path)
		} else if before[f.Path] != f.SHA256 {
			d.Changed = append(d.Changed, f.Path)
		}
	}
	for _, f := range old.Files {
		if after[f.Path] == "" {
			d.Removed = append(d.Removed, f.Path)
		}
	}
	for _, o := range overrides {
		_, f, err := next.Phase(o.PhaseID)
		if err != nil || f.SHA256 != o.BaseHash {
			d.Conflicts = append(d.Conflicts, o.PhaseID)
		}
	}
	return d
}
