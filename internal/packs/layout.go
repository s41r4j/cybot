package packs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

const ManifestPath = "cybot-pack.json"

// Manifest lets a repository define its actual phase graph without depending on
// mdpsec filenames or requiring a CYBOT binary update for each prompt revision.
type Manifest struct {
	SchemaVersion int      `json:"schema_version"`
	Phases        []Phase  `json:"phases"`
	Documents     []string `json:"documents,omitempty"`
}

var phaseIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,95}$`)
var slugPattern = regexp.MustCompile(`[^a-z0-9-]+`)

func safeSourcePath(p string) bool {
	if p == "" || len(p) > 240 || path.Clean(p) != p || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\?#%\x00\r\n") {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == ".." || strings.HasPrefix(segment, ".") || segment == "" {
			return false
		}
	}
	return true
}

func markdownPath(p string) bool { return safeSourcePath(p) && strings.HasSuffix(p, ".md") }
func licensePath(p string) bool {
	if !safeSourcePath(p) || strings.Contains(p, "/") {
		return false
	}
	switch strings.ToLower(p) {
	case "license", "license.md", "license.txt", "copying":
		return true
	}
	return false
}

func promptPath(p string) bool {
	return markdownPath(p) && (phasePattern.MatchString(p) || path.Base(p) == "SKILL.md" || strings.HasPrefix(p, "prompts/"))
}

func parseManifest(content string) (Manifest, error) {
	var m Manifest
	d := json.NewDecoder(bytes.NewBufferString(content))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, fmt.Errorf("invalid %s: %w", ManifestPath, err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return m, fmt.Errorf("manifest must contain one JSON document")
	}
	if m.SchemaVersion != 1 || len(m.Phases) == 0 || len(m.Phases) > 128 {
		return m, fmt.Errorf("manifest requires schema_version 1 and 1-128 phases")
	}
	seen := map[string]bool{}
	paths := map[string]bool{}
	for _, p := range m.Phases {
		if !phaseIDPattern.MatchString(p.ID) || !markdownPath(p.Path) || seen[p.ID] || paths[p.Path] {
			return m, fmt.Errorf("invalid or duplicate manifest phase %q", p.ID)
		}
		for _, dep := range p.Dependencies {
			if !seen[dep] {
				return m, fmt.Errorf("manifest dependency %q must precede %s", dep, p.ID)
			}
		}
		seen[p.ID] = true
		paths[p.Path] = true
	}
	for _, p := range m.Documents {
		if !markdownPath(p) && !licensePath(p) {
			return m, fmt.Errorf("unsupported manifest document %q", p)
		}
	}
	return m, nil
}

func manifestIn(files []File) (*Manifest, error) {
	for _, f := range files {
		if f.Path == ManifestPath {
			m, err := parseManifest(f.Content)
			return &m, err
		}
	}
	return nil, nil
}

func declaredFiles(m *Manifest) map[string]bool {
	out := map[string]bool{}
	if m != nil {
		out[ManifestPath] = true
		for _, p := range m.Phases {
			out[p.Path] = true
		}
		for _, p := range m.Documents {
			out[p] = true
		}
	}
	return out
}

func defaultPhase(f File) Phase {
	id := strings.TrimSuffix(path.Base(f.Path), ".md")
	if !phasePattern.MatchString(f.Path) {
		if path.Base(f.Path) == "SKILL.md" {
			id = "skill"
			if path.Dir(f.Path) != "." {
				id += "-" + path.Dir(f.Path)
			}
		} else {
			id = "prompt-" + strings.TrimSuffix(strings.TrimPrefix(f.Path, "prompts/"), ".md")
		}
		id = strings.Trim(slugPattern.ReplaceAllString(strings.ToLower(id), "-"), "-")
	}
	p := Phase{ID: id, Title: id, Path: f.Path, Dependencies: []string{}, Capabilities: []string{}, RequiredInputs: []string{"target", "scope"}, ExpectedArtifacts: []string{"phase-summary", "coverage-and-evidence"}, IntegrationGaps: []string{"Upstream helper scripts and phase validators require local equivalents."}}
	for _, line := range strings.Split(f.Content, "\n") {
		if strings.HasPrefix(line, "# ") {
			p.Title = strings.TrimSpace(strings.TrimPrefix(line, "# "))
			break
		}
	}
	return p
}

func normalizePhase(p Phase) Phase {
	if p.Title == "" {
		p.Title = p.ID
	}
	if p.Dependencies == nil {
		p.Dependencies = []string{}
	}
	if p.Capabilities == nil {
		p.Capabilities = []string{}
	}
	if p.RequiredInputs == nil {
		p.RequiredInputs = []string{"target", "scope"}
	}
	if p.ExpectedArtifacts == nil {
		p.ExpectedArtifacts = []string{"phase-summary", "coverage-and-evidence"}
	}
	if p.IntegrationGaps == nil {
		p.IntegrationGaps = []string{}
	}
	return p
}
