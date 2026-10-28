package packs

import (
	"context"
	"crypto/sha1"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"strings"
	"time"

	"github.com/s41r4j/cybot/internal/source"
)

//go:embed builtin
var builtin embed.FS

func Bundled() (Revision, error) {
	var meta struct {
		Repository string            `json:"repository"`
		Commit     string            `json:"commit"`
		Hashes     map[string]string `json:"sha256"`
	}
	b, err := builtin.ReadFile("builtin/provenance.json")
	if err != nil {
		return Revision{}, err
	}
	if err = json.Unmarshal(b, &meta); err != nil {
		return Revision{}, err
	}
	files := []File{}
	err = fs.WalkDir(builtin, "builtin", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := strings.TrimPrefix(p, "builtin/")
		if !allowedFile(name) {
			return nil
		}
		b, err := builtin.ReadFile(p)
		if err != nil {
			return err
		}
		if meta.Hashes[name] != Hash(string(b)) {
			return fmt.Errorf("bundled source checksum mismatch: %s", name)
		}
		files = append(files, File{Path: name, Content: string(b)})
		return nil
	})
	if err != nil {
		return Revision{}, err
	}
	if len(files) != len(meta.Hashes) {
		return Revision{}, fmt.Errorf("bundled file inventory mismatch")
	}
	return NewRevision(meta.Repository, meta.Commit, files)
}

// Getter permits offline HTTP fixtures without relaxing production URL checks.
type Getter func(context.Context, string) ([]byte, error)
type GitHub struct{ Get Getter }

type treeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
	Mode string `json:"mode"`
	Size int    `json:"size"`
	SHA  string `json:"sha"`
}

func (g GitHub) blob(ctx context.Context, repo, commit string, entry treeEntry) (File, error) {
	if !safeSourcePath(entry.Path) || entry.Type != "blob" || (entry.Mode != "100644" && entry.Mode != "100755") || entry.Size > MaxFileBytes || entry.Size <= 0 {
		return File{}, fmt.Errorf("unsupported source entry %q", entry.Path)
	}
	b, err := g.fetch(ctx, "https://raw.githubusercontent.com/"+repo+"/"+commit+"/"+entry.Path)
	if err != nil {
		return File{}, fmt.Errorf("fetch %s: %w", entry.Path, err)
	}
	if len(b) > MaxFileBytes || len(b) != entry.Size {
		return File{}, fmt.Errorf("source size mismatch for %s", entry.Path)
	}
	if GitBlobHash(b) != entry.SHA {
		return File{}, fmt.Errorf("Git blob checksum mismatch for %s", entry.Path)
	}
	return File{Path: entry.Path, Content: string(b), SHA256: Hash(string(b))}, nil
}

func (g GitHub) fetch(ctx context.Context, u string) ([]byte, error) {
	if g.Get != nil {
		return g.Get(ctx, u)
	}
	return source.Fetch(ctx, u)
}

func (g GitHub) Resolve(ctx context.Context, repository, ref string) (string, error) {
	repo, err := Repository(repository)
	if err != nil {
		return "", err
	}
	if ref == "" || len(ref) > 256 {
		return "", fmt.Errorf("invalid Git ref")
	}
	b, err := g.fetch(ctx, "https://api.github.com/repos/"+repo+"/commits/"+url.PathEscape(ref))
	if err != nil {
		return "", err
	}
	var result struct {
		SHA string `json:"sha"`
	}
	if err = json.Unmarshal(b, &result); err != nil {
		return "", err
	}
	if !commitPattern.MatchString(result.SHA) {
		return "", fmt.Errorf("GitHub returned an invalid commit SHA")
	}
	return result.SHA, nil
}

func (g GitHub) Fetch(ctx context.Context, repository, commit string) (Revision, error) {
	repo, err := Repository(repository)
	if err != nil {
		return Revision{}, err
	}
	if !commitPattern.MatchString(commit) {
		return Revision{}, fmt.Errorf("immutable commit SHA is required")
	}
	b, err := g.fetch(ctx, "https://api.github.com/repos/"+repo+"/git/trees/"+commit+"?recursive=1")
	if err != nil {
		return Revision{}, err
	}
	var tree struct {
		Truncated bool        `json:"truncated"`
		Tree      []treeEntry `json:"tree"`
	}
	if err = json.Unmarshal(b, &tree); err != nil {
		return Revision{}, err
	}
	if tree.Truncated {
		return Revision{}, fmt.Errorf("truncated GitHub tree; refusing incomplete revision")
	}
	files := []File{}
	total := 0
	var manifest *Manifest
	for _, entry := range tree.Tree {
		if entry.Path == ManifestPath {
			f, err := g.blob(ctx, repo, commit, entry)
			if err != nil {
				return Revision{}, err
			}
			m, err := parseManifest(f.Content)
			if err != nil {
				return Revision{}, err
			}
			manifest = &m
			files = append(files, f)
			total += len(f.Content)
		}
	}
	declared := declaredFiles(manifest)
	for _, entry := range tree.Tree {
		if entry.Path == ManifestPath {
			continue
		}
		selected := allowedFile(entry.Path)
		if manifest != nil {
			selected = declared[entry.Path] || licensePath(entry.Path) || entry.Path == "README.md" || entry.Path == "ADAPTATION.md" || entry.Path == "SECURITY.md"
		}
		if !selected {
			continue
		}
		if len(files) >= 128 || total+entry.Size > MaxPackBytes {
			return Revision{}, fmt.Errorf("pack exceeds size/file limits")
		}
		f, err := g.blob(ctx, repo, commit, entry)
		if err != nil {
			return Revision{}, err
		}
		total += len(f.Content)
		files = append(files, f)
	}
	return NewRevision(repo, commit, files)
}

// GitBlobHash verifies the immutable tree's object ID; SHA-256 is used for
// CYBOT's own artifact identity. SHA-1 here is the upstream Git object format.
func GitBlobHash(b []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return fmt.Sprintf("%x", h.Sum(nil))
}

type Check struct {
	PackID          string `json:"pack_id"`
	Active          string `json:"active_revision"`
	Available       string `json:"available_revision,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	Skipped         bool   `json:"skipped"`
	Error           string `json:"error,omitempty"`
}

func (s *Store) recordCheck(ctx context.Context, id, sha string, checkErr error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := readPack(ctx, tx, id)
	if err != nil {
		return err
	}
	p.CheckedAt = time.Now().UTC()
	p.LastError = ""
	if checkErr != nil {
		p.LastError = checkErr.Error()
	} else {
		p.Available = sha
	}
	if err = savePack(ctx, tx, p); err != nil {
		return err
	}
	if err = event(ctx, tx, id, "update-check", sha); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Check(ctx context.Context, id string, g GitHub, due time.Duration) (Check, error) {
	p, err := s.Get(ctx, id)
	if err != nil {
		return Check{}, err
	}
	c := Check{PackID: id, Active: p.Active, Available: p.Available, UpdateAvailable: p.Available != "" && p.Available != p.Active}
	interval := due
	if p.LastError != "" && interval > 15*time.Minute {
		interval = 15 * time.Minute
	}
	if due > 0 && time.Since(p.CheckedAt) < interval {
		c.Skipped = true
		return c, nil
	}
	sha, err := g.Resolve(ctx, p.Repository, p.Ref)
	if err != nil {
		c.Error = err.Error()
	} else {
		c.Available = sha
		c.UpdateAvailable = sha != p.Active
	}
	if saveErr := s.recordCheck(ctx, id, sha, err); saveErr != nil {
		return c, fmt.Errorf("record update check: %w", saveErr)
	}
	return c, err
}

func (s *Store) Sync(ctx context.Context, id string, g GitHub) (Pack, error) {
	p, err := s.Get(ctx, id)
	if err != nil {
		return p, err
	}
	sha, err := g.Resolve(ctx, p.Repository, p.Ref)
	if err == nil {
		if err = s.recordCheck(ctx, id, sha, nil); err != nil {
			return p, err
		}
		var r Revision
		r, err = s.Revision(ctx, id, sha)
		if err != nil {
			r, err = g.Fetch(ctx, p.Repository, sha)
		}
		if err == nil {
			var staged Pack
			staged, err = s.Stage(ctx, r, p.Ref)
			if err == nil {
				return staged, nil
			}
		}
	}
	if saveErr := s.recordCheck(ctx, id, "", err); saveErr != nil {
		return p, fmt.Errorf("sync: %v; record failure: %w", err, saveErr)
	}
	return p, err
}

// Install records a successful network check separately from local staging.
// Offline bundle installation never claims to have checked GitHub.
func (s *Store) Install(ctx context.Context, repo, ref string, g GitHub) (Pack, error) {
	sha, err := g.Resolve(ctx, repo, ref)
	if err != nil {
		return Pack{}, err
	}
	r, err := g.Fetch(ctx, repo, sha)
	if err != nil {
		return Pack{}, err
	}
	p, err := s.Stage(ctx, r, ref)
	if err != nil {
		return p, err
	}
	if err = s.recordCheck(ctx, p.ID, sha, nil); err != nil {
		return p, err
	}
	return s.Get(ctx, p.ID)
}
