package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/s41r4j/cybot/pkg/schema"
)

type Store struct{ root string }

func New(root string) *Store { return &Store{root: root} }

// Verify only artifacts inside this store, resolving symlinks before reading.
func (s *Store) Verify(ev schema.Evidence) error {
	root, err := filepath.EvalSymlinks(s.root)
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	path, err := filepath.EvalSymlinks(ev.Path)
	if err != nil {
		return err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("evidence path is outside this store")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return fmt.Errorf("evidence is not a bounded regular artifact")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != ev.SHA256 {
		return fmt.Errorf("evidence SHA-256 mismatch")
	}
	return nil
}
func (s *Store) Put(runID, kind, mediaType string, data []byte) (schema.Evidence, error) {
	if runID == "" || runID == "." || runID == ".." || strings.ContainsAny(runID, `/\`) {
		return schema.Evidence{}, fmt.Errorf("invalid evidence run ID")
	}
	var err error
	switch mediaType {
	case "application/json":
		data, err = DefaultHygieneRules.SanitizeJSON(data)
	case "application/x-ndjson":
		var lines [][]byte
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var sanitized []byte
			sanitized, err = DefaultHygieneRules.SanitizeJSON(line)
			if err != nil {
				break
			}
			lines = append(lines, sanitized)
		}
		data = bytes.Join(lines, []byte("\n"))
	default:
		if strings.HasPrefix(mediaType, "text/") {
			data = []byte(DefaultHygieneRules.SanitizeText(string(data)))
		}
	}
	if err != nil {
		return schema.Evidence{}, fmt.Errorf("sanitize evidence: %w", err)
	}
	sum := sha256.Sum256(data)
	id := uuid.NewString()
	dir := filepath.Join(s.root, runID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return schema.Evidence{}, err
	}
	path := filepath.Join(dir, id+".artifact")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return schema.Evidence{}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return schema.Evidence{}, fmt.Errorf("evidence path: %w", err)
	}
	return schema.Evidence{ID: id, Type: kind, Path: abs, SHA256: hex.EncodeToString(sum[:]), MediaType: mediaType, CreatedAt: time.Now().UTC()}, nil
}
