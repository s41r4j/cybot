package memory

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/s41r4j/cybot/pkg/schema"
	"github.com/google/uuid"
)

func TestSaveResultUpdatesRecallAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := schema.Result{RunID: uuid.NewString(), Capability: "fixture", Target: "example.test", Status: "completed", StartedAt: now, FinishedAt: now}
	if err := s.SaveResult(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	entries, err := s.EngagementMemory(context.Background(), r.Target)
	if err != nil || len(entries) != 1 || !entries[0].EstimateSkip {
		t.Fatalf("recall not saved: %#v %v", entries, err)
	}
	r.RunID = uuid.NewString()
	r.Status = "partial"
	r.FinishedAt = now.Add(time.Second)
	if err := s.SaveResult(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	entries, err = s.EngagementMemory(context.Background(), r.Target)
	if err != nil || entries[0].EstimateSkip {
		t.Fatal("partial run incorrectly recommends skip")
	}
}
