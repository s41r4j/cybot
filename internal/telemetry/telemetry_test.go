package telemetry

import (
	"context"
	"github.com/s41r4j/cybot/pkg/schema"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditJSONLRoundTripAndLimit(t *testing.T) {
	l := New(filepath.Join(t.TempDir(), "audit.jsonl"))
	for i := 0; i < 3; i++ {
		if err := l.Write(context.Background(), schema.AuditEvent{Timestamp: time.Unix(int64(i), 0).UTC(), Level: "info", Event: "test", Message: "safe"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := l.Read(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Timestamp.Unix() != 1 {
		t.Fatalf("unexpected events: %#v", got)
	}
}
