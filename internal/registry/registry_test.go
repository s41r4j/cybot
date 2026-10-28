package registry

import (
	"github.com/s41r4j/cybot/pkg/schema"
	"testing"
)

func TestRegistryStableListAndDuplicates(t *testing.T) {
	r := NewTools()
	if err := r.Register(schema.Tool{ID: "z"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(schema.Tool{ID: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(schema.Tool{ID: "a"}); err == nil {
		t.Fatal("expected duplicate error")
	}
	got := r.List()
	if got[0].ID != "a" || got[1].ID != "z" {
		t.Fatalf("not sorted: %#v", got)
	}
}
