package execution

import (
	"context"
	"github.com/s41r4j/cybot/pkg/schema"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRunner struct{ active, max atomic.Int32 }

func (f *fakeRunner) Health(context.Context, schema.Tool) error { return nil }
func (f *fakeRunner) Run(context.Context, Spec) (Output, error) {
	n := f.active.Add(1)
	for {
		m := f.max.Load()
		if n <= m || f.max.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(10 * time.Millisecond)
	f.active.Add(-1)
	return Output{}, nil
}
func TestBoundedRunnerLimitsConcurrency(t *testing.T) {
	base := &fakeRunner{}
	r := NewBounded(base, 2, 0)
	done := make(chan bool)
	for i := 0; i < 6; i++ {
		go func() { _, _ = r.Run(context.Background(), Spec{}); done <- true }()
	}
	for i := 0; i < 6; i++ {
		<-done
	}
	if base.max.Load() > 2 {
		t.Fatalf("max concurrency %d", base.max.Load())
	}
}
