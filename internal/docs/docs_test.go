package docs

import (
	"errors"
	"github.com/s41r4j/cybot/pkg/schema"
	"testing"
)

var errWrite = errors.New("fixture writer failure")

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errWrite }
func TestMarkdownReportPropagatesWriteError(t *testing.T) {
	if err := Write(failingWriter{}, "markdown", schema.Report{}); !errors.Is(err, errWrite) {
		t.Fatalf("ignored write error: %v", err)
	}
}
