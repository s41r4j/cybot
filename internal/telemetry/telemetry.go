package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/s41r4j/cybot/pkg/schema"
)

type Logger struct {
	path string
	mu   sync.Mutex
}

func New(path string) *Logger { return &Logger{path: path} }
func (l *Logger) Write(_ context.Context, e schema.AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(e)
}
func (l *Logger) Read(limit int) ([]schema.AuditEvent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return []schema.AuditEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	all := []schema.AuditEvent{}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		var e schema.AuditEvent
		if json.Unmarshal(s.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	if err = s.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, nil
}
