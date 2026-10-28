package registry

import (
	"fmt"
	"sort"
	"sync"

	"github.com/s41r4j/cybot/pkg/schema"
)

type Registry[T any] struct {
	mu      sync.RWMutex
	entries map[string]T
	id      func(T) string
}

func New[T any](id func(T) string) *Registry[T] { return &Registry[T]{entries: map[string]T{}, id: id} }
func (r *Registry[T]) Register(v T) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.id(v)
	if id == "" {
		return fmt.Errorf("registry: empty id")
	}
	if _, ok := r.entries[id]; ok {
		return fmt.Errorf("registry: %q already registered", id)
	}
	r.entries[id] = v
	return nil
}
func (r *Registry[T]) Upsert(v T) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.id(v)
	if id == "" {
		return fmt.Errorf("registry: empty id")
	}
	r.entries[id] = v
	return nil
}
func (r *Registry[T]) Get(id string) (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.entries[id]
	return v, ok
}
func (r *Registry[T]) List() []T {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]T, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.entries[id])
	}
	return out
}

type SkillRegistry = Registry[schema.Skill]
type ToolRegistry = Registry[schema.Tool]

func NewSkills() *SkillRegistry { return New(func(v schema.Skill) string { return v.ID }) }
func NewTools() *ToolRegistry   { return New(func(v schema.Tool) string { return v.ID }) }
