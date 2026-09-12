package adapter

import (
	"sync"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

// NewRegistry returns an empty production-safe registry. Test adapters live
// only in _test.go files and cannot be selected by normal server composition.
func NewRegistry() *Registry { return &Registry{adapters: map[string]Adapter{}} }

func (registry *Registry) Register(id string, implementation Adapter) error {
	if registry == nil || !adapterToken.MatchString(id) || implementation == nil || id == "test.fake" {
		return &Error{code: generated.ErrorCodeInputInvalid, target: "adapter-registration"}
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.adapters[id]; exists {
		return &Error{code: generated.ErrorCodeStateConflict, target: "adapter-registration"}
	}
	registry.adapters[id] = implementation
	return nil
}

func (registry *Registry) Resolve(id string) (Adapter, error) {
	if registry == nil || !adapterToken.MatchString(id) || id == "test.fake" {
		return nil, &Error{code: generated.ErrorCodePrerequisiteBlocked, target: "adapter"}
	}
	registry.mu.RLock()
	implementation := registry.adapters[id]
	registry.mu.RUnlock()
	if implementation == nil {
		return nil, &Error{code: generated.ErrorCodePrerequisiteBlocked, target: "adapter"}
	}
	return implementation, nil
}
