package backup

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// ConsistencyToken is an opaque handle a registered hook returns from Begin and
// consumes in Finish. It carries no secret material.
type ConsistencyToken struct {
	HookID string
	Value  string
}

// ConsistencyHook brackets one capture with a registered begin/finish pair. A
// successful Begin is always paired with exactly one Finish; Finish receives
// success=false whenever the bracketed capture did not succeed.
type ConsistencyHook interface {
	Begin(context.Context, PolicySource) (ConsistencyToken, error)
	Finish(context.Context, ConsistencyToken, bool) error
}

// HookRegistry resolves only registered consistency hooks by ID. An unregistered
// or mutable-source hook never resolves, so capture cannot use one.
type HookRegistry struct {
	hooks map[string]ConsistencyHook
}

func NewHookRegistry() *HookRegistry { return &HookRegistry{hooks: map[string]ConsistencyHook{}} }

func (registry *HookRegistry) Register(id string, hook ConsistencyHook) error {
	if registry == nil || id == "" || hook == nil {
		return failure.New(generated.ErrorCodeInputInvalid, "backup-consistency-hook", false)
	}
	if _, exists := registry.hooks[id]; exists {
		return failure.New(generated.ErrorCodeStateConflict, "backup-consistency-hook", false)
	}
	registry.hooks[id] = hook
	return nil
}

func (registry *HookRegistry) Resolve(id string) (ConsistencyHook, bool) {
	if registry == nil || id == "" {
		return nil, false
	}
	hook, ok := registry.hooks[id]
	return hook, ok
}

// SQLiteOnlineHookID is the registered hook that brackets a capture taken through
// SQLite's Online Backup API. That API provides the point-in-time consistency;
// this hook binds the exact policy digest to the begin/finish bracket.
const SQLiteOnlineHookID = "sqlite-online"

// SQLiteOnlineHook is the registered consistency hook for the store-owned online
// snapshot source. It never touches a mutable or unregistered source.
type SQLiteOnlineHook struct{}

func (SQLiteOnlineHook) Begin(_ context.Context, source PolicySource) (ConsistencyToken, error) {
	if source.Policy.ConsistencyHookID != SQLiteOnlineHookID || source.PolicyDigest == "" {
		return ConsistencyToken{}, failure.New(generated.ErrorCodeInputInvalid, "backup-consistency-hook", false)
	}
	return ConsistencyToken{HookID: SQLiteOnlineHookID, Value: source.PolicyDigest}, nil
}

func (SQLiteOnlineHook) Finish(_ context.Context, token ConsistencyToken, _ bool) error {
	if token.HookID != SQLiteOnlineHookID {
		return failure.New(generated.ErrorCodeInputInvalid, "backup-consistency-hook", false)
	}
	return nil
}

// DefaultHookRegistry returns a registry with only the store-owned SQLite online
// consistency hook registered.
func DefaultHookRegistry() *HookRegistry {
	registry := NewHookRegistry()
	_ = registry.Register(SQLiteOnlineHookID, SQLiteOnlineHook{})
	return registry
}
