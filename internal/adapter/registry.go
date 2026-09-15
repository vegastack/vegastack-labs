package adapter

import (
	"context"
	"sync"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type Registry struct {
	mu                  sync.RWMutex
	adapters            map[string]Adapter
	credentialResolvers map[string]CredentialResolver
}

type CredentialResolver interface {
	Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error)
}
type CredentialCapabilityScope struct {
	ResolverID, ConsumerID, ProfileID string
	Enabled                           bool
}

// NewRegistry returns an empty production-safe registry. Test adapters live
// only in _test.go files and cannot be selected by normal server composition.
func NewRegistry() *Registry {
	return &Registry{adapters: map[string]Adapter{}, credentialResolvers: map[string]CredentialResolver{}}
}

func credentialRegistryKey(resolverID, consumerID, profileID string) string {
	return resolverID + "\x00" + consumerID + "\x00" + profileID
}

// RegisterCredentialResolver requires an explicit compatible capability and
// deployment profile. The empty production registry cannot resolve a secret.
func (registry *Registry) RegisterCredentialResolver(scope CredentialCapabilityScope, implementation CredentialResolver) error {
	if registry == nil || implementation == nil || !scope.Enabled || !adapterToken.MatchString(scope.ResolverID) || scope.ResolverID == "test.fake" || !adapterToken.MatchString(scope.ConsumerID) || !adapterToken.MatchString(scope.ProfileID) {
		return &Error{code: generated.ErrorCodeInputInvalid, target: "credential-resolver-registration"}
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	key := credentialRegistryKey(scope.ResolverID, scope.ConsumerID, scope.ProfileID)
	if registry.credentialResolvers[key] != nil {
		return &Error{code: generated.ErrorCodeStateConflict, target: "credential-resolver-registration"}
	}
	registry.credentialResolvers[key] = implementation
	return nil
}

func (registry *Registry) ResolveCredentialResolver(resolverID, consumerID, profileID string) (CredentialResolver, error) {
	if registry == nil || !adapterToken.MatchString(resolverID) || !adapterToken.MatchString(consumerID) || !adapterToken.MatchString(profileID) || resolverID == "test.fake" {
		return nil, &Error{code: generated.ErrorCodePrerequisiteBlocked, target: "credential-resolver"}
	}
	registry.mu.RLock()
	resolved := registry.credentialResolvers[credentialRegistryKey(resolverID, consumerID, profileID)]
	registry.mu.RUnlock()
	if resolved == nil {
		return nil, &Error{code: generated.ErrorCodePrerequisiteBlocked, target: "credential-resolver"}
	}
	return resolved, nil
}

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
