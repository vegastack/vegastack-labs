package adapter

import (
	"context"
	"slices"
	"sync"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type Registry struct {
	mu                  sync.RWMutex
	adapters            map[string]Adapter
	credentialResolvers map[string]CredentialResolver
	credentialScopes    map[string]CredentialCapabilityScope
}

type CredentialResolver interface {
	Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error)
}
type CredentialCapabilityScope struct {
	ResolverID, ConsumerID, ProfileID, CapabilityID string
	Enabled                                         bool
}

// NewRegistry returns an empty production-safe registry. Test adapters live
// only in _test.go files and cannot be selected by normal server composition.
func NewRegistry() *Registry {
	return &Registry{adapters: map[string]Adapter{}, credentialResolvers: map[string]CredentialResolver{}, credentialScopes: map[string]CredentialCapabilityScope{}}
}

func credentialRegistryKey(resolverID, consumerID, profileID string) string {
	return resolverID + "\x00" + consumerID + "\x00" + profileID
}

// RegisterCredentialResolver requires an explicit compatible capability and
// deployment profile. The empty production registry cannot resolve a secret.
func (registry *Registry) RegisterCredentialResolver(scope CredentialCapabilityScope, implementation CredentialResolver) error {
	if registry == nil || implementation == nil || !scope.Enabled || !adapterToken.MatchString(scope.ResolverID) || scope.ResolverID == "test.fake" || !adapterToken.MatchString(scope.ConsumerID) || !adapterToken.MatchString(scope.ProfileID) || !adapterToken.MatchString(scope.CapabilityID) {
		return &Error{code: generated.ErrorCodeInputInvalid, target: "credential-resolver-registration"}
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	key := credentialRegistryKey(scope.ResolverID, scope.ConsumerID, scope.ProfileID)
	if registry.credentialResolvers[key] != nil {
		return &Error{code: generated.ErrorCodeStateConflict, target: "credential-resolver-registration"}
	}
	registry.credentialResolvers[key] = implementation
	registry.credentialScopes[key] = scope
	return nil
}

func (registry *Registry) ResolveCredentialCapability(resolverID, consumerID, profileID string) (string, error) {
	if registry == nil {
		return "", &Error{code: generated.ErrorCodePrerequisiteBlocked, target: "credential-capability"}
	}
	registry.mu.RLock()
	scope, ok := registry.credentialScopes[credentialRegistryKey(resolverID, consumerID, profileID)]
	registry.mu.RUnlock()
	if !ok || !scope.Enabled || scope.ResolverID != resolverID || scope.ConsumerID != consumerID || scope.ProfileID != profileID || !adapterToken.MatchString(scope.CapabilityID) {
		return "", &Error{code: generated.ErrorCodePrerequisiteBlocked, target: "credential-capability"}
	}
	return scope.CapabilityID, nil
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

// RegisteredCredentialConsumers returns the exact enabled consumer set for a
// resolver and applied profile. It reveals no resolver or credential material.
func (registry *Registry) RegisteredCredentialConsumers(resolverID, profileID string) ([]string, error) {
	if registry == nil || !adapterToken.MatchString(resolverID) || !adapterToken.MatchString(profileID) || resolverID == "test.fake" {
		return nil, &Error{code: generated.ErrorCodePrerequisiteBlocked, target: "credential-consumer-registry"}
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	consumers := make([]string, 0)
	for key, scope := range registry.credentialScopes {
		if !scope.Enabled || scope.ResolverID != resolverID || scope.ProfileID != profileID || registry.credentialResolvers[key] == nil || !adapterToken.MatchString(scope.ConsumerID) {
			continue
		}
		consumers = append(consumers, scope.ConsumerID)
	}
	slices.Sort(consumers)
	return slices.Compact(consumers), nil
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
