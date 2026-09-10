// Package identity owns provider-neutral authenticated identity values.
package identity

import (
	"context"
	"regexp"

	"github.com/vegastack/vegastack-labs/internal/failure"
)

const LocalOSPeerMethod = "local-os-peer"

var principalIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

type LocalPeer struct {
	PID int32
	UID uint32
	GID uint32
}

type Principal struct {
	ID     string
	Method string
}

type Binding struct {
	UID         uint32
	PrincipalID string
}

type LocalPrincipalResolver interface {
	ResolveLocalPeer(context.Context, LocalPeer) (Principal, error)
}

type localPrincipalResolver struct {
	byUID map[uint32]string
}

func NewLocalPrincipalResolver(bindings []Binding) (LocalPrincipalResolver, error) {
	if len(bindings) == 0 || len(bindings) > 256 {
		return nil, failure.New("INPUT_INVALID", "principal-bindings", false)
	}
	byUID := make(map[uint32]string, len(bindings))
	principals := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if !principalIDPattern.MatchString(binding.PrincipalID) {
			return nil, failure.New("INPUT_INVALID", "principal-bindings", false)
		}
		if _, exists := byUID[binding.UID]; exists {
			return nil, failure.New("INPUT_INVALID", "principal-bindings", false)
		}
		if _, exists := principals[binding.PrincipalID]; exists {
			return nil, failure.New("INPUT_INVALID", "principal-bindings", false)
		}
		byUID[binding.UID] = binding.PrincipalID
		principals[binding.PrincipalID] = struct{}{}
	}
	return &localPrincipalResolver{byUID: byUID}, nil
}

func (resolver *localPrincipalResolver) ResolveLocalPeer(ctx context.Context, peer LocalPeer) (Principal, error) {
	if err := ctx.Err(); err != nil {
		return Principal{}, failure.New("INTERRUPTED", "local-peer", false)
	}
	principalID, ok := resolver.byUID[peer.UID]
	if !ok {
		return Principal{}, failure.New("AUTHENTICATION_REQUIRED", "local-peer", false)
	}
	return Principal{ID: principalID, Method: LocalOSPeerMethod}, nil
}

type principalContextKey struct{}

func WithVerifiedPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok && ValidPrincipal(principal)
}
