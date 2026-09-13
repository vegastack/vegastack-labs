// Package identity owns provider-neutral authenticated identity values.
package identity

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/principal"
)

const LocalOSPeerMethod = principal.LocalOSPeerMethod

type LocalPeer = principal.LocalPeer
type Binding = principal.Binding
type LocalPrincipalResolver = principal.LocalPrincipalResolver

func NewLocalPrincipalResolver(bindings []Binding) (LocalPrincipalResolver, error) {
	return principal.NewLocalPrincipalResolver(bindings)
}

type principalContextKey struct{}

func WithVerifiedPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok && ValidPrincipal(principal)
}
