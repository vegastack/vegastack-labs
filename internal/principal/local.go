// Package principal owns provider-neutral principal values and the local OS
// peer contract. It deliberately contains no remote transport or provider
// implementation.
package principal

import (
	"context"
	"regexp"

	"github.com/vegastack/vegastack-labs/internal/failure"
)

const LocalOSPeerMethod = "local-os-peer"

type Kind string

const (
	Human  Kind = "human"
	Agent  Kind = "agent"
	Policy Kind = "policy"
)

type Principal struct {
	ID     string
	Method string
	Kind   Kind
}

type LocalPeer struct {
	PID int32
	UID uint32
	GID uint32
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

var principalIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)

func NewLocalPrincipalResolver(bindings []Binding) (LocalPrincipalResolver, error) {
	if len(bindings) == 0 || len(bindings) > 256 {
		return nil, failure.New("INPUT_INVALID", "principal-bindings", false)
	}
	byUID := make(map[uint32]string, len(bindings))
	principals := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if !ValidID(binding.PrincipalID) {
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

func ValidID(id string) bool {
	return principalIDPattern.MatchString(id)
}
