package server

import (
	"context"
	"slices"

	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// The immutable installation profile lists independently verified physical
// identities. Empty, unknown and excluded identities have no transport path.
// Populating this list is an installation action, never an API declaration.
type hostActionTargets struct {
	repository *store.HostActionRepository
	allowed    []string
}

func (s hostActionTargets) Resolve(ctx context.Context, b generated.HostActionBundle) (transport.Target, error) {
	if s.repository == nil || !slices.Contains(s.allowed, b.HostIdentityDigest) {
		return transport.Target{}, actionFailure()
	}
	x, err := s.repository.ExecutionForBundle(ctx, b)
	if err != nil {
		return transport.Target{}, err
	}
	r := x.Draft.Request
	if r.ConsoleConfirmation.HostIdentityDigest != b.HostIdentityDigest || r.HostID != b.HostID || r.CallerUID != b.CallerUID || r.AutomationPrincipalID != b.AutomationPrincipalID {
		return transport.Target{}, actionFailure()
	}
	t := x.Target
	return transport.Target{HostID: r.HostID, HostIdentityDigest: b.HostIdentityDigest, Address: t.Address, User: t.User, HostKey: t.HostKey, AutomationPrincipalID: r.AutomationPrincipalID, Port: uint16(t.Port), CallerUID: uint32(r.CallerUID), Revision: t.Revision}, nil
}
