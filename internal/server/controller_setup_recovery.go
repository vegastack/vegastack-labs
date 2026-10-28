package server

import (
	"context"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"path/filepath"
)

type controllerSetupRecovery struct {
	authority   *store.Store
	profile     serverconfig.Profile
	destination string
}

func (c controllerSetupRecovery) PrepareRecovery(ctx context.Context, q generated.ControllerSetupRecoveryRequest, p identity.Principal) (generated.ControllerSetupRecoveryData, error) {
	var zero generated.ControllerSetupRecoveryData
	if c.authority == nil || p.Method != identity.LocalOSPeerMethod || identity.EffectivePrincipalKind(p) != identity.PrincipalHuman {
		return zero, actionFailure()
	}
	initial, e := c.authority.IsInitialAdministrator(ctx, p.ID)
	if e != nil || !initial {
		return zero, actionFailure()
	}
	bound := false
	for _, b := range c.profile.PrincipalBindings {
		if b.PrincipalID == p.ID && b.UID != c.profile.SocketOwnerUID {
			return zero, actionFailure()
		}
		if b.UID == c.profile.SocketOwnerUID && b.PrincipalID == p.ID {
			bound = true
		}
	}
	if !bound {
		return zero, actionFailure()
	}
	source, e := store.NewOnlineSnapshotSource(c.authority)
	if e != nil {
		return zero, e
	}
	expected, e := source.CurrentExpectation(ctx)
	if e != nil || expected.Revision.StateRevision != q.ExpectedStateRevision || expected.Revision.RecoveryEpoch != q.RecoveryEpoch {
		return zero, actionFailure()
	}
	authority, e := c.authority.CurrentAuthority(ctx)
	if e != nil {
		return zero, e
	}
	destination := c.destination
	if destination == "" {
		destination = linuxrole.ControllerRecoveryImage
	}
	if filepath.Clean(destination) != destination {
		return zero, actionFailure()
	}
	image, e := source.OnlineSnapshot(ctx, store.OnlineSnapshotRequest{Destination: destination, Expected: expected})
	if e != nil {
		return zero, e
	}
	return generated.ControllerSetupRecoveryData{Schema: generated.SchemaIDControllerSetupRecoveryData, SchemaVersion: "1.0.0", ImageDigest: fmt.Sprintf("sha256:%x", image.DatabaseSHA256), ControllerInstanceID: authority.InstanceID, StateRevision: image.Revision.StateRevision, RecoveryEpoch: image.Revision.RecoveryEpoch}, nil
}
