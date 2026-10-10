//go:build linux

package server

import (
	"context"
	"encoding/json"
	"time"

	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// composeRecoveryTransfer supplies only the existing server-owned staged files.
// The adapter checks current execution authority before opening this source and
// signs the complete rendered descriptor; no API input chooses filesystem paths.
func composeRecoveryTransfer(a *transport.Adapter, s *store.Store, database string, uid uint32, gates *store.GateRepository) error {
	if err := a.SetRecoveryPayloadSource(func(ctx context.Context, b generated.HostActionBundle) (*transport.RecoveryPayload, error) {
		var d generated.ControlRecoveryReceiveInput
		if b.ActionID != hostaction.RecoveryReceiveAction || generated.ValidateContractJSON(generated.SchemaIDControlRecoveryReceiveInput, []byte(b.ActionInput), generated.ContractExact) != nil || json.Unmarshal([]byte(b.ActionInput), &d) != nil || recovery.ValidateCandidateTransferDescriptor(d) != nil {
			return nil, actionFailure()
		}
		pending, found, err := store.NewRestoreRepository(s).PendingPromotion(ctx)
		if err != nil || !found || hostaction.Digest(pending.Binding) != hostaction.Digest(d.Binding) || pending.DatabaseDigest != d.DatabaseDigest || pending.JournalDigest != d.JournalDigest || pending.BundleDigest != d.BundleDigest {
			return nil, actionFailure()
		}
		baseline, err := (hostRoleComposition{gates: gates, clock: time.Now}).baseline(ctx, d.Replacement.NewHostID)
		if err != nil || baseline.IdentityDigest != d.Replacement.NewIdentityDigest || baseline.ProfileLockDigest != d.Replacement.ProfileLockDigest {
			return nil, actionFailure()
		}
		source, err := recovery.OpenCandidateTransfer(ctx, database, uid, d)
		if err != nil {
			return nil, err
		}
		if hostaction.Digest(source.Descriptor) != hostaction.Digest(d) {
			source.Close()
			return nil, actionFailure()
		}
		current, err := (hostRoleComposition{gates: gates, clock: time.Now}).baseline(ctx, d.Replacement.NewHostID)
		if err != nil || current.BindingDigest != baseline.BindingDigest {
			source.Close()
			return nil, actionFailure()
		}
		return &transport.RecoveryPayload{Descriptor: source.Descriptor, Candidate: source.Candidate, Journal: source.Journal}, nil
	}); err != nil {
		return err
	}
	return a.SetRecoveryReceiveFinalizer(func(ctx context.Context, b generated.HostActionBundle, d generated.ControlRecoveryReceiveInput, result generated.HostActionResult) error {
		return s.SuspendRecoverySource(ctx, b, d, result)
	})
}
