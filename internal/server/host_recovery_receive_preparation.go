package server

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// hostRecoveryReceivePreparation resolves a single existing staged restore.
// It does not suspend a source, transfer bytes, or touch the destination.
type hostRecoveryReceivePreparation struct {
	authority    *store.Store
	gates        *store.GateRepository
	databasePath string
	ownerUID     uint32
	clock        func() time.Time
}

// NewRecoveryReceivePreparer uses the same server-owned authority and protected
// staged-file root as ordinary operation composition. Preparation is inert.
func NewRecoveryReceivePreparer(authority *store.Store, gates *store.GateRepository, databasePath string, ownerUID uint32, clock func() time.Time) api.RecoveryReceivePreparer {
	return hostRecoveryReceivePreparation{authority: authority, gates: gates, databasePath: databasePath, ownerUID: ownerUID, clock: clock}
}

func (c hostRecoveryReceivePreparation) PrepareRecoveryReceive(ctx context.Context, r generated.HostActionRequest) (generated.HostActionRequest, error) {
	if c.authority == nil || c.gates == nil || c.clock == nil || r.ActionID != store.ControlRecoveryReceiveAction {
		return r, actionFailure()
	}
	var selector generated.PlanReferenceRequest
	var supplied *generated.ControlRecoveryReceiveInput
	if generated.ValidateContractJSON(generated.SchemaIDPlanReferenceRequest, []byte(r.ActionInput), generated.ContractExact) == nil {
		if json.Unmarshal([]byte(r.ActionInput), &selector) != nil {
			return r, actionFailure()
		}
	} else {
		var v generated.ControlRecoveryReceiveInput
		if generated.ValidateContractJSON(generated.SchemaIDControlRecoveryReceiveInput, []byte(r.ActionInput), generated.ContractExact) != nil || json.Unmarshal([]byte(r.ActionInput), &v) != nil {
			return r, actionFailure()
		}
		supplied = &v
		selector.PlanID = v.Binding.PlanID
		selector.PlanDigest = v.Binding.PlanDigest
		selector.RecoveryEpoch = v.Binding.PriorRecoveryEpoch
	}
	revisions := store.NewPlanRepository(c.authority)
	before, err := revisions.CurrentRevision(ctx)
	if err != nil || before.StateRevision != r.ExpectedStateRevision || before.RecoveryEpoch != r.RecoveryEpoch {
		return r, actionFailure()
	}
	pending, found, err := store.NewRestoreRepository(c.authority).PendingPromotion(ctx)
	if err != nil || !found || pending.Binding.PlanID != selector.PlanID || pending.Binding.PlanDigest != selector.PlanDigest || pending.Binding.PriorRecoveryEpoch != selector.RecoveryEpoch || r.RecoveryEpoch != selector.RecoveryEpoch {
		return r, actionFailure()
	}
	hosts := store.NewHostActionRepository(c.authority)
	descriptor, err := hosts.ResolveRecoveryReceivePreparation(ctx, pending.Binding)
	if err != nil || r.HostID != descriptor.Replacement.NewHostID || r.TargetRevision != descriptor.Replacement.NewTargetRevision || r.TargetDigest != descriptor.Replacement.NewTargetDigest || r.ConsoleConfirmation.HostIdentityDigest != descriptor.Replacement.NewIdentityDigest {
		return r, actionFailure()
	}
	baseline, err := (hostRoleComposition{gates: c.gates, clock: c.clock}).baseline(ctx, descriptor.Replacement.NewHostID)
	if err != nil || baseline.IdentityDigest != descriptor.Replacement.NewIdentityDigest || baseline.ProfileLockDigest != descriptor.Replacement.ProfileLockDigest {
		return r, actionFailure()
	}
	// Fixed staged paths and protected file identities are selected by the owning
	// recovery builder. This I/O happens outside every database transaction.
	source, err := recovery.OpenCandidateTransfer(ctx, c.databasePath, c.ownerUID, descriptor)
	if err != nil {
		return r, err
	}
	rebuilt := source.Descriptor
	if err = source.Close(); err != nil {
		return r, err
	}
	if supplied != nil && hostaction.Digest(*supplied) != hostaction.Digest(rebuilt) {
		return r, actionFailure()
	}
	again, err := hosts.ResolveRecoveryReceivePreparation(ctx, pending.Binding)
	again.CandidateBytes = rebuilt.CandidateBytes
	again.CandidateBytesDigest = rebuilt.CandidateBytesDigest
	again.JournalBytes = rebuilt.JournalBytes
	after, revErr := revisions.CurrentRevision(ctx)
	if err != nil || revErr != nil || after != before || hostaction.Digest(again) != hostaction.Digest(rebuilt) {
		return r, actionFailure()
	}
	raw, err := json.Marshal(rebuilt)
	if err != nil || len(raw) > 32768 {
		return r, actionFailure()
	}
	r.ActionInput = string(raw)
	r.ActionInputDigest = hostaction.BytesDigest(raw)
	return r, nil
}
