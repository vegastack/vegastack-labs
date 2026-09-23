package recovery

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// StoreRecoveryCanary owns only the authority-local canary boundaries. The
// noop run, independent audit checkpoint, verified backup, and renewed former
// writer denial remain explicit external ports on CanaryVerifier.
type StoreRecoveryCanary struct {
	Authority *store.Store
	Restores  *store.RestoreRepository
}

func (canary StoreRecoveryCanary) CurrentAuthority(ctx context.Context) (AuthorityBinding, error) {
	if canary.Authority == nil {
		return AuthorityBinding{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-authority", false)
	}
	state, err := canary.Authority.CurrentAuthority(ctx)
	if err != nil {
		return AuthorityBinding{}, err
	}
	health, err := canary.Authority.Health(ctx)
	if err != nil {
		return AuthorityBinding{}, err
	}
	return AuthorityBinding{InstanceID: state.InstanceID, RecoveryEpoch: state.RecoveryEpoch, StateRevision: health.Revision.StateRevision, Mode: state.Mode}, nil
}

func (canary StoreRecoveryCanary) VerifyRecoveryRead(ctx context.Context, request CanaryRequest) error {
	bundle, err := canary.exactBundle(ctx, request)
	if err != nil {
		return err
	}
	if err := (AuthorityAdmission{State: canary}).Require(ctx, AuthorityBinding{InstanceID: request.NewInstanceID, RecoveryEpoch: request.RecoveryEpoch, StateRevision: request.ExpectedStateRevision, Mode: "recovery-required"}); err != nil {
		return err
	}
	return canary.Authority.VerifyRecoveredAuthority(ctx, bundle.Binding)
}

func (canary StoreRecoveryCanary) VerifyOldEpochDenied(ctx context.Context, request CanaryRequest) error {
	bundle, err := canary.exactBundle(ctx, request)
	if err != nil {
		return err
	}
	if bundle.Binding.PriorRecoveryEpoch+1 != request.RecoveryEpoch {
		return failure.New(generated.ErrorCodeRecoveryRequired, "recovery-canary-old-epoch", false)
	}
	return canary.Authority.VerifyRecoveryOldEpochMutationDenied(ctx, request.ExpectedStateRevision, bundle.Binding.PriorRecoveryEpoch)
}

func (canary StoreRecoveryCanary) EnableAuthority(ctx context.Context, request CanaryRequest, digest string) error {
	if _, err := canary.exactBundle(ctx, request); err != nil {
		return err
	}
	return canary.Authority.EnableRecoveredAuthority(ctx, request.NewInstanceID, request.RecoveryEpoch, request.ExpectedStateRevision, digest)
}

func (canary StoreRecoveryCanary) exactBundle(ctx context.Context, request CanaryRequest) (store.RecoveredAuthorityBundle, error) {
	if canary.Authority == nil || canary.Restores == nil {
		return store.RecoveredAuthorityBundle{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-authority", false)
	}
	bundle, _, err := canary.Restores.RecoveredAuthorityBundle(ctx, request.PlanID)
	if err != nil {
		return store.RecoveredAuthorityBundle{}, err
	}
	if bundle.Plan.PlanDigest != request.PlanDigest || bundle.Binding.NewInstanceID != request.NewInstanceID || bundle.Binding.NextRecoveryEpoch != request.RecoveryEpoch || bundle.Binding.FenceSetDigest != request.FenceSetDigest || bundle.Binding.CanaryRunID != request.CanaryRunID || bundle.Binding.CanaryStepID != request.CanaryStepID || bundle.Binding.CanaryLeaseID != request.CanaryLeaseID || bundle.Binding.CanaryChallengeID != request.CanaryChallengeID || bundle.Binding.CanaryReceiptID != request.CanaryReceiptID || bundle.Status != "verification-required" {
		return store.RecoveredAuthorityBundle{}, failure.New(generated.ErrorCodePlanStale, "recovery-canary-authority", false)
	}
	return bundle, nil
}
