package recovery

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type CandidateStoreOpener func(context.Context, string) (*store.Store, error)
type StoreCandidateAuthority struct{ Open CandidateStoreOpener }

type RestoreCandidateRepository interface {
	BindCandidate(context.Context, store.RecoveryCandidateRequest) error
}

// StoreCandidateRecorder binds the staged filesystem artifact to the exact
// immutable restore session before the old authority can be shut down.
type StoreCandidateRecorder struct {
	Repository               RestoreCandidateRepository
	Expected                 store.RevisionToken
	PreservedAuthorityDigest string
}

func (recorder StoreCandidateRecorder) BindRecoveryCandidate(ctx context.Context, binding generated.RestoreBinding, receipt CandidateReceipt) error {
	if recorder.Repository == nil || !restoreDigest.MatchString(recorder.PreservedAuthorityDigest) ||
		receipt.PlanID != binding.PlanID || receipt.CandidateDigest != binding.CandidateDigest ||
		receipt.NewInstanceID != binding.NewInstanceID || receipt.NextRecoveryEpoch != binding.NextRecoveryEpoch ||
		!restoreDigest.MatchString(receipt.DatabaseDigest) || !restoreDigest.MatchString(receipt.JournalDigest) {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-candidate-record", false)
	}
	return recorder.Repository.BindCandidate(ctx, store.RecoveryCandidateRequest{
		CandidateID:              "candidate-" + binding.PlanID,
		PlanID:                   binding.PlanID,
		CandidateDigest:          binding.CandidateDigest,
		PreservedAuthorityDigest: recorder.PreservedAuthorityDigest,
		FenceSetDigest:           binding.FenceSetDigest,
		AuditDecisionDigest:      binding.AuditDecisionDigest,
		DatabaseDigest:           receipt.DatabaseDigest,
		JournalDigest:            receipt.JournalDigest,
		BundleDigest:             receipt.BundleDigest,
		Expected:                 recorder.Expected,
	})
}

type StoreRecoveryBundleStore struct {
	Open     CandidateStoreOpener
	Plans    *store.PlanRepository
	Restores *store.RestoreRepository
}

func (bundles StoreRecoveryBundleStore) WriteRecoveryBundle(ctx context.Context, path string, binding generated.RestoreBinding) (string, error) {
	if bundles.Open == nil || bundles.Plans == nil || bundles.Restores == nil {
		return "", failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-authority-bundle", false)
	}
	planned, err := bundles.Plans.GetPlan(ctx, binding.PlanID)
	if err != nil {
		return "", err
	}
	qualification, err := bundles.Restores.Qualification(ctx, binding.PlanID)
	if err != nil {
		return "", err
	}
	candidate, err := bundles.Open(ctx, path)
	if err != nil {
		return "", err
	}
	defer candidate.Close()
	return candidate.WriteRecoveredAuthorityBundle(ctx, store.RecoveredAuthorityBundle{Plan: planned.Plan, Readable: planned.Readable, Request: qualification.Request, Binding: binding, Status: "verification-required"})
}

func (bundles StoreRecoveryBundleStore) VerifyRecoveryBundle(ctx context.Context, path string, binding generated.RestoreBinding, digest string) error {
	if bundles.Open == nil || !restoreDigest.MatchString(digest) {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-authority-bundle", false)
	}
	candidate, err := bundles.Open(ctx, path)
	if err != nil {
		return err
	}
	defer candidate.Close()
	stored, got, err := candidate.RecoveredAuthorityBundle(ctx, binding.PlanID)
	if err != nil || got != digest || !sameRestoreSource(stored.Binding.Source, binding.Source) || stored.Binding.PlanDigest != binding.PlanDigest || stored.Binding.HumanAcknowledgementID != binding.HumanAcknowledgementID {
		return failure.New(generated.ErrorCodeIntegrityFailure, "recovery-authority-bundle", false)
	}
	return nil
}

func (authority StoreCandidateAuthority) PrepareRecoveredAuthority(ctx context.Context, path string, binding generated.RestoreBinding, continuity AuditContinuity) error {
	if authority.Open == nil || path == "" || !restoreDigest.MatchString(continuity.IndependentCheckpointDigest) || continuity.DecisionDigest != binding.AuditDecisionDigest {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-candidate-authority", false)
	}
	candidate, err := authority.Open(ctx, path)
	if err != nil {
		return err
	}
	defer candidate.Close()
	return candidate.PrepareRecoveredAuthority(ctx, binding, audit.Fingerprint(continuity.IndependentCheckpointDigest))
}

func (authority StoreCandidateAuthority) VerifyRecoveredAuthority(ctx context.Context, path string, binding generated.RestoreBinding) error {
	if authority.Open == nil || path == "" || !validCandidateBinding(binding) {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-candidate-authority", false)
	}
	candidate, err := authority.Open(ctx, path)
	if err != nil {
		return err
	}
	defer candidate.Close()
	return candidate.VerifyRecoveredAuthority(ctx, binding)
}
