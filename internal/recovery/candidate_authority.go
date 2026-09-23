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
		Expected:                 recorder.Expected,
	})
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
