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
