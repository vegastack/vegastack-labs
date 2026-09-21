package recovery

import (
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// RestorePlanBinding is the immutable, server-derived subset that a future
// restore plan must commit. This package does not persist or authorize a plan.
type RestorePlanBinding struct {
	PlanID              string
	PlanDigest          string
	PointID             string
	PointDigest         string
	ManifestDigest      string
	VerificationDigest  string
	FenceSetDigest      string
	AuditDecisionDigest string
	CandidateDigest     string
	TargetDigest        string
	PriorInstanceID     string
	NewInstanceID       string
	StateRevision       int64
	PriorRecoveryEpoch  int64
	NextRecoveryEpoch   int64
}

type RestoreRunIntent struct {
	RestorePlanBinding
	HumanAcknowledgementID string
}

type AuthorityRevision struct {
	StateRevision int64
	RecoveryEpoch int64
	InstanceID    string
}

// ValidateRunBinding is a final-boundary comparison, not a substitute for
// independently verifying the fence, acknowledgement, candidate or point.
func ValidateRunBinding(plan RestorePlanBinding, run RestoreRunIntent, live AuthorityRevision) error {
	blocked := func() error { return failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-run-binding", false) }
	if plan != run.RestorePlanBinding || run.HumanAcknowledgementID == "" ||
		plan.PlanID == "" || plan.PointID == "" ||
		plan.PriorInstanceID == "" || plan.NewInstanceID == "" || plan.PriorInstanceID == plan.NewInstanceID ||
		plan.StateRevision < 0 || plan.PriorRecoveryEpoch < 0 ||
		plan.PriorRecoveryEpoch == int64(^uint64(0)>>1) || plan.NextRecoveryEpoch != plan.PriorRecoveryEpoch+1 ||
		live.StateRevision != plan.StateRevision || live.RecoveryEpoch != plan.PriorRecoveryEpoch || live.InstanceID != plan.PriorInstanceID {
		return blocked()
	}
	for _, digest := range []string{plan.PlanDigest, plan.PointDigest, plan.ManifestDigest, plan.VerificationDigest,
		plan.FenceSetDigest, plan.AuditDecisionDigest, plan.CandidateDigest, plan.TargetDigest} {
		if !sourceDigestPattern.MatchString(digest) {
			return blocked()
		}
	}
	return nil
}
