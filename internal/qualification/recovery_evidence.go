package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"time"
)

// ReplacementRecoveryEvidence is the generated-only projection of actual
// storage joins, never an accepted public observation or report payload.
type ReplacementRecoveryEvidence struct {
	CurrentProfileID         string
	CurrentProfileLockDigest string
	Binding                  generated.RestoreBinding
	Replacement              generated.HostReplacementState
	Continuity               generated.HostReplacementContinuityReference
	CanaryDigest             string
	CanaryRunID              string
	CanaryEventID            int64
	VerifiedAt               string
}

// ValidateReplacementRecoveryEvidence ties the completed control restore and
// canary to the actual subsequent alias commit. Isolated successful restore or
// stateless replacement cannot stand in for this complete lineage.
func ValidateReplacementRecoveryEvidence(e ProducerExecution, v ReplacementRecoveryEvidence) error {
	p, r, x := e.Plan, e.Reference, e.Receipt
	q := p.HostReplacement
	b, s, c := v.Binding, v.Replacement, v.Continuity
	if q == nil || q.Operation != "commit" || q.RestorationClass != "control-database" || q.Source == nil || r.ScenarioID != "replacement-recovery" || r.HostID != q.NewHostID || x.Status != "succeeded" || x.PlanID != p.PlanID || x.PlanDigest != p.PlanDigest || x.RunID != r.RunID || x.StepID != r.StepID || x.LeaseID != r.LeaseID || x.RecoveryEpoch != p.Binding.RecoveryEpoch {
		return ErrUnavailable
	}
	if v.CurrentProfileID != q.ProfileID || v.CurrentProfileLockDigest != q.ProfileLockDigest || s.Status != "committed" || s.RestorationClass != "control-database" || s.ReplacementID != q.ReplacementID || s.PlanID == nil || *s.PlanID != p.PlanID || s.RunID == nil || *s.RunID != r.RunID || s.RestorePlanID == nil || *s.RestorePlanID != b.PlanID || s.OldHostID != q.OldHostID || s.NewHostID != q.NewHostID || s.OldIdentityDigest != q.OldIdentityDigest || s.NewIdentityDigest != q.NewIdentityDigest || s.OldIdentityDigest == s.NewIdentityDigest || s.RecoveryEpoch != p.Binding.RecoveryEpoch || s.RoleIntentRevision <= 0 || s.RoleBindingDigest != q.ProposedRoleBindingDigest {
		return ErrUnavailable
	}
	if b.NewInstanceID == "" || b.PriorInstanceID == "" || b.NewInstanceID == b.PriorInstanceID || b.NextRecoveryEpoch != b.PriorRecoveryEpoch+1 || b.NextRecoveryEpoch != s.RecoveryEpoch || b.FormerHostID != q.OldHostID || b.ReplacementHostID != q.NewHostID || b.Source.PointID != q.Source.PointID || hostaction.Digest(b.Source) != q.Source.SourceBindingDigest || b.ReplacementContinuity == nil || hostaction.Digest(*b.ReplacementContinuity) != hostaction.Digest(c) || c.ReplacementID != q.ReplacementID || c.Digest != s.ContinuityDigest || c.SourceBindingDigest != q.Source.SourceBindingDigest || c.SourcePointID != b.Source.PointID || c.CurrentAliasHighWatermark < c.SourceAliasHighWatermark || s.RestorationReceiptDigest != hostaction.Digest(b) {
		return ErrUnavailable
	}
	if v.CanaryRunID == "" || v.CanaryRunID != b.CanaryRunID || v.CanaryEventID <= 0 || !nativeDigest(v.CanaryDigest) || len(s.AliasBindings) != len(q.AliasBindings) || len(s.AliasBindings) == 0 {
		return ErrUnavailable
	}
	if _, err := time.Parse(time.RFC3339, v.VerifiedAt); err != nil {
		return ErrUnavailable
	}
	for i, a := range s.AliasBindings {
		prior := q.AliasBindings[i]
		if a.AliasID != prior.AliasID || a.OwnerHostID != q.NewHostID || a.OwnerIdentityDigest != q.NewIdentityDigest || a.OwnerRevision != prior.OwnerRevision+2 || a.OwnershipGeneration != prior.OwnershipGeneration+1 {
			return ErrUnavailable
		}
	}
	return nil
}
func nativeDigest(v string) bool {
	if len(v) != 71 || v[:7] != "sha256:" {
		return false
	}
	for _, c := range v[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
