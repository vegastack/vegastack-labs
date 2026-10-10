package gate

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// EvaluateNativeProfileQualification consumes only the server's internally
// verified current qualification set. Reports and uploaded fixtures never
// populate that set. Ordinary host admission is a separate evaluator.
func EvaluateNativeProfileQualification(ctx context.Context, s store.HostAdmissionSnapshot, scope ResolvedScope, gateID string, at time.Time) (generated.GateEvaluation, error) {
	if err := ctx.Err(); err != nil {
		return generated.GateEvaluation{}, err
	}
	stage := strings.TrimPrefix(gateID, "native.")
	if gateID != "native."+stage || !slices.Contains([]string{"baseline", "role", "recovery"}, stage) {
		return generated.GateEvaluation{}, errNativeProvenance
	}
	state := newEvaluationContext(nil, scope, Subject{ID: s.Profile.ProfileID, Kind: "profile", StateRevision: s.Revision.StateRevision}, at, NewProofRegistry())
	def := state.definitions[gateID].Definition
	out := state.base(gateID, def)
	out.Outcome, out.ReasonCode, out.ReadyForInput = "blocked", "host-qualification-missing", true
	if at.IsZero() || s.Profile.ProfileID != scope.ProfileID || s.Revision.RecoveryEpoch != scope.RecoveryEpoch || scope.StateRevision > s.Revision.StateRevision {
		return out, nil
	}
	var selected *generated.GateEvidence
	for i := range s.Evidence {
		e := &s.Evidence[i]
		if e.GateID == gateID && e.SubjectID == scope.ProfileID && (selected == nil || e.StateRevision > selected.StateRevision || e.StateRevision == selected.StateRevision && e.EvidenceID > selected.EvidenceID) {
			selected = e
		}
	}
	if selected == nil {
		return out, nil
	}
	e := *selected
	out.EvidenceIDs = []string{e.EvidenceID}
	if e.Status != "applied" || e.SourceKind != "local" || e.ProofClass != "live" || e.CollectorID != "native-debian-228" || e.ProfileID != scope.ProfileID || e.ProfileVersion != scope.ProfileVersion || e.PolicyID != scope.PolicyID || e.PolicyVersion != scope.PolicyVersion || e.RecoveryEpoch != s.Revision.RecoveryEpoch || e.StateRevision > s.Revision.StateRevision || !hostEvidenceTime(e, at.UTC()) {
		return out, nil
	}
	b, exists := s.Bundles[e.EvidenceID]
	joined, internal := s.NativeProducerBindings[e.EvidenceID]
	if !exists || !internal || b.NativeQualification == nil || hostaction.Digest(b) != e.BundleDigest || hostaction.Digest(*b.NativeQualification) != e.ArtifactDigest || hostaction.Digest(joined.Qualification) != hostaction.Digest(*b.NativeQualification) {
		return out, nil
	}
	p := b.NativeQualification
	for _, q := range s.Qualifications {
		if q.EvidenceID == e.EvidenceID && q.Stage == stage && q.ProfileDigest == s.ProfileLockDigest && q.ProfileDigest == p.ProfileLockDigest && q.SourceDigest == p.SourceDigest && q.RecoveryEpoch == s.Revision.RecoveryEpoch && q.ObservedAt == e.ObservedAt && q.ExpiresAt == e.ExpiresAt {
			out.Outcome, out.ReasonCode, out.ReadyForInput, out.EvidenceSource = "passed", "proof-verified", false, "local"
			return out, nil
		}
	}
	return out, nil
}
