package gate

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
)

// IngressPilotVerifier compares acknowledged server-produced evidence with new
// observations. The normal G-012 verifier is deliberately not installed here.
type IngressPilotVerifier struct {
	PolicyDigest string
	Facts        []generated.GateEvidenceFact
	Bundle       func(context.Context, string) (generated.GateEvidenceBundle, error)
}

func (v IngressPilotVerifier) Verify(ctx context.Context, def Definition, e generated.GateEvidence) (ProofResult, error) {
	deny := ProofResult{ReasonCode: "pilot-evidence-unverified"}
	if v.Bundle == nil || len(v.Facts) == 0 || e.ArtifactDigest != v.PolicyDigest || e.CollectorID != ingress.PilotCollectorID || e.SourceKind != "local" || e.ProofClass != "live" || (def.ID != "platform-safety" && def.ID != ingress.PilotGateID && def.ID != "G-016") {
		return deny, nil
	}
	b, err := v.Bundle(ctx, e.EvidenceID)
	if err != nil {
		return deny, err
	}
	if ingress.Digest(b) != e.BundleDigest || b.CollectorID != ingress.PilotCollectorID || b.ObservedAt != e.ObservedAt || ingress.Digest(b.Facts) != ingress.Digest(v.Facts) || len(b.Checks) != 1 || b.Checks[0].CheckID != "controller-read-pilot" || b.Checks[0].Result != "passed" || b.Checks[0].ResultDigest != ingress.Digest(v.Facts) {
		return deny, nil
	}
	return ProofResult{Verified: true, ReasonCode: "controller-read-pilot-only"}, nil
}

// EvaluateIngressPilot uses the immutable applied evidence lineage as the
// subject. Evidence does not have the unrelated credential activation revision.
// The verifier separately binds its artifact to the current protected policy
// and new observations. Generic uploads still cannot create a live proof.
func EvaluateIngressPilot(ctx context.Context, reader interface {
	CurrentEvidenceReader
	EvidenceReader
}, scope ResolvedScope, subject Subject, gateID string, at time.Time, registry ProofRegistry) (generated.GateEvaluation, error) {
	rows, err := reader.ListCurrentAppliedGateEvidence(ctx, gateID, subject.ID)
	if err != nil {
		return generated.GateEvaluation{}, err
	}
	if len(rows) > 0 {
		latest := rows[0]
		for _, e := range rows[1:] {
			if e.StateRevision > latest.StateRevision {
				latest = e
			}
		}
		subject.DeclarationID, subject.DeclarationRevision, subject.StateRevision, subject.ArtifactDigest = latest.DeclarationID, latest.DeclarationRevision, latest.StateRevision, latest.ArtifactDigest
	}
	e, err := Evaluate(ctx, reader, scope, subject, gateID, at, registry)
	if err == nil && e.Outcome == "passed" {
		e.ReasonCode = "controller-read-pilot-only"
	}
	return e, err
}
