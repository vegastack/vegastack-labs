package gate

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"time"
)

// NotificationReadinessVerifier validates the server's actual acknowledged test
// receipts. Its outcome is provider acceptance, never human-read or site silence.
type NotificationReadinessVerifier struct {
	PolicyDigest string
	Epoch        int64
	Now          time.Time
	Receipts     func(context.Context, string) (operations.NotificationReceipts, error)
	Bundle       func(context.Context, string) (generated.GateEvidenceBundle, error)
}

func (v NotificationReadinessVerifier) Verify(ctx context.Context, d Definition, e generated.GateEvidence) (ProofResult, error) {
	deny := ProofResult{ReasonCode: "notification-readiness-unverified"}
	if d.ID != "G-011" || e.GateID != "G-011" || e.SubjectID != "scope" || e.SourceKind != "local" || e.ProofClass != "live" || e.CollectorID != operations.ReadinessCollector || e.ArtifactDigest != v.PolicyDigest || v.Bundle == nil || v.Receipts == nil {
		return deny, nil
	}
	r, err := v.Receipts(ctx, e.EvidenceID)
	if err != nil {
		return deny, err
	}
	observed, err := operations.ValidateNotificationReceipts(r, v.PolicyDigest, v.Epoch, v.Now)
	if err != nil {
		return deny, nil
	}
	want := operations.NotificationBundle(r, observed)
	b, err := v.Bundle(ctx, e.EvidenceID)
	if err != nil {
		return deny, err
	}
	if operations.NotificationDigest(b) != operations.NotificationDigest(want) || operations.NotificationDigest(b) != e.BundleDigest || b.ObservedAt != e.ObservedAt {
		return deny, nil
	}
	return ProofResult{Verified: true, ReasonCode: "provider-accepted-notification-routes"}, nil
}

// EvaluateNotificationReadiness binds the immutable applied evidence lineage;
// current policy/reference checks and actual receipts remain verifier-owned.
func EvaluateNotificationReadiness(ctx context.Context, r interface {
	EvidenceReader
	CurrentEvidenceReader
}, s ResolvedScope, subject Subject, at time.Time, v NotificationReadinessVerifier) (generated.GateEvaluation, error) {
	rows, err := r.ListCurrentAppliedGateEvidence(ctx, "G-011", subject.ID)
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
		subject.DeclarationID = latest.DeclarationID
		subject.DeclarationRevision = latest.DeclarationRevision
		subject.StateRevision = latest.StateRevision
		subject.ArtifactDigest = latest.ArtifactDigest
	}
	registry := NewProofRegistry()
	registry.Register("G-011", "local", v)
	return Evaluate(ctx, r, s, subject, "G-011", at, registry)
}
