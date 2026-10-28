package gate

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
)

type pilotEvidenceReader struct{ rows []generated.GateEvidence }

func (r pilotEvidenceReader) ListAppliedGateEvidence(context.Context, string, string) ([]generated.GateEvidence, error) {
	return r.rows, nil
}
func (r pilotEvidenceReader) ListCurrentAppliedGateEvidence(context.Context, string, string) ([]generated.GateEvidence, error) {
	return r.rows, nil
}

func TestIngressPilotAcknowledgedEvidenceRequiresCurrentServerFacts(t *testing.T) {
	at := time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)
	facts := []generated.GateEvidenceFact{{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "pilot.policy", ValueDigest: ingress.Digest("policy")}}
	bundle := ingress.PilotBundle(facts, at.Add(-time.Minute))
	base := validAppliedFixture(at)
	base.GateID, base.SubjectID, base.CollectorID = ingress.PilotGateID, "scope", ingress.PilotCollectorID
	base.ArtifactDigest, base.BundleDigest, base.ObservedAt = ingress.Digest("protected-policy"), ingress.Digest(bundle), bundle.ObservedAt
	scope := ResolvedScope{ProfileID: base.ProfileID, ProfileVersion: base.ProfileVersion, PolicyID: base.PolicyID, PolicyVersion: base.PolicyVersion, Capabilities: []string{ingress.PilotCapability}, StateRevision: 99, RecoveryEpoch: base.RecoveryEpoch}
	subject := Subject{ID: "scope", Kind: "site", ReleaseBuildID: base.ReleaseBuildID, ToolVersion: base.ToolVersion, StateRevision: 99}
	registry := NewProofRegistry()
	registry.Register(ingress.PilotGateID, "local", IngressPilotVerifier{PolicyDigest: base.ArtifactDigest, Facts: facts, Bundle: func(context.Context, string) (generated.GateEvidenceBundle, error) { return bundle, nil }})
	e, err := EvaluateIngressPilot(context.Background(), pilotEvidenceReader{[]generated.GateEvidence{base}}, scope, subject, ingress.PilotGateID, at, registry)
	if err != nil || e.Outcome != "passed" || e.ReasonCode != "controller-read-pilot-only" {
		t.Fatalf("current pilot proof: %+v %v", e, err)
	}
	for name, mutate := range map[string]func(*generated.GateEvidence){
		"upload":    func(e *generated.GateEvidence) { e.SourceKind, e.ProofClass = "fixture", "fixture" },
		"epoch":     func(e *generated.GateEvidence) { e.RecoveryEpoch++ },
		"scope":     func(e *generated.GateEvidence) { e.ArtifactDigest = ingress.Digest("foreign-policy") },
		"collector": func(e *generated.GateEvidence) { e.CollectorID = "claimed-collector" },
		"expired":   func(e *generated.GateEvidence) { e.ExpiresAt = at.Add(-time.Second).Format(time.RFC3339) },
		"revoked":   func(e *generated.GateEvidence) { e.Status = "revoked" },
	} {
		t.Run(name, func(t *testing.T) {
			row := base
			mutate(&row)
			e, err := EvaluateIngressPilot(context.Background(), pilotEvidenceReader{[]generated.GateEvidence{row}}, scope, subject, ingress.PilotGateID, at, registry)
			if err != nil || e.Outcome == "passed" {
				t.Fatalf("unsafe proof: %+v %v", e, err)
			}
		})
	}
	changed := append([]generated.GateEvidenceFact{}, facts...)
	changed[0].ValueDigest = ingress.Digest("changed-credential-or-origin")
	registry.Register(ingress.PilotGateID, "local", IngressPilotVerifier{PolicyDigest: base.ArtifactDigest, Facts: changed, Bundle: func(context.Context, string) (generated.GateEvidenceBundle, error) { return bundle, nil }})
	e, err = EvaluateIngressPilot(context.Background(), pilotEvidenceReader{[]generated.GateEvidence{base}}, scope, subject, ingress.PilotGateID, at, registry)
	if err != nil || e.Outcome == "passed" {
		t.Fatal("changed live facts retained authority")
	}
	full, err := Evaluate(context.Background(), pilotEvidenceReader{}, scope, subject, "G-012", at, registry)
	if err != nil || full.Outcome != "blocked" {
		t.Fatalf("full gate was waived: %+v %v", full, err)
	}
}
