package gate

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"testing"
	"time"
)

func TestNotificationReadinessUsesAppliedLineageAndDeniesChangedReceiptScope(t *testing.T) {
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Second)
	r := operations.NotificationReceipts{ReferenceDigest: operations.Digest("refs"), RunID: "run-test", PlanID: "plan-test", PlanDigest: operations.Digest("plan"), StepID: "step-test", LeaseID: "lease-test", PolicyDigest: operations.Digest("policy"), HumanID: "human-test"}
	for _, phase := range []string{"failure", "recovery"} {
		state := "open"
		if phase == "recovery" {
			state = "closed"
		}
		r.Receipts = append(r.Receipts, operations.NotificationReceipt{Route: "github", Phase: phase, ProviderID: 17, State: state, AcceptedAt: at.Add(-time.Minute).Format(time.RFC3339), ResponseDigest: operations.Digest(state)}, operations.NotificationReceipt{Route: "slack", Phase: phase, State: "provider-accepted", AcceptedAt: at.Add(-time.Minute).Format(time.RFC3339), ResponseDigest: operations.Digest("ok")})
	}
	bundle := operations.NotificationBundle(r, at.Add(-time.Minute))
	e := validAppliedFixture(at)
	e.GateID = "G-011"
	e.SubjectID = "scope"
	e.CollectorID = operations.ReadinessCollector
	e.ArtifactDigest = r.PolicyDigest
	e.BundleDigest = operations.NotificationDigest(bundle)
	e.ObservedAt = bundle.ObservedAt
	scope := ResolvedScope{ProfileID: e.ProfileID, ProfileVersion: e.ProfileVersion, PolicyID: e.PolicyID, PolicyVersion: e.PolicyVersion, StateRevision: 999}
	subject := Subject{ID: "scope", Kind: "site", ReleaseBuildID: e.ReleaseBuildID, ToolVersion: e.ToolVersion, StateRevision: 999}
	v := NotificationReadinessVerifier{PolicyDigest: r.PolicyDigest, Now: at, Receipts: func(context.Context, string) (operations.NotificationReceipts, error) { return r, nil }, Bundle: func(context.Context, string) (generated.GateEvidenceBundle, error) { return bundle, nil }}
	reader := pilotEvidenceReader{[]generated.GateEvidence{e}}
	actual, err := EvaluateNotificationReadiness(ctx, reader, scope, subject, at, v)
	if err != nil || actual.Outcome != "passed" {
		t.Fatal(actual, err)
	}
	unbound, err := Evaluate(ctx, reader, scope, subject, "G-011", at, NewProofRegistry())
	if err != nil || unbound.Outcome == "passed" {
		t.Fatal("generic evaluator weakened", unbound, err)
	}
	for name, change := range map[string]func(*generated.GateEvidence){"fixture": func(e *generated.GateEvidence) { e.SourceKind = "fixture"; e.ProofClass = "fixture" }, "expired": func(e *generated.GateEvidence) { e.ExpiresAt = at.Add(-time.Second).Format(time.RFC3339) }, "epoch": func(e *generated.GateEvidence) { e.RecoveryEpoch++ }, "revoked": func(e *generated.GateEvidence) { e.Status = "revoked" }, "policy": func(e *generated.GateEvidence) { e.ArtifactDigest = operations.Digest("other") }, "collector": func(e *generated.GateEvidence) { e.CollectorID = "uploaded-claim" }} {
		t.Run(name, func(t *testing.T) {
			bad := e
			change(&bad)
			got, err := EvaluateNotificationReadiness(ctx, pilotEvidenceReader{[]generated.GateEvidence{bad}}, scope, subject, at, v)
			if err != nil || got.Outcome == "passed" {
				t.Fatal(got, err)
			}
		})
	}
	r.Receipts = r.Receipts[:3]
	got, err := EvaluateNotificationReadiness(ctx, reader, scope, subject, at, v)
	if err != nil || got.Outcome == "passed" {
		t.Fatal("incomplete receipt passed", got, err)
	}
}
