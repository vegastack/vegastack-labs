package plan

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestRestorePlanPreservesExactFenceAuditAndAuthorityBinding(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-a", PointDigest: digest, ManifestDigest: digest, VerificationDigest: digest, SourceClass: "local", RepositoryGenerationID: "generation-a", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: 2, DependencyDigests: []string{digest}}
	fences := []generated.RestoreFenceItem{{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: "host-service", SubjectID: "former-host", Required: true, EvidenceIDs: []string{"evidence-a"}, EvidenceDigest: digest, ObservedAt: "2026-09-24T05:30:00Z", Status: "verified"}}
	decision := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 4, IndependentLastEventID: 4, IndependentCheckpointDigest: digest, Strategy: "matched", DecisionDigest: digest}
	request := generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 8, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "restore-a", Source: source, Fences: fences, AuditDecision: decision, PointID: source.PointID, DependencyIDs: []string{"dependency-a"}, TargetIDs: []string{"control-a"}, PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: 2, NextRecoveryEpoch: 3, FenceSetDigest: digest, AuditDecisionDigest: digest, CandidateDigest: digest}
	declaration, err := change.BuildRestoreChange(context.Background(), request, source, fences, decision)
	if err != nil {
		t.Fatal(err)
	}
	result, binding, err := BuildRestorePlan(context.Background(), declaration, request, source, fences, decision)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "planned" || result.AuthorizationBranch != "human" || result.ExecutorMode != "central" || result.Risk != "control-plane" || len(result.Operations) != 1 || binding.PlanID != result.PlanID || binding.PlanDigest != result.PlanDigest || binding.FenceSetDigest != request.FenceSetDigest || binding.AuditDecisionDigest != request.AuditDecisionDigest || binding.PriorInstanceID != request.PriorInstanceID || binding.NewInstanceID != request.NewInstanceID || binding.NextRecoveryEpoch != binding.PriorRecoveryEpoch+1 {
		t.Fatalf("plan=%#v binding=%#v", result, binding)
	}
}
