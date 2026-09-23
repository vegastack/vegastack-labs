package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func syntheticRestoreValues() (generated.RestoreRequest, generated.RestoreRunRequest, generated.RestoreVerifyRequest) {
	digest := "sha256:" + strings.Repeat("a", 64)
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "point-a", PointDigest: digest, ManifestDigest: digest, VerificationDigest: digest, SourceClass: "local", RepositoryGenerationID: "generation-a", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: 2, DependencyDigests: []string{digest}}
	plan := generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 8, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "restore-a", Source: source, Fences: []generated.RestoreFenceItem{{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: "host-service", SubjectID: "former-host", Required: true, EvidenceIDs: []string{"evidence-a"}, EvidenceDigest: digest, ObservedAt: "2026-09-24T05:30:00Z", Status: "verified"}}, AuditDecision: generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 4, IndependentLastEventID: 4, IndependentCheckpointDigest: digest, Strategy: "matched", DecisionDigest: digest}, PointID: "point-a", DependencyIDs: []string{"dependency-a"}, TargetIDs: []string{"control-a"}, PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: 2, NextRecoveryEpoch: 3, FenceSetDigest: digest, AuditDecisionDigest: digest, CandidateDigest: digest}
	run := generated.RestoreRunRequest{Schema: generated.SchemaIDRestoreRunRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 10, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "restore-run-a", Source: source, PointID: "point-a", PlanID: "plan-a", PlanDigest: digest, HumanAcknowledgementID: "ack-a", FenceSetDigest: digest, AuditDecisionDigest: digest, CandidateDigest: digest, PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: 2, NextRecoveryEpoch: 3}
	verify := generated.RestoreVerifyRequest{Schema: generated.SchemaIDRestoreVerifyRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 11, RecoveryEpoch: 3, TargetDigest: digest, IdempotencyKey: "restore-verify-a", Source: source, PointID: "point-a", PlanID: "plan-a", PlanDigest: digest, PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: 2, NextRecoveryEpoch: 3, FenceSetDigest: digest, AuditDecisionDigest: digest, CandidateDigest: digest}
	return plan, run, verify
}

func syntheticRestoreRequest(t *testing.T, command string) []byte {
	t.Helper()
	plan, run, verify := syntheticRestoreValues()
	var value any
	switch command {
	case generated.CommandNameRestorePlan:
		value = plan
	case generated.CommandNameRestoreRun:
		value = run
	case generated.CommandNameRestoreVerify:
		value = verify
	default:
		t.Fatalf("unknown restore command %s", command)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
