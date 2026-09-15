package generated

import (
	"encoding/json"
	"strings"
	"testing"
)

func phase5Document(t *testing.T, value map[string]any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func phase5DigestFixture() string { return "sha256:" + strings.Repeat("a", 64) }

func TestPhase5GateEvidenceRejectsFixturePromotionAndInvalidFreshness(t *testing.T) {
	evidence := map[string]any{
		"schema": SchemaIDGateEvidence, "schemaVersion": "1.0.0", "evidenceId": "evidence-a",
		"gateId": "gate-a", "subjectId": "subject-a", "definitionVersion": "1.0.0", "evaluatorVersion": "1.0.0",
		"sourceKind": "fixture", "proofClass": "fixture", "artifactDigest": phase5DigestFixture(),
		"observedAt": "2026-09-15T08:00:00Z", "expiresAt": "2026-09-15T09:00:00Z", "recoveryEpoch": 2, "status": "applied",
	}
	if err := ValidateContractJSON(SchemaIDGateEvidence, phase5Document(t, evidence), ContractExact); err != nil {
		t.Fatal(err)
	}
	evidence["proofClass"] = "live"
	if err := ValidateContractJSON(SchemaIDGateEvidence, phase5Document(t, evidence), ContractExact); err == nil {
		t.Fatal("fixture evidence promoted to live")
	}
	evidence["proofClass"] = "fixture"
	evidence["expiresAt"] = "2026-09-15T07:00:00Z"
	if err := ValidateContractJSON(SchemaIDGateEvidence, phase5Document(t, evidence), ContractExact); err == nil {
		t.Fatal("stale evidence accepted")
	}
}

func TestPhase5NestedBackupStatusRejectsFixturePromotion(t *testing.T) {
	job := map[string]any{
		"schema": SchemaIDBackupJob, "schemaVersion": "1.0.0", "jobId": "job-a", "policyId": "policy-a",
		"sourceKind": "fixture", "proofClass": "live", "pointId": nil, "status": "queued", "runId": nil,
		"recoveryEpoch": 2, "verificationDigest": nil,
	}
	status := map[string]any{
		"schema": SchemaIDBackupStatusData, "schemaVersion": "1.0.0", "policies": []any{}, "jobs": []any{job}, "recoveryEpoch": 2,
	}
	if err := ValidateContractJSON(SchemaIDBackupStatusData, phase5Document(t, status), ContractExact); err == nil {
		t.Fatal("nested fixture backup claimed live proof")
	}
}

func TestPhase5RestoreBindingRejectsAmbiguousEpochAndController(t *testing.T) {
	binding := map[string]any{
		"schema": SchemaIDRestoreBinding, "schemaVersion": "1.0.0", "pointId": "point-a",
		"dependencyIds": []string{"point-b"}, "targetIds": []string{"control-a"}, "targetDigest": phase5DigestFixture(),
		"planId": "plan-a", "planDigest": phase5DigestFixture(), "humanAcknowledgementId": "ack-a",
		"formerControllerFenceDigest": phase5DigestFixture(), "priorInstanceId": "instance-old", "newInstanceId": "instance-new",
		"priorRecoveryEpoch": 2, "nextRecoveryEpoch": 3, "status": "planned",
	}
	if err := ValidateContractJSON(SchemaIDRestoreBinding, phase5Document(t, binding), ContractExact); err != nil {
		t.Fatal(err)
	}
	binding["nextRecoveryEpoch"] = 2
	if err := ValidateContractJSON(SchemaIDRestoreBinding, phase5Document(t, binding), ContractExact); err == nil {
		t.Fatal("non-incremented recovery epoch accepted")
	}
	binding["nextRecoveryEpoch"] = 3
	binding["newInstanceId"] = "instance-old"
	if err := ValidateContractJSON(SchemaIDRestoreBinding, phase5Document(t, binding), ContractExact); err == nil {
		t.Fatal("same controller instance accepted")
	}
}

func TestPhase5ClosedRequestAndCompatibleRead(t *testing.T) {
	request := map[string]any{
		"schema": SchemaIDGateEvidenceRequest, "schemaVersion": "1.0.0", "expectedStateRevision": 3,
		"recoveryEpoch": 2, "targetDigest": phase5DigestFixture(), "idempotencyKey": "key-a",
		"evidenceId": "evidence-a", "gateId": "gate-a", "subjectId": "subject-a",
		"definitionVersion": "1.0.0", "evaluatorVersion": "1.0.0", "artifactDigest": phase5DigestFixture(),
		"observedAt": "2026-09-15T08:00:00Z",
	}
	if err := ValidateContractJSON(SchemaIDGateEvidenceRequest, phase5Document(t, request), ContractExact); err != nil {
		t.Fatal(err)
	}
	request["proofClass"] = "live"
	if err := ValidateContractJSON(SchemaIDGateEvidenceRequest, phase5Document(t, request), ContractExact); err == nil {
		t.Fatal("request accepted caller-issued proof class")
	}
	delete(request, "proofClass")
	delete(request, "recoveryEpoch")
	if err := ValidateContractJSON(SchemaIDGateEvidenceRequest, phase5Document(t, request), ContractExact); err == nil {
		t.Fatal("request without epoch accepted")
	}
	request["recoveryEpoch"] = 2
	request["schemaVersion"] = "1.1.0"
	request["x-display"] = "safe"
	if err := ValidateContractJSON(SchemaIDGateEvidenceRequest, phase5Document(t, request), ContractCompatibleRead); err != nil {
		t.Fatal(err)
	}
	if err := ValidateContractJSON(SchemaIDGateEvidenceRequest, phase5Document(t, request), ContractExact); err == nil {
		t.Fatal("exact request accepted additive version")
	}
	request["x-password"] = "private-canary"
	if err := ValidateContractJSON(SchemaIDGateEvidenceRequest, phase5Document(t, request), ContractCompatibleRead); err == nil {
		t.Fatal("compatible request accepted secret-shaped addition")
	}
	delete(request, "x-password")
	request["schemaVersion"] = "2.0.0"
	if err := ValidateContractJSON(SchemaIDGateEvidenceRequest, phase5Document(t, request), ContractCompatibleRead); err == nil {
		t.Fatal("unknown major accepted")
	}
}

func TestPhase5ScheduledJobBindingRejectsWidening(t *testing.T) {
	policy := ScheduledJobPolicy{
		Schema: SchemaIDScheduledJobPolicy, SchemaVersion: "1.0.0", PolicyID: "policy-a", Revision: 2,
		ActionKind: "backup", ExactTargetIDs: []string{"control-a"}, ActionDigest: phase5DigestFixture(),
		TargetDigest: phase5DigestFixture(), IntervalSeconds: 3600, Enabled: true, RecoveryEpoch: 2,
	}
	job := ScheduledJob{
		Schema: SchemaIDScheduledJob, SchemaVersion: "1.0.0", JobID: "job-a", PolicyID: "policy-a",
		PolicyRevision: 2, ActionDigest: phase5DigestFixture(), TargetDigest: phase5DigestFixture(),
		Status: "queued", RecoveryEpoch: 2,
	}
	if err := ValidateScheduledJobBinding(policy, job); err != nil {
		t.Fatal(err)
	}
	job.Status = "authorized"
	encoded, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateContractJSON(SchemaIDScheduledJob, encoded, ContractExact); err == nil {
		t.Fatal("unknown scheduled state accepted")
	}
	job.Status = "queued"
	job.TargetDigest = "sha256:" + strings.Repeat("b", 64)
	if err := ValidateScheduledJobBinding(policy, job); err == nil {
		t.Fatal("scheduled job widened targets")
	}
	job.TargetDigest = phase5DigestFixture()
	job.ActionDigest = "sha256:" + strings.Repeat("b", 64)
	if err := ValidateScheduledJobBinding(policy, job); err == nil {
		t.Fatal("scheduled job changed action")
	}
	job.ActionDigest = phase5DigestFixture()
	job.RecoveryEpoch = 3
	if err := ValidateScheduledJobBinding(policy, job); err == nil {
		t.Fatal("scheduled job changed epoch")
	}
}
