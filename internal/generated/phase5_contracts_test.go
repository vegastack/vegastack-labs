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

func TestCredentialReferenceV11RequiresExactBinding(t *testing.T) {
	valid := map[string]any{
		"schema": SchemaIDCredentialReference, "schemaVersion": "1.1.0",
		"referenceId": "ref-a", "consumerId": "adapter-a", "purposeId": "deploy-a",
		"targetId": "service-a", "resolverId": "native-a", "materialVersion": "version-a",
		"fingerprint": phase5DigestFixture(), "status": "staged", "stateRevision": 2,
		"recoveryEpoch": 1, "activatedAt": nil, "verifiedConsumerIds": []string{},
	}
	if err := ValidateContractJSON(SchemaIDCredentialReference, phase5Document(t, valid), ContractExact); err != nil {
		t.Fatalf("bound v1.1 reference rejected: %v", err)
	}
	delete(valid, "resolverId")
	if err := ValidateContractJSON(SchemaIDCredentialReference, phase5Document(t, valid), ContractExact); err == nil {
		t.Fatal("missing resolver binding accepted")
	}
	valid["resolverId"] = "native-a"
	valid["material"] = "private-value"
	if err := ValidateContractJSON(SchemaIDCredentialReference, phase5Document(t, valid), ContractExact); err == nil {
		t.Fatal("private material field accepted")
	}
}

func validCheckpointV11(t *testing.T) []byte {
	t.Helper()
	return phase5Document(t, map[string]any{
		"schema": SchemaIDAuditCheckpoint, "schemaVersion": "1.1.0", "checkpointId": "checkpoint-a",
		"instanceId": "instance-a", "recoveryEpoch": 2, "firstEventId": 1, "lastEventId": 3,
		"firstSegmentSequence": 1, "lastSegmentSequence": 3, "chainDigest": phase5DigestFixture(),
		"signerReferenceId": "signer-a", "signerMaterialVersion": "version-a",
		"signatureDigest": phase5DigestFixture(), "publicKeyId": "public-key-a",
		"exportReceiptDigest": phase5DigestFixture(), "independentReadDigest": phase5DigestFixture(),
		"status": "anchored", "reasonCode": "independent-match", "preAnchor": false,
		"independentCopyDigest": phase5DigestFixture(), "sourceKind": "independent", "proofClass": "live",
		"verifiedAt": "2026-09-16T08:00:00Z", "verificationStatus": "verified",
	})
}

func TestCheckpointV11RequiresIndependentBindings(t *testing.T) {
	raw := []byte(`{"schema":"vegastack-labs.dev/audit-checkpoint","schemaVersion":"1.1.0","checkpointId":"cp-a"}`)
	if err := ValidateContractJSON(SchemaIDAuditCheckpoint, raw, ContractExact); err == nil {
		t.Fatal("unbound checkpoint accepted")
	}
	if err := ValidateContractJSON(SchemaIDAuditCheckpoint, validCheckpointV11(t), ContractExact); err != nil {
		t.Fatal(err)
	}
	var checkpoint map[string]any
	if err := json.Unmarshal(validCheckpointV11(t), &checkpoint); err != nil {
		t.Fatal(err)
	}
	delete(checkpoint, "independentReadDigest")
	if err := ValidateContractJSON(SchemaIDAuditCheckpoint, phase5Document(t, checkpoint), ContractExact); err == nil {
		t.Fatal("anchored checkpoint without independent read accepted")
	}
}

func TestCredentialReferenceV10CompatibleReadCannotAuthorizeResolution(t *testing.T) {
	legacy := map[string]any{
		"schema": SchemaIDCredentialReference, "schemaVersion": "1.0.0",
		"referenceId": "ref-a", "consumerId": "adapter-a", "purposeId": "deploy-a",
		"materialVersion": "version-a", "fingerprint": phase5DigestFixture(),
		"status": "active", "recoveryEpoch": 1,
	}
	raw := phase5Document(t, legacy)
	if err := ValidateContractJSON(SchemaIDCredentialReference, raw, ContractCompatibleRead); err != nil {
		t.Fatalf("historical credential reference rejected: %v", err)
	}
	if err := ValidateContractJSON(SchemaIDCredentialReference, raw, ContractExact); err == nil {
		t.Fatal("historical credential reference authorized as a current exact binding")
	}
	delete(legacy, "consumerId")
	if err := ValidateContractJSON(SchemaIDCredentialReference, phase5Document(t, legacy), ContractCompatibleRead); err == nil {
		t.Fatal("incomplete historical credential reference accepted")
	}
	legacy["consumerId"] = "adapter-a"
	legacy["privateKey"] = "private-value"
	if err := ValidateContractJSON(SchemaIDCredentialReference, phase5Document(t, legacy), ContractCompatibleRead); err == nil {
		t.Fatal("secret-like historical addition accepted")
	}
}

func validEvidenceV11(t *testing.T) []byte {
	t.Helper()
	return phase5Document(t, map[string]any{
		"schema": SchemaIDGateEvidence, "schemaVersion": "1.1.0", "evidenceId": "evidence-a",
		"gateId": "gate-a", "subjectId": "subject-a", "definitionVersion": "1.0.0", "evaluatorVersion": "1.0.0",
		"releaseBuildId": "release-a", "toolVersion": "1.0.0", "profileId": "profile-a", "profileVersion": "1.0.0",
		"policyId": "policy-a", "policyVersion": "1.0.0", "declarationId": "declaration-a", "declarationRevision": 1,
		"stateRevision": 3, "sourceKind": "local", "proofClass": "live", "collectorId": "collector-a",
		"humanId": "human-a", "artifactDigest": phase5DigestFixture(), "bundleDigest": phase5DigestFixture(),
		"observedAt": "2026-09-15T08:00:00Z", "appliedAt": "2026-09-15T08:05:00Z", "expiresAt": "2026-09-15T09:00:00Z",
		"recoveryEpoch": 2, "supersedesEvidenceId": nil, "revokesEvidenceId": nil, "status": "applied",
	})
}

func TestEvidenceV11RequiresAppliedBindings(t *testing.T) {
	raw := []byte(`{"schema":"vegastack-labs.dev/gate-evidence","schemaVersion":"1.1.0","evidenceId":"e-a","gateId":"g-a","subjectId":"s-a"}`)
	if err := ValidateContractJSON(SchemaIDGateEvidence, raw, ContractExact); err == nil {
		t.Fatal("missing applied version/revision/epoch bindings accepted")
	}
	if err := ValidateContractJSON(SchemaIDGateEvidence, validEvidenceV11(t), ContractExact); err != nil {
		t.Fatal(err)
	}
}

func TestPhase5GateEvidenceRejectsFixturePromotionAndInvalidFreshness(t *testing.T) {
	evidence := map[string]any{}
	if err := json.Unmarshal(validEvidenceV11(t), &evidence); err != nil {
		t.Fatal(err)
	}
	evidence["sourceKind"] = "fixture"
	evidence["proofClass"] = "fixture"
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
		"schema": SchemaIDBackupJob, "schemaVersion": "1.1.0", "jobId": "job-a", "policyId": "policy-a",
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
		"schema": SchemaIDGateEvidenceRequest, "schemaVersion": "1.1.0", "expectedStateRevision": 3,
		"recoveryEpoch": 2, "targetDigest": phase5DigestFixture(), "idempotencyKey": "key-a",
		"evidenceId": "evidence-a", "gateId": "gate-a", "subjectId": "subject-a",
		"definitionVersion": "1.0.0", "evaluatorVersion": "1.0.0",
		"supersedesEvidenceId": nil, "revokesEvidenceId": nil, "artifactDigest": phase5DigestFixture(),
		"observedAt": "2026-09-15T08:00:00Z",
		"bundle": map[string]any{"schema": SchemaIDGateEvidenceBundle, "schemaVersion": "1.1.0",
			"facts": []any{}, "checks": []any{}, "attachments": []any{}, "collectorId": "collector-a", "observedAt": "2026-09-15T08:00:00Z"},
	}
	if err := ValidateContractJSON(SchemaIDGateEvidenceRequest, phase5Document(t, request), ContractExact); err != nil {
		t.Fatal(err)
	}
	request["passGate"] = true
	if err := ValidateContractJSON(SchemaIDGateEvidenceRequest, phase5Document(t, request), ContractExact); err == nil {
		t.Fatal("request accepted caller-issued pass flag")
	}
	delete(request, "passGate")
	delete(request, "recoveryEpoch")
	if err := ValidateContractJSON(SchemaIDGateEvidenceRequest, phase5Document(t, request), ContractExact); err == nil {
		t.Fatal("request without epoch accepted")
	}
	request["recoveryEpoch"] = 2
	request["schemaVersion"] = "1.2.0"
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

func TestPhase5RestoreAndJobRequestsRequireExactBindingFields(t *testing.T) {
	requests := []struct {
		name     string
		schemaID string
		value    map[string]any
	}{
		{"restore", SchemaIDRestoreRunRequest, map[string]any{
			"schema": SchemaIDRestoreRunRequest, "schemaVersion": "1.0.0", "expectedStateRevision": 3,
			"recoveryEpoch": 2, "targetDigest": phase5DigestFixture(), "idempotencyKey": "restore-key",
			"pointId": "point-a", "planId": "plan-a", "planDigest": phase5DigestFixture(),
			"humanAcknowledgementId": "ack-a", "formerControllerFenceDigest": phase5DigestFixture(),
			"priorInstanceId": "instance-old", "newInstanceId": "instance-new",
			"priorRecoveryEpoch": 2, "nextRecoveryEpoch": 3,
		}},
		{"job", SchemaIDScheduledJobRequest, map[string]any{
			"schema": SchemaIDScheduledJobRequest, "schemaVersion": "1.0.0", "expectedStateRevision": 3,
			"recoveryEpoch": 2, "targetDigest": phase5DigestFixture(), "idempotencyKey": "job-key",
			"policyId": "policy-a", "policyRevision": 2, "actionDigest": phase5DigestFixture(),
			"planId": "plan-a", "planDigest": phase5DigestFixture(), "humanAcknowledgementId": "ack-a",
		}},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			if err := ValidateContractJSON(request.schemaID, phase5Document(t, request.value), ContractExact); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"recoveryEpoch", "planDigest", "targetDigest"} {
				original := request.value[field]
				delete(request.value, field)
				if err := ValidateContractJSON(request.schemaID, phase5Document(t, request.value), ContractExact); err == nil {
					t.Errorf("%s request without %s accepted", request.name, field)
				}
				request.value[field] = original
			}
		})
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
