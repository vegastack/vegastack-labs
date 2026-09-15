package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func syntheticGateRequest(t *testing.T, command string) []byte {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	var value any
	switch command {
	case generated.CommandNameGateEvidence:
		bundle := generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", Facts: []generated.GateEvidenceFact{}, Checks: []generated.GateEvidenceCheck{}, Attachments: []generated.GateEvidenceAttachment{}, CollectorID: "collector-test", ObservedAt: "2026-09-15T00:00:00Z"}
		value = generated.GateEvidenceRequest{Schema: generated.SchemaIDGateEvidenceRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-test", EvidenceID: "evidence-test", GateID: "G-008", SubjectID: "site-a", DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", ArtifactDigest: digest, ObservedAt: bundle.ObservedAt, Bundle: bundle}
	case generated.CommandNameGateProfileDraft:
		value = generated.GateProfileDraftRequest{Schema: generated.SchemaIDGateProfileDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "key-test", BindingID: "binding-test", ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-test", PolicyVersion: "1.0.0", Capabilities: []string{}}
	default:
		t.Fatal("unexpected command")
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
