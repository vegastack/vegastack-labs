package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestAuditCommandsRenderOnlySanitizedStateAndIncidentGuidance(t *testing.T) {
	operations := successfulControlOperations(t)
	independent := "sha256:" + strings.Repeat("7", 64)
	incident := generated.AuditVerificationData{
		Schema: generated.SchemaIDAuditVerificationData, SchemaVersion: "1.1.0", Status: "incident", InstanceID: "instance-a",
		RecoveryEpoch: 2, LocalDigest: "sha256:" + strings.Repeat("6", 64), IndependentDigest: &independent,
		IndependentMatch: false, LastAnchoredSequence: 9, ReasonCode: "independent-checkpoint-ahead", PreAnchor: false,
	}
	operations.auditVerifyResponse = operationResponse(t, "api.v1.audit-history.verification", false, 2, 7, incident)
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{"audit", "verify", "--config", "profile.json"}, nil, WithControlOperations(operations, nil))
	if code != 0 || stderr != "" || !strings.Contains(stdout, "Mutations are blocked") || !strings.Contains(stdout, "independent-checkpoint-ahead") || strings.Contains(stdout, "private-audit-fixture") {
		t.Fatalf("human audit output = code %d stdout %q stderr %q", code, stdout, stderr)
	}
	code, stdout, stderr = runTestAppWithOptions(t, context.Background(), []string{"audit", "checkpoints", "--config", "profile.json", "--output", "json"}, nil, WithControlOperations(operations, nil))
	if code != 0 || stderr != "" || !strings.Contains(stdout, generated.SchemaIDAuditCheckpointListData) || strings.Contains(stdout, "private-audit-fixture") {
		t.Fatalf("JSON audit output = code %d stdout %q stderr %q", code, stdout, stderr)
	}
}
