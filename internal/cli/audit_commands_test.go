package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestAuditCommandsRenderOnlySanitizedStateAndIncidentGuidance(t *testing.T) {
	operations := successfulControlOperations(t)
	incident := generated.BrowserAuditVerificationData{
		Schema: generated.SchemaIDBrowserAuditVerificationData, SchemaVersion: "1.0.0", Status: "incident",
		ReasonCode: "independent-checkpoint-ahead", SourceKind: "independent", ProofClass: "live",
		IndependentMatch: false, LastAnchoredSequence: 9, PreAnchor: false, StateRevision: 7, RecoveryEpoch: 2,
		SafeNextAction: "investigate the audit integrity incident",
	}
	operations.auditVerifyResponse = operationResponse(t, "api.v1.audit-history.verification", false, 2, 7, incident)
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{"audit", "verify", "--config", "profile.json"}, nil, WithControlOperations(operations, nil))
	if code != 0 || stderr != "" || !strings.Contains(stdout, "Mutations are blocked") || !strings.Contains(stdout, "independent-checkpoint-ahead") || !strings.Contains(stdout, "Source independent") || !strings.Contains(stdout, "Proof live") || !strings.Contains(stdout, "Safe next action investigate the audit integrity incident") || strings.Contains(stdout, "private-audit-fixture") {
		t.Fatalf("human audit output = code %d stdout %q stderr %q", code, stdout, stderr)
	}
	code, stdout, stderr = runTestAppWithOptions(t, context.Background(), []string{"audit", "checkpoints", "--config", "profile.json", "--output", "json"}, nil, WithControlOperations(operations, nil))
	if code != 0 || stderr != "" || !strings.Contains(stdout, generated.SchemaIDBrowserAuditCheckpointListData) || strings.Contains(stdout, "private-audit-fixture") {
		t.Fatalf("JSON audit output = code %d stdout %q stderr %q", code, stdout, stderr)
	}
}
