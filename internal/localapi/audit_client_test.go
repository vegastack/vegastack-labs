package localapi

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestAuditClientUsesFixedSanitizedRoutes(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	checkpoint := generated.BrowserAuditCheckpoint{Schema: generated.SchemaIDBrowserAuditCheckpoint, SchemaVersion: "1.0.0", CheckpointID: "checkpoint-a", FirstEventID: 1, LastEventID: 2, ChainDigest: digest, Status: "anchored", ReasonCode: "verified", SourceKind: "independent", ProofClass: "live", VerificationStatus: "verified", RecoveryEpoch: 2}
	checkpoints := generated.BrowserAuditCheckpointListData{Schema: generated.SchemaIDBrowserAuditCheckpointListData, SchemaVersion: "1.0.0", Items: []generated.BrowserAuditCheckpoint{checkpoint}, StateRevision: 7, RecoveryEpoch: 2}
	raw, profile, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.audit-checkpoints.list", false, 2, 7, checkpoints))
	response, err := NewClient(clientTestFactory()).AuditCheckpoints(context.Background(), profile)
	request := <-captured
	if err != nil || !bytes.Equal(response.Raw, raw) || request.method != http.MethodGet || request.path != "/api/v1/audit-checkpoints" || len(request.body) != 0 || len(response.Data.Checkpoints) != 1 || response.Data.Checkpoints[0].CheckpointID != checkpoint.CheckpointID {
		t.Fatalf("checkpoint response/request = %#v/%#v err=%v", response, request, err)
	}

	verification := generated.BrowserAuditVerificationData{Schema: generated.SchemaIDBrowserAuditVerificationData, SchemaVersion: "1.0.0", Status: "degraded", ReasonCode: "no-independent-anchor", SourceKind: "none", ProofClass: "none", IndependentMatch: false, LastAnchoredSequence: 0, PreAnchor: false, StateRevision: 7, RecoveryEpoch: 2, SafeNextAction: "collect and compare an independent audit checkpoint"}
	raw, profile, captured = serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.audit-history.verification", false, 2, 7, verification))
	verified, err := NewClient(clientTestFactory()).VerifyAudit(context.Background(), profile)
	request = <-captured
	if err != nil || !bytes.Equal(verified.Raw, raw) || request.method != http.MethodGet || request.path != "/api/v1/audit-history/verification" || verified.Data.Status != "degraded" || bytes.Contains(verified.Raw, []byte("private-audit-fixture")) {
		t.Fatalf("verification response/request = %#v/%#v err=%v", verified, request, err)
	}
}

func TestAuditClientRejectsObsoletePrivateAndMisbindingResponses(t *testing.T) {
	private := generated.AuditCheckpointListData{Schema: generated.SchemaIDAuditCheckpointListData, SchemaVersion: "1.0.0", Checkpoints: []generated.AuditCheckpoint{}, RecoveryEpoch: 2}
	_, profile, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.audit-checkpoints.list", false, 2, 7, private))
	if _, err := NewClient(clientTestFactory()).AuditCheckpoints(context.Background(), profile); err == nil {
		t.Fatal("obsolete private audit checkpoint response passed browser-contract validation")
	}
	<-captured

	mismatched := generated.BrowserAuditVerificationData{Schema: generated.SchemaIDBrowserAuditVerificationData, SchemaVersion: "1.0.0", Status: "pending", ReasonCode: "no-independent-anchor", SourceKind: "none", ProofClass: "none", StateRevision: 8, RecoveryEpoch: 2, SafeNextAction: "collect an independent audit checkpoint"}
	_, profile, captured = serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.audit-history.verification", false, 2, 7, mismatched))
	if _, err := NewClient(clientTestFactory()).VerifyAudit(context.Background(), profile); err == nil {
		t.Fatal("audit verification with a mismatched state revision passed validation")
	}
	<-captured
}
