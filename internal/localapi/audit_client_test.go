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
	checkpoints := generated.AuditCheckpointListData{Schema: generated.SchemaIDAuditCheckpointListData, SchemaVersion: "1.0.0", Checkpoints: []generated.AuditCheckpoint{}, RecoveryEpoch: 2}
	raw, profile, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.audit-checkpoints.list", false, 2, 7, checkpoints))
	response, err := NewClient(clientTestFactory()).AuditCheckpoints(context.Background(), profile)
	request := <-captured
	if err != nil || !bytes.Equal(response.Raw, raw) || request.method != http.MethodGet || request.path != "/api/v1/audit-checkpoints" || len(request.body) != 0 {
		t.Fatalf("checkpoint response/request = %#v/%#v err=%v", response, request, err)
	}

	verification := generated.AuditVerificationData{Schema: generated.SchemaIDAuditVerificationData, SchemaVersion: "1.1.0", Status: "degraded", InstanceID: "instance-a", RecoveryEpoch: 2, LocalDigest: digest, IndependentMatch: false, LastAnchoredSequence: 0, ReasonCode: "no-independent-anchor", PreAnchor: false}
	raw, profile, captured = serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.audit-history.verification", false, 2, 7, verification))
	verified, err := NewClient(clientTestFactory()).VerifyAudit(context.Background(), profile)
	request = <-captured
	if err != nil || !bytes.Equal(verified.Raw, raw) || request.method != http.MethodGet || request.path != "/api/v1/audit-history/verification" || bytes.Contains(verified.Raw, []byte("private-audit-fixture")) {
		t.Fatalf("verification response/request = %#v/%#v err=%v", verified, request, err)
	}
}
