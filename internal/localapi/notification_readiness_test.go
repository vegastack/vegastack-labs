package localapi

import (
	"bytes"
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"net/http"
	"testing"
)

func TestNotificationReadinessClientAcceptsInertMutationEnvelopeOnlyOnFixedRoute(t *testing.T) {
	d := operations.Digest("fixture")
	doc := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: "notification-test-a", DeclarationType: "notification-readiness", Revision: 1, StateRevision: 5, RecoveryEpoch: 2, ContentDigest: d, Status: "draft", CreatedAt: "2026-10-28T00:00:00Z", CreatedBy: "human-a", AgentSessionID: "session-a", Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "notification-readiness", OperationType: operations.ReadinessOperation, AdapterID: operations.ReadinessAdapter, TargetID: "routes-test", InputDigest: d, ArtifactDigest: d}}}
	raw, p, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.operations.notification-readiness", true, 2, 5, doc))
	q := generated.NotificationReadinessRequest{Schema: generated.SchemaIDNotificationReadinessRequest, SchemaVersion: "1.0.0", Action: "canary-draft", RequestID: "test-a", ExpectedStateRevision: 4, RecoveryEpoch: 2}
	r, e := NewClient(clientTestFactory()).NotificationReadiness(context.Background(), p, q)
	req := <-captured
	if e != nil || !bytes.Equal(raw, r.Raw) || req.path != "/api/v1/operations/notification-readiness" || req.method != "POST" || bytes.Contains(req.body, []byte("webhook")) {
		t.Fatal(req, e)
	}
	q.Action = "send-now"
	if _, e = NewClient(clientTestFactory()).NotificationReadiness(context.Background(), p, q); e == nil {
		t.Fatal("direct send action accepted")
	}
}
