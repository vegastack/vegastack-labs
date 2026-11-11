package api

import (
	"bytes"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"net/http/httptest"
	"testing"
)

func TestDeploymentDraftDecodesOptionalRecoveryExactly(t *testing.T) {
	q := generated.ServiceDeploymentDraftRequest{Schema: generated.SchemaIDServiceDeploymentDraftRequest, SchemaVersion: "1.0.0", ServiceID: "service-a", ArtifactID: "image-a", Action: "reconcile", IdempotencyKey: "reconcile-a", ReasonDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Recovery: &generated.ServiceDeploymentRecovery{Schema: generated.SchemaIDServiceDeploymentRecovery, SchemaVersion: "1.0.0", PriorPlanID: "plan-a", PriorRunID: "run-a", PriorStepID: "step-a", PriorRequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ProviderReceiptID: "receipt-a"}}
	raw, _ := json.Marshal(q)
	request := httptest.NewRequest("POST", "/api/v1/services/deployment-drafts", bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	var got generated.ServiceDeploymentDraftRequest
	if e := decodeOperationRequest(request, 16384, []string{"schema", "schemaVersion", "serviceId", "artifactId", "action", "expectedStateRevision", "recoveryEpoch", "idempotencyKey", "reasonDigest"}, &got, "recovery"); e != nil {
		t.Fatal(e)
	}
	again, _ := json.Marshal(got)
	if string(raw) != string(again) {
		t.Fatal("recovery selector changed in decoding")
	}
}
