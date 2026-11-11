package servicecatalog

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestDeploymentReconciliationContract(t *testing.T) {
	// Decode through the generated public shape so the original contract is red
	// before the optional selector and action are introduced.
	raw := []byte(`{"schema":"vegastack-labs.dev/service-deployment-draft-request","schemaVersion":"1.0.0","serviceId":"service-a","artifactId":"image-a","action":"reconcile","expectedStateRevision":1,"recoveryEpoch":0,"idempotencyKey":"recover-a","reasonDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","recovery":{"schema":"vegastack-labs.dev/service-deployment-recovery","schemaVersion":"1.0.0","priorPlanId":"plan-a","priorRunId":"run-a","priorStepId":"step-a","priorRequestDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","providerReceiptId":"receipt-a"}}`)
	if err := generated.ValidateContractJSON(generated.SchemaIDServiceDeploymentDraftRequest, raw, generated.ContractExact); err != nil {
		t.Fatalf("explicit reconciliation rejected: %v", err)
	}
	var q generated.ServiceDeploymentDraftRequest
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentRecoveryOptionalBytesAndActionIsolation(t *testing.T) {
	q := generated.ServiceDeploymentDraftRequest{Schema: generated.SchemaIDServiceDeploymentDraftRequest, SchemaVersion: "1.0.0", ServiceID: "service-a", ArtifactID: "image-a", Action: "deploy", ExpectedStateRevision: 1, IdempotencyKey: "deploy-a", ReasonDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	raw, _ := json.Marshal(q)
	const old = `{"schema":"vegastack-labs.dev/service-deployment-draft-request","schemaVersion":"1.0.0","serviceId":"service-a","artifactId":"image-a","action":"deploy","expectedStateRevision":1,"recoveryEpoch":0,"idempotencyKey":"deploy-a","reasonDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	if string(raw) != old {
		t.Fatalf("old canonical bytes changed: %s", raw)
	}
}
