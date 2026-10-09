package localapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestGrantBatchClientBindsExactDraft(t *testing.T) {
	input := generated.AuthorizationGrantBatchRequest{Schema: generated.SchemaIDAuthorizationGrantBatchRequest, SchemaVersion: "1.0.0", PrincipalID: "human-a", ExpectedGrantRevision: 1, ExpectedStateRevision: 4, RecoveryEpoch: 2, IdempotencyKey: "grant-test", ReasonDigest: hostaction.Digest("reason"), Changes: []generated.AuthorizationGrantChange{{Schema: generated.SchemaIDAuthorizationGrantChange, SchemaVersion: "1.0.0", GrantID: "read-a", Change: "add", RoleID: "reader", Action: "read", Capability: "host.read", ResourceKind: "host", ResourceID: "host-a"}}}
	sum := sha256.Sum256([]byte(input.PrincipalID))
	id := "authorization-policy-" + hex.EncodeToString(sum[:16])
	for _, variant := range []string{"valid", "subject", "epoch", "revision", "operation"} {
		t.Run(variant, func(t *testing.T) {
			batch := input
			batch.Changes = append([]generated.AuthorizationGrantChange(nil), input.Changes...)
			doc := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: id, DeclarationType: "authorization.policy", Revision: 1, StateRevision: 5, RecoveryEpoch: 2, ContentDigest: hostaction.Digest("document"), Status: "draft", CreatedAt: "2026-10-10T00:00:00Z", CreatedBy: "human-a", AgentSessionID: "session-a", AuthorizationGrantBatch: &batch, Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "grant-batch", OperationType: "identity.change", AdapterID: "core.authorization", TargetID: "human-a", InputDigest: hostaction.Digest(input), ArtifactDigest: hostaction.Digest("core.authorization@1")}}}
			switch variant {
			case "subject":
				doc.AuthorizationGrantBatch.PrincipalID = "human-b"
			case "epoch":
				doc.RecoveryEpoch = 3
			case "revision":
				doc.Revision = 2
			case "operation":
				doc.Operations[0].TargetID = "human-b"
			}
			_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.authorization.grant-batches.create", true, doc.RecoveryEpoch, 5, doc))
			_, err := NewClient(clientTestFactory()).DraftAuthorizationGrants(context.Background(), profile, input)
			req := <-captured
			if req.method != "POST" || req.path != "/api/v1/authorization/grant-batches" {
				t.Fatal("wrong route", req)
			}
			if variant == "valid" && err != nil {
				t.Fatal(err)
			}
			if variant != "valid" && err == nil {
				t.Fatal("mismatched grant response accepted")
			}
		})
	}
}
