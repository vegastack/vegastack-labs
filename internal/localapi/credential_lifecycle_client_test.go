package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestLifecycleClientUsesFiniteRouteAndRejectsSubstitutedSubmission(t *testing.T) {
	draft := "draft-a"
	input := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", Action: "credential.stage", DraftID: &draft, ReferenceID: "reference-a", MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{}, ExpectedStateRevision: 7, RecoveryEpoch: 2, IdempotencyKey: "key-a"}
	input.TargetDigest = credentialref.LifecycleTargetDigest(input)
	for _, wrong := range []bool{false, true} {
		data := generated.CredentialLifecycleSubmission{Schema: generated.SchemaIDCredentialLifecycleSubmission, SchemaVersion: "1.2.0", ChangeID: "change-a", OperationID: "operation-a", ReferenceID: input.ReferenceID, Action: input.Action, Status: "draft", StateRevision: 9, RecoveryEpoch: 2}
		if wrong {
			data.Action = "credential.revoke"
		}
		raw, profile, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.credential-lifecycle-drafts.create", true, 2, 9, data))
		response, err := NewClient(clientTestFactory()).CreateCredentialLifecycleDraft(context.Background(), profile, input)
		if wrong && err == nil {
			t.Fatal("substituted action passed typed response verification")
		}
		if !wrong && (err != nil || !bytes.Equal(response.Raw, raw)) {
			t.Fatalf("exact response err=%v raw=%s", err, response.Raw)
		}
		request := <-captured
		var actual generated.CredentialLifecycleRequest
		if request.method != http.MethodPost || request.path != "/api/v1/credential-lifecycle-drafts" || request.contentType != "application/json" || json.Unmarshal(request.body, &actual) != nil || !reflect.DeepEqual(actual, input) {
			t.Fatalf("finite metadata request: %+v", request)
		}
	}
}
