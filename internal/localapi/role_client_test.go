package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func roleActionRequest() generated.HostActionRequest {
	d := "sha256:" + strings.Repeat("a", 64)
	return generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "debian.role.apply", ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: d, HostID: "host-a", TargetRevision: 1, TargetDigest: d, AutomationPrincipalID: "automation", CallerUID: 1000, CredentialReferenceID: "ssh-key", CredentialMaterialVersion: "v1", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: d, HostIdentityDigest: d}, ExpectedStateRevision: 7, RecoveryEpoch: 2, IdempotencyKey: "role-a"}
}
func TestRoleDraftClientResponseBindings(t *testing.T) {
	input := roleActionRequest()
	for _, variant := range []string{"valid", "draft", "declaration", "revision", "epoch"} {
		t.Run(variant, func(t *testing.T) {
			d := "sha256:" + strings.Repeat("b", 64)
			data := generated.HostActionSubmission{OriginalRequestDigest: hostRequestDigest(input), Schema: generated.SchemaIDHostActionSubmission, SchemaVersion: "1.0.0", ContentDigest: d, DraftID: "host-action-" + d[7:39], DeclarationID: "host-action-" + d[7:39], StateRevision: 9, RecoveryEpoch: 2}
			switch variant {
			case "draft":
				data.DraftID = "wrong"
			case "declaration":
				data.DeclarationID = "wrong"
			case "revision":
				data.StateRevision++
			case "epoch":
				data.RecoveryEpoch++
			}
			_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.host-actions.draft", false, 2, 9, data))
			_, err := NewClient(clientTestFactory()).SubmitHostAction(context.Background(), profile, input)
			req := <-captured
			raw, _ := json.Marshal(input)
			if req.method != "POST" || req.path != "/api/v1/host-actions/draft" || !bytes.Equal(req.body, raw) {
				t.Fatal("request changed")
			}
			if variant == "valid" && err != nil {
				t.Fatal(err)
			}
			if variant != "valid" && err == nil {
				t.Fatal("mismatched response accepted")
			}
		})
	}
}

func TestRoleDraftClientPreservesDeniedEnvelope(t *testing.T) {
	for _, code := range []string{generated.ErrorCodeAuthorizationDenied, generated.ErrorCodePlanStale, generated.ErrorCodePrerequisiteBlocked} {
		t.Run(code, func(t *testing.T) {
			envelope, err := clientTestFactory().Failure("api.v1.host-actions.draft", generated.RunStatusFailed, code, "role", false, 2, 7, struct{}{})
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(envelope)
			raw = append(raw, '\n')
			_, profile, captured := serveFixedResponse(t, expectedHTTPStatus(code), raw)
			response, err := NewClient(clientTestFactory()).SubmitHostAction(context.Background(), profile, roleActionRequest())
			<-captured
			if err != nil || response.ExitCode != generated.ErrorExitCodes[code] || !bytes.Equal(response.Raw, raw) {
				t.Fatalf("denial changed: %v %+v", err, response)
			}
			select {
			case <-captured:
				t.Fatal("mutation retried")
			default:
			}
		})
	}
}
