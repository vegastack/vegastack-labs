package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func syntheticLifecycleRequest(t *testing.T, command string) []byte {
	t.Helper()
	draft, prior := "draft-a", "version-prior"
	priorEpoch := int64(1)
	digest := "sha256:" + strings.Repeat("a", 64)
	input := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.2.0", Action: "credential." + strings.TrimPrefix(command, "credential "), ReferenceID: "reference-a", MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{}, ExpectedStateRevision: 7, RecoveryEpoch: 2, IdempotencyKey: "key-a"}
	switch input.Action {
	case "credential.stage":
		input.DraftID = &draft
	case "credential.activate":
		input.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
	case "credential.rotate":
		input.DraftID = &draft
		input.PriorMaterialVersion = &prior
		input.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
	case "credential.revoke":
		input.ConsumerIDs = []string{}
	case "credential.recover":
		input.DraftID = &draft
		input.PriorRecoveryEpoch = &priorEpoch
		input.CustodyProofDigest = &digest
		input.FormerControllerFenceDigest = &digest
	}
	input.TargetDigest = credentialref.LifecycleTargetDigest(input)
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (stub *stubCredentialOperations) CreateCredentialLifecycleDraft(_ context.Context, config string, input generated.CredentialLifecycleRequest) (localapi.TypedResponse[generated.CredentialLifecycleSubmission], error) {
	stub.calls++
	stub.config = config
	data := generated.CredentialLifecycleSubmission{Schema: generated.SchemaIDCredentialLifecycleSubmission, SchemaVersion: "1.2.0", ChangeID: "change-a", OperationID: "operation-a", ReferenceID: input.ReferenceID, Action: input.Action, Status: "draft", StateRevision: input.ExpectedStateRevision + 2, RecoveryEpoch: input.RecoveryEpoch}
	envelope := stub.response.Result
	envelope.Command = "api.v1.credential-lifecycle-drafts.create"
	envelope.StateRevision = data.StateRevision
	envelope.RecoveryEpoch = data.RecoveryEpoch
	envelope.Data, _ = json.Marshal(data)
	raw, _ := json.Marshal(envelope)
	return localapi.TypedResponse[generated.CredentialLifecycleSubmission]{Raw: append(raw, '\n'), Result: envelope, Data: data}, stub.err
}

func TestLifecycleCLIRejectsCrossActionAndPrivateFieldsBeforeService(t *testing.T) {
	for _, mode := range []string{"cross-action", "private-field"} {
		t.Run(mode, func(t *testing.T) {
			raw := syntheticLifecycleRequest(t, generated.CommandNameCredentialStage)
			if mode == "private-field" {
				raw = append(raw[:len(raw)-1], []byte(`,"value":"private-canary"}`)...)
			}
			action := "stage"
			if mode == "cross-action" {
				action = "revoke"
			}
			operations := successfulCredentialOperations(t)
			files := &stubFileReader{content: raw}
			code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{"credential", action, "--config", "profile.json", "--file", "request.json", "--output", "json"}, nil, WithControlOperations(successfulControlOperations(t), files), WithCredentialControlOperations(operations))
			if code != 2 || operations.calls != 0 || strings.Contains(stdout+stderr, "private-canary") {
				t.Fatalf("unsafe CLI request: code=%d calls=%d output=%s%s", code, operations.calls, stdout, stderr)
			}
		})
	}
}
