package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
	input := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", Action: "credential." + strings.TrimPrefix(command, "credential "), ReferenceID: "reference-a", MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{}, ExpectedStateRevision: 7, RecoveryEpoch: 2, IdempotencyKey: "key-a"}
	switch input.Action {
	case "credential.stage":
		input.DraftID = &draft
	case "credential.activate":
		input.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
		input.NativeConsumers = &[]generated.CredentialNativeConsumer{{Schema: generated.SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a"}}
		input.NativeDeniedReaders = &[]generated.CredentialNativeDeniedReader{{Schema: generated.SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "consumer-denied", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied"}}
	case "credential.rotate":
		input.DraftID = &draft
		input.PriorMaterialVersion = &prior
		input.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
		input.NativeConsumers = &[]generated.CredentialNativeConsumer{{Schema: generated.SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a"}}
		input.NativeDeniedReaders = &[]generated.CredentialNativeDeniedReader{{Schema: generated.SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "consumer-denied", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied"}}
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

func TestLifecycleCLIValidLeavesReturnMetadataOnly(t *testing.T) {
	for _, action := range []string{"stage", "activate", "rotate", "revoke", "recover"} {
		for _, output := range []string{"human", "json"} {
			t.Run(action+"/"+output, func(t *testing.T) {
				operations := successfulCredentialOperations(t)
				files := &stubFileReader{content: syntheticLifecycleRequest(t, "credential "+action)}
				code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{"credential", action, "--config", "profile.json", "--file", "request.json", "--output", output}, nil, WithControlOperations(successfulControlOperations(t), files), WithCredentialControlOperations(operations))
				if code != 0 || operations.calls != 1 || operations.config != "profile.json" || stderr != "" {
					t.Fatalf("valid lifecycle command: code=%d calls=%d stderr=%q", code, operations.calls, stderr)
				}
				if strings.Contains(stdout+stderr, "private-canary") || strings.Contains(stdout+stderr, "ciphertextFingerprint") || strings.Contains(stdout+stderr, "\"value\"") {
					t.Fatal("lifecycle output disclosed private data")
				}
				if output == "json" {
					var envelope generated.RunResult
					if err := json.Unmarshal([]byte(stdout), &envelope); err != nil || envelope.Command != "api.v1.credential-lifecycle-drafts.create" || envelope.StateRevision != 9 {
						t.Fatalf("JSON lifecycle envelope = %+v %v", envelope, err)
					}
					var submission generated.CredentialLifecycleSubmission
					if err := json.Unmarshal(envelope.Data, &submission); err != nil || submission.Action != "credential."+action || submission.ChangeID != "change-a" || submission.Status != "draft" {
						t.Fatalf("JSON lifecycle submission = %+v %v", submission, err)
					}
				} else {
					want := "Credential lifecycle draft draft\nAction: credential." + action + "\nReference: reference-a\nChange: change-a\nState revision: 9\nRecovery epoch: 2\n"
					if action == "stage" {
						golden, err := os.ReadFile(filepath.Join("testdata", "credential-lifecycle-human.golden"))
						if err != nil {
							t.Fatal(err)
						}
						want = string(golden)
					}
					if stdout != want {
						t.Fatalf("human lifecycle output = %q, want %q", stdout, want)
					}
				}
			})
		}
	}

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
