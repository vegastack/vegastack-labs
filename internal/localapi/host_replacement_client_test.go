package localapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func replacementClientBytesDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func replacementClientInput() generated.HostReplacementRequest {
	d := func(s string) string { return replacementClientBytesDigest([]byte(s)) }
	return generated.HostReplacementRequest{
		Schema: generated.SchemaIDHostReplacementRequest, SchemaVersion: "1.0.0", ReplacementID: "replacement-a", Operation: "freeze", RestorationClass: "stateless-role",
		OldHostID: "old-host", NewHostID: "new-host", OldIdentityDigest: d("old"), NewIdentityDigest: d("new"), OldTargetDigest: d("old-target"), NewTargetDigest: d("new-target"), OldSSHHostKeyDigest: d("old-key"), NewSSHHostKeyDigest: d("new-key"), OldTargetRevision: 1, NewTargetRevision: 1,
		ProfileID: "profile", ProfileLockDigest: d("profile"), OldRoleBindingDigest: d("old-role"), RoleDeclarationID: "old-role", RoleDeclarationRevision: 1, ProposedRoleDeclarationID: "new-role", ProposedRoleDeclarationRevision: 1, ProposedRoleBindingDigest: d("new-role"), PreservedPreimageDigest: d("preimage"),
		AliasBindings: []generated.HostReplacementAliasBinding{{Schema: generated.SchemaIDHostReplacementAliasBinding, SchemaVersion: "1.0.0", AliasID: "alias-a", OwnerHostID: "old-host", OwnerIdentityDigest: d("old"), OwnerRevision: 1, OwnershipGeneration: 1}}, PayloadIDs: []string{}, VolumeIDs: []string{}, ResourceIDs: []string{},
		OSPreparation: generated.HostReplacementOsPreparation{Schema: generated.SchemaIDHostReplacementOsPreparation, SchemaVersion: "1.0.0", Method: "administrator-prepared", ObservationID: "observation-a", ObservationDigest: d("observation"), HostIdentityDigest: d("new"), ConfirmedAt: "2026-10-09T12:00:00Z"}, ExpectedStateRevision: 1, RecoveryEpoch: 0, IdempotencyKey: "freeze-a",
	}
}

func TestHostReplacementClientBindingAndNoRetry(t *testing.T) {
	input := replacementClientInput()
	raw, _ := json.Marshal(input)
	digest := replacementClientBytesDigest(raw)
	id := "host-replacement-" + digest[7:39]
	for _, mode := range []string{"valid", "replacement", "digest", "epoch", "state", "failure"} {
		t.Run(mode, func(t *testing.T) {
			data := generated.HostReplacementSubmission{Schema: generated.SchemaIDHostReplacementSubmission, SchemaVersion: "1.0.0", ReplacementID: input.ReplacementID, DraftID: id, DeclarationID: id, ContentDigest: digest, StateRevision: 2, RecoveryEpoch: 0}
			switch mode {
			case "replacement":
				data.ReplacementID = "other"
			case "digest":
				data.ContentDigest = replacementClientBytesDigest([]byte("other"))
			case "epoch":
				data.RecoveryEpoch++
			case "state":
				data.StateRevision++
			}
			status := 200
			if mode == "failure" {
				status = 503
			}
			_, profile, captured := serveFixedResponse(t, status, operationEnvelope(t, "api.v1.host-replacements.create", false, 0, 2, data))
			response, err := NewClient(clientTestFactory()).PrepareHostReplacement(context.Background(), profile, input)
			request := <-captured
			if request.method != "POST" || request.path != "/api/v1/host-replacements" {
				t.Fatalf("wrong request %+v", request)
			}
			if mode == "valid" {
				if err != nil || response.Data.ContentDigest != digest {
					t.Fatal(err)
				}
			} else if err == nil && response.ExitCode == 0 {
				t.Fatal("accepted mismatched or failed response")
			}
			select {
			case <-captured:
				t.Fatal("replacement mutation retried")
			default:
			}
		})
	}
}
func TestHostReplacementInspectRejectsInvalidPath(t *testing.T) {
	profile, captured := serveGateCheckResponses(t, "G-001", nil, nil)
	if _, err := NewClient(clientTestFactory()).GetHostReplacement(context.Background(), profile, "../outside"); err == nil {
		t.Fatal("invalid replacement path accepted")
	}
	select {
	case <-captured:
		t.Fatal("invalid replacement contacted server")
	default:
	}
}

func TestHostReplacementInspectPreservesPendingStateAndBinding(t *testing.T) {
	input := replacementClientInput()
	for _, mode := range []string{"valid", "replacement", "epoch", "revision"} {
		t.Run(mode, func(t *testing.T) {
			d := replacementClientBytesDigest([]byte("state"))
			state := generated.HostReplacementState{Schema: generated.SchemaIDHostReplacementState, SchemaVersion: "1.0.0", ReplacementID: input.ReplacementID, DeclarationID: "replacement-draft", DeclarationRevision: 2, OldHostID: input.OldHostID, NewHostID: input.NewHostID, OldIdentityDigest: input.OldIdentityDigest, NewIdentityDigest: input.NewIdentityDigest, BindingDigest: d, RoleBindingDigest: d, PriorOwnershipGeneration: 1, ProposedOwnershipGeneration: 2, AliasBindings: input.AliasBindings, StateRevision: 3, RecoveryEpoch: 0, Status: "verification-required", RestorationClass: "stateless-role", NextAction: "qualify-replacement", Blockers: []string{"native-qualification-pending"}}
			switch mode {
			case "replacement":
				state.ReplacementID = "other"
			case "epoch":
				state.RecoveryEpoch++
			case "revision":
				state.StateRevision++
			}
			_, profile, captured := serveFixedResponse(t, 200, operationEnvelope(t, "api.v1.host-replacements.get", false, 0, 3, state))
			response, err := NewClient(clientTestFactory()).GetHostReplacement(context.Background(), profile, input.ReplacementID)
			request := <-captured
			if request.method != "GET" || request.path != "/api/v1/host-replacements/replacement-a" {
				t.Fatalf("wrong route %+v", request)
			}
			if mode == "valid" {
				if err != nil || response.Data.Status != "verification-required" || response.Data.NextAction != "qualify-replacement" {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted mismatched state")
			}
		})
	}
}
