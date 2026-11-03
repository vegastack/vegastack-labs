package hostdiscovery

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func targetWithActionUser(t *testing.T, target generated.HostDiscoveryTarget, user string) generated.HostDiscoveryTarget {
	t.Helper()
	raw, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["actionUser"], err = json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err = generated.ValidateContractJSON(generated.SchemaIDHostDiscoveryTarget, raw, generated.ContractExact); err != nil {
		t.Fatalf("action-user target contract rejected: %v", err)
	}
	if err = json.Unmarshal(raw, &target); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestActionUserTargetValidationAndDigest(t *testing.T) {
	base := validTarget(t)
	action := targetWithActionUser(t, base, "automation")
	if err := ValidateTarget(action); err != nil {
		t.Fatal(err)
	}
	if action.User != base.User {
		t.Fatal("action account replaced discovery account")
	}
	if Digest(action) == Digest(base) {
		t.Fatal("action login was omitted from the approval target digest")
	}
	other := targetWithActionUser(t, base, "automation-two")
	if Digest(other) == Digest(action) {
		t.Fatal("changed action login reused the same target digest")
	}
	for _, user := range []string{"", "root", "a;id", "two users", strings.Repeat("a", 33)} {
		t.Run("invalid-"+user, func(t *testing.T) {
			raw, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			fields["actionUser"], err = json.Marshal(user)
			if err != nil {
				t.Fatal(err)
			}
			raw, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if generated.ValidateContractJSON(generated.SchemaIDHostDiscoveryTarget, raw, generated.ContractExact) != nil {
				return
			}
			var target generated.HostDiscoveryTarget
			if err = json.Unmarshal(raw, &target); err != nil {
				t.Fatal(err)
			}
			if ValidateTarget(target) == nil {
				t.Fatalf("unsafe action login %q accepted", user)
			}
		})
	}
}

func TestActionUserRequiresFreshConsoleConfirmation(t *testing.T) {
	request := preloadedTargetRequest(t)
	request.Target.ActionUser = new("automation")
	if ValidateConsoleConfirmation(request) == nil {
		t.Fatal("discovery target with changed action login reused the previous approval")
	}
	request.ConsoleConfirmation.TargetDigest = Digest(request.Target)
	if err := ValidateConsoleConfirmation(request); err != nil {
		t.Fatal(err)
	}
}

// Captured from the pre-actionUser contract at 99d743fe. Existing stored target
// bytes and approval digests must survive decoding with the additive contract.
func TestActionUserLegacyTargetEncodingAndDigest(t *testing.T) {
	const legacy = `{"schema":"vegastack-labs.dev/host-discovery-target","schemaVersion":"1.0.0","targetId":"candidate-a","revision":1,"address":"127.0.0.1","port":2222,"user":"inspect","hostKey":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","profileId":"profile-a","credentialReferenceId":"ref-a","materialVersion":"v1","expectedOs":"debian","expectedVersion":"13","expectedArchitecture":"amd64","inventoryDraftId":null,"inventoryDraftRevision":0,"assetId":null,"recoveryEpoch":0}`
	var target generated.HostDiscoveryTarget
	if err := json.Unmarshal([]byte(legacy), &target); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTarget(target); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != legacy {
		t.Fatal("legacy target encoding changed")
	}
	if Digest(target) != "sha256:5634850479af0953c3708b119b858f9c434b40cc6e2d45198d3d7fbbd651aaa9" {
		t.Fatal("legacy approval digest changed")
	}
}
