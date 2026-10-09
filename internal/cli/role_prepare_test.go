package cli

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"os"
	"strings"
	"testing"
)

func syntheticRoleInput() generated.LinuxRoleInput {
	raw, err := os.ReadFile("../linuxrole/testdata/role-input.json")
	if err != nil {
		panic(err)
	}
	var in generated.LinuxRoleInput
	if json.Unmarshal(raw, &in) != nil {
		panic("invalid synthetic role fixture")
	}
	in.RoleBindingDigest = linuxrole.RoleBindingDigest(in)
	in.RenderedPolicyDigest = linuxrole.PolicyDigest(in)
	return in
}
func TestServerPreparationIsInertAndEquivalent(t *testing.T) {
	raw, _ := json.Marshal(syntheticRoleInput())
	files := &stubFileReader{content: raw}
	args := []string{"server", "prepare", "--file", "input.json"}
	code, human, stderr := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(nil, files))
	if code != 0 || stderr != "" || !strings.Contains(human, "Preparation only") {
		t.Fatalf("code=%d %s %s", code, human, stderr)
	}
	code, out, stderr := runTestAppWithOptions(t, context.Background(), append(args, "--output", "json"), nil, WithControlOperations(nil, files))
	var result generated.RunResult
	if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &result) != nil || result.Changed {
		t.Fatalf("code=%d %s %s", code, out, stderr)
	}
	var prep generated.RolePreparation
	if json.Unmarshal(result.Data, &prep) != nil || linuxrole.ValidatePreparation(prep) != nil || !strings.Contains(human, prep.PolicyDigest) {
		t.Fatal("JSON/human preparation mismatch")
	}
}
func TestRolePreparationRejectsUnboundedOrUnknownInput(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"shell":"anything"}`), []byte(strings.Repeat(" ", 32769))} {
		code, _, _ := runTestAppWithOptions(t, context.Background(), []string{"server", "prepare", "--file", "input.json"}, nil, WithControlOperations(nil, &stubFileReader{content: raw}))
		if code == 0 {
			t.Fatal("invalid preparation accepted")
		}
	}
}

func syntheticRoleRequest(t *testing.T) generated.HostActionRequest {
	t.Helper()
	raw, _ := json.Marshal(syntheticRoleInput())
	d := "sha256:" + strings.Repeat("a", 64)
	return generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "debian.role.apply", ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), HostID: "test-host", TargetRevision: 1, TargetDigest: d, AutomationPrincipalID: "automation", CallerUID: 1000, CredentialReferenceID: "ssh-key", CredentialMaterialVersion: "v1", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: d, HostIdentityDigest: d}, ExpectedStateRevision: 1, RecoveryEpoch: 0, IdempotencyKey: "role-a"}
}

func TestRolePreparationRejectsOtherActionsBeforeTransport(t *testing.T) {
	request := syntheticRoleRequest(t)
	request.ActionID = "debian.baseline.apply"
	raw, _ := json.Marshal(request)
	code, _, _ := runTestAppWithOptions(t, context.Background(), []string{"node", "role", "prepare", "--config", "profile.json", "--file", "input.json"}, nil, WithControlOperations(nil, &stubFileReader{content: raw}))
	if code != 2 {
		t.Fatalf("non-role action reached control boundary: %d", code)
	}
}
