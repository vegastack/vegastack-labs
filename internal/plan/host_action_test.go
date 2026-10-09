package plan

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"strings"
	"testing"
)

type actionDraftReader struct{ d store.HostActionDraft }

func (a actionDraftReader) GetDraft(context.Context, string) (store.HostActionDraft, error) {
	return a.d, nil
}
func TestHostActionPlanNeverOmitsHumanConsoleReview(t *testing.T) {
	r := generated.HostActionRequest{HostID: "host-a", ActionID: "access.apply", ActionInput: "{\"source\":\"synthetic\"}", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Method: "administrator-verified-console"}}
	p := generated.Plan{HostAction: &r}
	body := readablePlan(p)
	if !strings.Contains(body, "synthetic") || !strings.Contains(body, "administrator-verified-console") || !strings.Contains(body, "pinned key") {
		t.Fatal("incomplete human review")
	}
	before, _ := planDigest(p)
	p.HostAction.ActionInput = "{}"
	after, _ := planDigest(p)
	if before == after {
		t.Fatal("action changes not sealed")
	}
	_ = hostaction.AdapterID
}

func TestHostActionCredentialPlanNamesBothMachinesAndRestartUnit(t *testing.T) {
	p := generated.Plan{HostActionNativeUnit: "vsk-labs.service", HostActionConsole: &generated.HostActionCredentialConfirmation{Schema: generated.SchemaIDHostActionCredentialConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetRevision: 1, HostIdentityDigest: hostaction.Digest("destination"), TargetDigest: hostaction.Digest("pinned destination"), NativeConsumerMachineID: strings.Repeat("a", 32)}}
	body := readablePlan(p)
	for _, part := range []string{"BOTH", "destination host", "consumer/controller machine", "vsk-labs.service", strings.Repeat("a", 32)} {
		if !strings.Contains(body, part) {
			t.Fatalf("missing %s in review", part)
		}
	}
	before, _ := planDigest(p)
	p.HostActionNativeUnit = "different.service"
	after, _ := planDigest(p)
	if before == after {
		t.Fatal("restart unit omitted from immutable plan")
	}
}
