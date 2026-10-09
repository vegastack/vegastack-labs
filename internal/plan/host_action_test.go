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
