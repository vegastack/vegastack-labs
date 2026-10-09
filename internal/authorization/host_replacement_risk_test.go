package authorization

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestHostReplacementRiskAndHumanBranch(t *testing.T) {
	for _, op := range []string{"host.alias.claim", "host.replacement.freeze", "host.replacement.commit"} {
		p := generated.Plan{Risk: "infrastructure", Operations: []generated.PlanOperation{{Sequence: 1, OperationType: op}}}
		if _, err := ClassifyPlan(p); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if preauthorizedOperation(op) {
			t.Fatal("ownership operation preauthorized")
		}
		if op != "host.alias.claim" {
			p.HostReplacement = &generated.HostReplacementRequest{RestorationClass: "control-database"}
			if _, err := ClassifyPlan(p); err == nil {
				t.Fatal("control replacement downgraded")
			}
			p.Risk = "control-plane"
			if _, err := ClassifyPlan(p); err != nil {
				t.Fatal(err)
			}
		}
	}
}
