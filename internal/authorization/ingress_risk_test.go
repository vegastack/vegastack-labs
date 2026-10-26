package authorization

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestIngressIsHumanInfrastructureWork(t *testing.T) {
	for _, action := range []string{"import", "tunnel-config-update", "access-policy-update", "dns-record-update", "connector-disconnect", "token-rotate"} {
		op := "network.ingress." + action
		p := generated.Plan{Risk: string(RiskInfrastructure), Operations: []generated.PlanOperation{{Sequence: 1, OperationType: op}}}
		risk, e := ClassifyPlan(p)
		if e != nil || risk != RiskInfrastructure || preauthorizedOperation(op) {
			t.Fatalf("unexpected ingress authority %s %v", action, e)
		}
	}
}
