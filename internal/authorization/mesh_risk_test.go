package authorization

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestMeshUsesInfrastructureAcknowledgementAndNeverPreauthorization(t *testing.T) {
	for _, name := range []string{"import", "profile-routing-update", "gateway-rule-update", "registration-delete"} {
		op := "network.mesh." + name
		p := generated.Plan{Risk: string(RiskInfrastructure), Operations: []generated.PlanOperation{{Sequence: 1, OperationType: op}}}
		risk, e := ClassifyPlan(p)
		if e != nil || risk != RiskInfrastructure || preauthorizedOperation(op) || !roleAllows(RoleInfrastructureAdmin, ActionAcknowledge, risk) {
			t.Fatalf("wrong Mesh authority %s %s %v", name, risk, e)
		}
	}
}
