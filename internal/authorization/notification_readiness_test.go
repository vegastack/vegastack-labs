package authorization

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestNotificationReadinessRiskIsClosedHumanControlPlane(t *testing.T) {
	p := generated.Plan{Risk: string(RiskControlPlane), Operations: []generated.PlanOperation{{Sequence: 1, OperationType: "operations.notification-readiness.test"}}}
	if r, e := ClassifyPlan(p); e != nil || r != RiskControlPlane {
		t.Fatal(r, e)
	}
	if IsPreauthorizedOperation(p.Operations[0].OperationType) {
		t.Fatal("canary preauthorized")
	}
	for _, risk := range []RiskClass{RiskRoutine, RiskDestructive} {
		p.Risk = string(risk)
		if _, e := ClassifyPlan(p); e == nil {
			t.Fatal("wrong risk", risk)
		}
	}
	p.Risk = string(RiskControlPlane)
	p.Operations[0].OperationType = "operations.notification-readiness.send-now"
	if _, e := ClassifyPlan(p); e == nil {
		t.Fatal("unknown send operation")
	}
}
