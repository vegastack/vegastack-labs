package authorization

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestHostActionRiskCannotUseRoutinePreauthorization(t *testing.T) {
	p := generated.Plan{Risk: string(RiskInfrastructure), Operations: []generated.PlanOperation{{Sequence: 1, OperationType: "host.action.execute"}}}
	if risk, err := ClassifyPlan(p); err != nil || risk != RiskInfrastructure {
		t.Fatalf("host action classification: %v", err)
	}
	if IsPreauthorizedOperation("host.action.execute") {
		t.Fatal("privileged action became routine")
	}
	p.Risk = string(RiskRoutine)
	if _, err := ClassifyPlan(p); err == nil {
		t.Fatal("caller lowered privileged action risk")
	}
}
