package authorization

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestLocalRetentionOperationsAreHumanOnlyDestructive(t *testing.T) {
	for _, operation := range []string{"backup.retention-locks.activate", "backup.local.retire"} {
		plan := generated.Plan{Risk: string(RiskDestructive), Operations: []generated.PlanOperation{{Sequence: 1, OperationType: operation}}}
		if risk, err := ClassifyPlan(plan); err != nil || risk != RiskDestructive {
			t.Fatalf("%s risk=%q err=%v", operation, risk, err)
		}
		if preauthorizedOperation(operation) {
			t.Fatalf("%s gained automatic preauthorization", operation)
		}
		for _, wrong := range []RiskClass{RiskRoutine, RiskInfrastructure} {
			plan.Risk = string(wrong)
			if _, err := ClassifyPlan(plan); err == nil {
				t.Fatalf("%s accepted embedded risk %q", operation, wrong)
			}
		}
	}
}
