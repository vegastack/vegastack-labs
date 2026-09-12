package authorization

import (
	"errors"
	"sort"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type RiskClass string

const (
	RiskRoutine        RiskClass = "routine"
	RiskProductionLike RiskClass = "production-like"
	RiskInfrastructure RiskClass = "infrastructure"
	RiskDestructive    RiskClass = "destructive"
	RiskControlPlane   RiskClass = "control-plane"
)

var errUnknownRisk = errors.New("unknown plan operation or risk")

var operationRisk = map[string]RiskClass{
	"application.deploy.low-risk":        RiskRoutine,
	"application.deploy.production-like": RiskProductionLike,
	"audit.checkpoint":                   RiskRoutine,
	"backup.snapshot":                    RiskRoutine,
	"backup.verify":                      RiskRoutine,
	"drift.scan":                         RiskRoutine,
	"health.check":                       RiskRoutine,
	"node.add":                           RiskInfrastructure,
	"node.remove":                        RiskInfrastructure,
	"shell.grant":                        RiskInfrastructure,
	"shell.revoke":                       RiskInfrastructure,
	"public-exposure.change":             RiskInfrastructure,
	"backup-policy.change":               RiskInfrastructure,
	"backup.restore":                     RiskDestructive,
	"resource.delete":                    RiskDestructive,
	"backup.retention.change":            RiskDestructive,
	"network.change":                     RiskControlPlane,
	"identity.change":                    RiskControlPlane,
	"secret-provider.change":             RiskControlPlane,
	"control-plane.change":               RiskControlPlane,
	"control-plane.recover":              RiskControlPlane,
}

var riskRank = map[RiskClass]int{
	RiskRoutine: 1, RiskProductionLike: 2, RiskInfrastructure: 3, RiskDestructive: 4, RiskControlPlane: 5,
}

func ValidRiskClass(risk RiskClass) bool { _, ok := riskRank[risk]; return ok }

// ClassifyPlan derives risk only from the closed provider-neutral operation
// table and rejects any plan whose embedded classification disagrees.
func ClassifyPlan(plan generated.Plan) (RiskClass, error) {
	if len(plan.Operations) == 0 || len(plan.Operations) > 256 {
		return "", errUnknownRisk
	}
	operations := append([]generated.PlanOperation(nil), plan.Operations...)
	sort.SliceStable(operations, func(i, j int) bool { return operations[i].Sequence < operations[j].Sequence })
	result := RiskRoutine
	for index, operation := range operations {
		if operation.Sequence != int64(index+1) {
			return "", errUnknownRisk
		}
		risk, ok := operationRisk[operation.OperationType]
		if !ok {
			return "", errUnknownRisk
		}
		if riskRank[risk] > riskRank[result] {
			result = risk
		}
	}
	if RiskClass(plan.Risk) != result {
		return "", errUnknownRisk
	}
	return result, nil
}

func preauthorizedOperation(operation string) bool {
	switch operation {
	case "application.deploy.low-risk", "audit.checkpoint", "backup.snapshot", "backup.verify", "drift.scan", "health.check":
		return true
	default:
		return false
	}
}
