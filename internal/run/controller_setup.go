package run

import "github.com/vegastack/vegastack-labs/internal/generated"

// This is not a generic deferred-executor mechanism. Only the fixed controller
// bootstrap class can be admitted without immediately invoking an adapter.
func ControllerSetupPlan(p generated.Plan) bool {
	if p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || len(p.Operations) != 1 || p.HostAction != nil || p.HostRoleScope != nil || p.HostAccessSequence != nil || credentialPlanDigest(p) != "" {
		return false
	}
	op := p.Operations[0]
	return op.AdapterID == "core.controller-setup" && op.OperationType == "controller.setup.bootstrap" && !op.Idempotent && len(op.InputDigest) == 71 && len(op.ArtifactDigest) == 71
}
