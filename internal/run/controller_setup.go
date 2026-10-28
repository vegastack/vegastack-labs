package run

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"regexp"
)

var controllerSetupHash = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// This is not a generic deferred-executor mechanism. Only the fixed controller
// bootstrap class can be admitted without immediately invoking an adapter.
func ControllerSetupPlan(p generated.Plan) bool {
	if p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || len(p.Operations) != 1 || p.HostAction != nil || p.HostRoleScope != nil || p.HostAccessSequence != nil || credentialPlanDigest(p) != "" {
		return false
	}
	op := p.Operations[0]
	return op.AdapterID == "core.controller-setup" && op.OperationType == "controller.setup.bootstrap" && !op.Idempotent && controllerSetupHash.MatchString(op.InputDigest) && controllerSetupHash.MatchString(op.ArtifactDigest)
}
