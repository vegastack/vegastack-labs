package plan

import (
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

var controllerSetupDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func controllerSetupPlanCandidate(d generated.DeclarationRevision, ops []generated.PlanOperation) bool {
	if d.DeclarationType == "controller.setup" {
		return true
	}
	for _, op := range ops {
		if op.AdapterID == "core.controller-setup" || strings.HasPrefix(op.OperationType, "controller.setup.") {
			return true
		}
	}
	return false
}

func sealedSingleControllerSetup(d generated.DeclarationRevision, ops []generated.PlanOperation) bool {
	if d.DeclarationType != "controller.setup" || len(ops) != 1 || len(d.Extensions) != 0 ||
		d.Maintenance != nil || d.HostingLifecycle != nil || d.ServiceRecovery != nil || d.ServiceDeployment != nil ||
		d.CIJob != nil || d.CIEnrollment != nil || d.ServiceImport != nil || d.NetworkEndpoint != nil ||
		d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil || d.Operations[0].OffsiteRunSpec != nil {
		return false
	}
	op := ops[0]
	return op.Sequence == 1 && authorization.ValidIdentifier(op.OperationID) && authorization.ValidIdentifier(op.TargetID) &&
		op.AdapterID == "core.controller-setup" && op.OperationType == "controller.setup.bootstrap" && !op.Idempotent &&
		controllerSetupDigest.MatchString(op.InputDigest) && controllerSetupDigest.MatchString(op.ArtifactDigest)
}
