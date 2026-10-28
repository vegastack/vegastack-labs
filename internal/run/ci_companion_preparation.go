package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type ciCompanionPreparationKey struct{}
type ciCompanionPreparation struct{ planID, planDigest string }

func credentialExternalAdmitted(ctx context.Context, p generated.Plan) bool {
	if p.ExecutorMode != "external" || p.AuthorizationBranch != "human" {
		return false
	}
	if proof, ok := ctx.Value(ciCompanionPreparationKey{}).(ciCompanionPreparation); ok && proof.planID == p.PlanID && proof.planDigest == p.PlanDigest {
		return true
	}
	if proof, ok := ctx.Value(managedDeploymentContextKey{}).(managedDeploymentContext); ok && proof.planID == p.PlanID && proof.planDigest == p.PlanDigest {
		return true
	}
	return false
}
