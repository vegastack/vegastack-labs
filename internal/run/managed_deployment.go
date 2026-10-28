package run

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

// ExternalManagedDeploymentAdmission derives its principal and numeric job
// identity from durably consumed CI admission and current protected bindings.
// A controller binding is an assertion until this method revalidates it.
type ExternalManagedDeploymentAdmission interface {
	VerifyManagedDeploymentJob(context.Context, adapter.ExactExecutionBinding, generated.Plan, generated.RunStep) (identity.Principal, error)
}
type managedDeploymentContextKey struct{}
type managedDeploymentContext struct {
	controller         adapter.ExactExecutionBinding
	planID, planDigest string
	principal          identity.Principal
}

func managedPrincipalContext(ctx context.Context, p identity.Principal) bool {
	if p.Method != identity.ManagedCIControllerMethod {
		return true
	}
	proof, ok := ctx.Value(managedDeploymentContextKey{}).(managedDeploymentContext)
	return ok && proof.principal == p && identity.ValidPrincipal(p)
}

// managedContext is internal and never decoded from an API request, job frame
// or executor extension. Every call revalidates the current durable CI proof.
func (e *ExternalExecutor) managedContext(ctx context.Context, parent adapter.ExactExecutionBinding, planID string) (context.Context, identity.Principal, error) {
	deny := func() (context.Context, identity.Principal, error) {
		return ctx, identity.Principal{}, runError(generated.ErrorCodeAuthorizationDenied, "managed-deployment")
	}
	if e == nil {
		return deny()
	}
	guard, ok := e.deploymentAdmission.(ExternalManagedDeploymentAdmission)
	if !ok {
		return deny()
	}
	stored, err := e.plans.Get(ctx, planID)
	if err != nil {
		return ctx, identity.Principal{}, err
	}
	plan := stored.Plan
	if plan.PlanID != planID || plan.ExecutorMode != "external" || len(plan.Operations) != 1 {
		return deny()
	}
	runs, err := e.runs.ActiveRuns(ctx)
	if err != nil {
		return ctx, identity.Principal{}, err
	}
	var selected *generated.Run
	for i := range runs {
		r := &runs[i]
		if r.PlanID == planID && r.PlanDigest == plan.PlanDigest && r.Status == "running" && !r.CancellationRequested {
			if selected != nil {
				return deny()
			}
			selected = r
		}
	}
	if selected == nil || len(selected.Steps) != 1 {
		return deny()
	}
	p, err := guard.VerifyManagedDeploymentJob(ctx, parent, plan, selected.Steps[0])
	if err != nil {
		return ctx, identity.Principal{}, err
	}
	if p.Method != identity.ManagedCIControllerMethod || !identity.ValidPrincipal(p) || plan.ExecutorID == nil || *plan.ExecutorID != p.ID || selected.ExecutorID != p.ID {
		return deny()
	}
	parent.ContractExtensions = append([]generated.ContractExtension(nil), parent.ContractExtensions...)
	proof := managedDeploymentContext{controller: parent, planID: planID, planDigest: plan.PlanDigest, principal: p}
	return context.WithValue(ctx, managedDeploymentContextKey{}, proof), p, nil
}
func (e *ExternalExecutor) ClaimManaged(ctx context.Context, parent adapter.ExactExecutionBinding, planID string, r generated.ExecutorClaimRequest) (generated.ExecutorLease, error) {
	bound, p, err := e.managedContext(ctx, parent, planID)
	if err != nil {
		return generated.ExecutorLease{}, err
	}
	return e.Claim(bound, p, r)
}
func (e *ExternalExecutor) RenewManaged(ctx context.Context, parent adapter.ExactExecutionBinding, r generated.ExecutorRenewRequest) (generated.ExecutorLease, error) {
	if e == nil {
		return generated.ExecutorLease{}, runError(generated.ErrorCodeInputInvalid, "external-executor")
	}
	lease, err := e.leases.Get(ctx, r.LeaseID)
	if err != nil {
		return generated.ExecutorLease{}, err
	}
	bound, p, err := e.managedContext(ctx, parent, lease.PlanID)
	if err != nil {
		return generated.ExecutorLease{}, err
	}
	return e.Renew(bound, p, r)
}
func (e *ExternalExecutor) SubmitManagedReceipt(ctx context.Context, parent adapter.ExactExecutionBinding, r generated.ExecutionReceiptRequest) (generated.ExecutionReceipt, error) {
	if e == nil {
		return generated.ExecutionReceipt{}, runError(generated.ErrorCodeInputInvalid, "external-executor")
	}
	lease, err := e.leases.Get(ctx, r.Receipt.LeaseID)
	if err != nil {
		return generated.ExecutionReceipt{}, err
	}
	bound, p, err := e.managedContext(ctx, parent, lease.PlanID)
	if err != nil {
		return generated.ExecutionReceipt{}, err
	}
	return e.SubmitReceipt(bound, p, r)
}
