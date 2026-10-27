package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

// Repeat current resource grants in the existing run reservation transaction.
// Later effects retain their owning transaction checks and native boundaries.
func verifyWorkflowRunAuthorization(ctx context.Context, row discoveryRow, run generated.Run, attribution audit.Attribution, serviceRepo *ServiceRepository, excluded ...string) error {
	var canonical []byte
	var readable string
	var p generated.Plan
	if row(`SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, run.PlanID, run.PlanDigest).Scan(&canonical, &readable) != nil || !decodeStoredPlan(canonical, readable, &p) {
		return actionError(generated.ErrorCodePlanStale)
	}
	if p.CIJob == nil && p.CIEnrollment == nil && p.HostingLifecycle == nil && p.ServiceRecovery == nil && p.ServiceDeployment == nil && p.ServiceImport == nil && p.NetworkEndpoint == nil && p.AuthorizationGrantBatch == nil && p.HostDiscoveryTarget == nil && p.HostAdoption == nil && p.HostAction == nil && p.HostAccessSequence == nil && p.HostReplacement == nil && p.HostAliasClaim == nil {
		return nil
	}
	principal, ok := identity.PrincipalFromContext(ctx)
	if !ok || principal.ID != attribution.AuthenticatedPrincipalID || principal.Method != attribution.AuthenticatedPrincipalMethod || run.AcknowledgementID == nil || p.AuthorizationBranch != "human" {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	var human string
	if row(`SELECT human_id FROM acknowledgement_requests WHERE acknowledgement_id=? AND plan_id=? AND plan_digest=? AND recovery_epoch=? AND status='approved'`, *run.AcknowledgementID, p.PlanID, p.PlanDigest, p.Binding.RecoveryEpoch).Scan(&human) != nil || attribution.ResponsibleHumanPrincipalID == nil || *attribution.ResponsibleHumanPrincipalID != human {
		return actionError(generated.ErrorCodeApprovalRequired)
	}
	for _, op := range p.Operations {
		for _, id := range authorization.ExecutionResourceIDs(p, op) {
			if err := authorizeBaselinePrincipal(ctx, row, p, human, id, authorization.ActionAcknowledge, "plan.acknowledge", "plan-target"); err != nil {
				return err
			}
			if err := authorizeBaselinePrincipal(ctx, row, p, principal.ID, id, authorization.ActionExecute, op.OperationType, "execution-target"); err != nil {
				return err
			}
		}
	}
	if in := p.HostingLifecycle; in != nil {
		return NewHostingLifecycleRepository(serviceRepo.store).validate(principal, row, *in)
	}
	if in := p.ServiceRecovery; in != nil {
		return NewServiceRecoveryRepository(serviceRepo.store).validate(principal, row, *in)
	}
	if in := p.ServiceDeployment; in != nil {
		return NewDeploymentRepository(serviceRepo.store).validate(principal, row, *in)
	}
	if in := p.CIJob; in != nil {
		return NewCIJobRepository(serviceRepo.store).validate(principal, row, *in)
	}
	if in := p.CIEnrollment; in != nil {
		return NewCIEnrollmentRepository(serviceRepo.store).validate(principal, row, *in)
	}
	if in := p.ServiceImport; in != nil {
		return serviceRepo.validate(principal, row, *in)
	}
	if in := p.NetworkEndpoint; in != nil {
		return validateNetworkEndpointState(ctx, row, *in, excluded...)
	}
	if b := p.AuthorizationGrantBatch; b != nil {
		if err := validateLifecycleActor(ctx, *b); err != nil {
			return err
		}
		if err := validateGrantBatchPrincipal(row, *b); err != nil {
			return err
		}
		if _, err := adoptionGrant(ctx, row, b.PrincipalID, "authorization-policy", "author", "authorization.policy.write", true); err != nil {
			return err
		}
		return validateGrantBatchChanges(row, *b)
	}
	return nil
}
