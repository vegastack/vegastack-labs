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
func verifyWorkflowRunAuthorization(ctx context.Context, row discoveryRow, run generated.Run, attribution audit.Attribution) error {
	var canonical []byte
	var readable string
	var p generated.Plan
	if row(`SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, run.PlanID, run.PlanDigest).Scan(&canonical, &readable) != nil || !decodeStoredPlan(canonical, readable, &p) {
		return actionError(generated.ErrorCodePlanStale)
	}
	if p.AuthorizationGrantBatch == nil && p.HostDiscoveryTarget == nil && p.HostAdoption == nil && p.HostAction == nil && p.HostAccessSequence == nil && p.HostReplacement == nil && p.HostAliasClaim == nil {
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
	if b := p.AuthorizationGrantBatch; b != nil {
		var revision int64
		if row(`SELECT grant_revision FROM effective_authorization_principals WHERE principal_id=? AND status='active'`, b.PrincipalID).Scan(&revision) != nil || revision != b.ExpectedGrantRevision {
			return actionError(generated.ErrorCodePlanStale)
		}
		if _, err := adoptionGrant(ctx, row, b.PrincipalID, "authorization-policy", "author", "authorization.policy.write", true); err != nil {
			return err
		}
		return validateGrantBatchChanges(row, *b)
	}
	return nil
}
