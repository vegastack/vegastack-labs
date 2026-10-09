package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
)

func validateRoleCurrent(row discoveryRow, p generated.Plan) error {
	if p.HostAction == nil || p.HostRoleScope == nil || p.HostBaselineScope != nil || p.HostAccessSequence != nil {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	scope, err := linuxrole.ScopeForRequest(*p.HostAction)
	if err != nil || scope == nil || hostaction.Digest(scope) != hostaction.Digest(p.HostRoleScope) {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	if (scope.RoleID == "control" || scope.RoleID == "application" || scope.RoleID == "ci") && !scope.NetworkingRequired {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	_, err = actionTarget(row, *p.HostAction)
	return err
}
func roleProjection(p generated.Plan) (generated.DebianAccessInput, error) {
	if p.HostAction == nil || p.HostRoleScope == nil {
		return generated.DebianAccessInput{}, actionError(generated.ErrorCodeIntegrityFailure)
	}
	in, err := linuxrole.DecodeInput([]byte(p.HostAction.ActionInput))
	return generated.DebianAccessInput{HostID: in.HostID, HostIdentityDigest: in.HostIdentityDigest, ProfileID: in.ProfileID, ProfileLockDigest: in.ProfileLockDigest, ProfileLock: in.ProfileLock, ActionVersion: in.ActionVersion}, err
}
func validateRoleMeasurement(p generated.Plan, m generated.AccessMeasurement, ordinal int) error {
	s := p.HostRoleScope
	if s == nil || p.HostAction == nil || ordinal >= len(s.ControlIDs) || m.ControlID != s.ControlIDs[ordinal] || m.ProducerID != "linux-role" || m.ProducerVersion != "1.0.0" || m.Kind != "role" || m.Role == nil || m.Baseline != nil || m.Volume != nil || m.Probe != nil || len(m.DestinationOwnership) != 0 || m.Role.RoleID != s.RoleID || m.Role.RoleBindingDigest != s.RoleBindingDigest || m.ConfigurationDigest != p.HostAction.ActionInputDigest || m.Status == "passed" && m.Role.Verification != "effective-probe" && !(m.ControlID == "linux.role-network-boundary" && m.Role.Verification == "configuration-observed") {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	return nil
}
func authorizeRoleScope(ctx context.Context, row discoveryRow, p generated.Plan, runID string) error {
	if p.HostRoleScope == nil || p.HostAction == nil {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	var human, executor string
	if row(`SELECT a.human_id FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id WHERE r.run_id=? AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch`, runID).Scan(&human) != nil || row(`SELECT principal_id FROM audit_events WHERE event_type='run.created' AND correlation_id=? ORDER BY event_id LIMIT 1`, runID).Scan(&executor) != nil {
		return actionError(generated.ErrorCodeApprovalRequired)
	}
	for _, id := range []string{p.HostRoleScope.SubjectHostID, p.HostRoleScope.ExecutionHostID} {
		if err := authorizeBaselinePrincipal(ctx, row, p, human, id, authorization.ActionAcknowledge, "plan.acknowledge", "plan-target"); err != nil {
			return err
		}
		for _, principal := range []string{executor, p.HostAction.AutomationPrincipalID} {
			if err := authorizeBaselinePrincipal(ctx, row, p, principal, id, authorization.ActionExecute, "host.action.execute", "execution-target"); err != nil {
				return err
			}
		}
	}
	return nil
}
func (r *HostActionRepository) ValidateRolePreparation(ctx context.Context, request generated.HostActionRequest) error {
	scope, err := linuxrole.ScopeForRequest(request)
	if err != nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	if scope == nil {
		return nil
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if err := validateRoleCurrent(row, generated.Plan{HostAction: &request, HostRoleScope: scope}); err != nil {
			return err
		}
		_, err := adoptionGrant(ctx, row, scope.SubjectHostID, "host", "author", "host.action.prepare", true)
		return err
	})
}
