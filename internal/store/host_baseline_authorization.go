package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

// Uses the same canonical evaluator against this transaction's exact current
// principal/grant snapshot; no role/risk SQL approximation.
type baselinePolicySnapshot struct {
	row    discoveryRow
	action authorization.Action
}

func (s baselinePolicySnapshot) Snapshot(_ context.Context, id string, target authorization.Target) (authorization.EffectivePolicySnapshot, error) {
	p := authorization.EffectivePolicySnapshot{PrincipalID: id}
	if e := s.row(`SELECT m.state_revision,m.recovery_epoch,p.principal_kind,p.status,p.grant_revision FROM system_meta m JOIN effective_authorization_principals p ON p.principal_id=? WHERE m.id=1`, id).Scan(&p.StateRevision, &p.RecoveryEpoch, &p.PrincipalKind, &p.Status, &p.GrantRevision); e != nil {
		return p, e
	}
	var g authorization.EffectiveGrant
	var branch sql.NullString
	e := s.row(`SELECT role_id,action,capability,resource_kind,resource_id,branch FROM effective_authorization_grants WHERE principal_id=? AND capability=? AND resource_kind=? AND resource_id=? AND action=? AND branch='human' AND status='active' AND grant_revision=? ORDER BY role_id,action,grant_id LIMIT 1`, id, target.Capability, target.ResourceKind, target.ResourceID, s.action, p.GrantRevision).Scan(&g.Role, &g.AllowedAction, &g.Capability, &g.ResourceKind, &g.ResourceID, &branch)
	if e == sql.ErrNoRows {
		return p, nil
	}
	if e != nil {
		return p, e
	}
	g.Branch = authorization.Branch(branch.String)
	p.Grants = []authorization.EffectiveGrant{g}
	return p, nil
}
func authorizeBaselineScope(ctx context.Context, row discoveryRow, p generated.Plan, runID, human string) error {
	if p.HostBaselineScope == nil {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	var executor string
	if row(`SELECT principal_id FROM audit_events WHERE event_type='run.created' AND correlation_id=? ORDER BY event_id LIMIT 1`, runID).Scan(&executor) != nil {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	for _, id := range []string{p.HostBaselineScope.SubjectHostID, p.HostBaselineScope.ExecutionHostID} {
		for _, q := range []struct {
			id        string
			action    authorization.Action
			cap, kind string
		}{{human, authorization.ActionAcknowledge, "plan.acknowledge", "plan-target"}, {executor, authorization.ActionExecute, "host.action.execute", "execution-target"}} {
			var kind identity.PrincipalKind
			if row(`SELECT principal_kind FROM effective_authorization_principals WHERE principal_id=?`, q.id).Scan(&kind) != nil {
				return actionError(generated.ErrorCodeAuthorizationDenied)
			}
			if q.action == authorization.ActionAcknowledge && kind != identity.PrincipalHuman {
				return actionError(generated.ErrorCodeAuthorizationDenied)
			}
			decision, e := authorization.NewEvaluator(baselinePolicySnapshot{row, q.action}).Authorize(ctx, identity.Principal{ID: q.id, Method: identity.LocalOSPeerMethod, Kind: kind}, authorization.Request{Action: q.action, Target: authorization.Target{Capability: q.cap, ResourceKind: q.kind, ResourceID: id}, Plan: &p, Branches: []authorization.Branch{authorization.BranchHuman}})
			if e != nil || !decision.Allowed {
				return actionError(generated.ErrorCodeAuthorizationDenied)
			}
		}
	}
	return nil
}
