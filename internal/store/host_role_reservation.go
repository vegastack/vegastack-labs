package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
)

// HostRunReadContext restores only the authenticated actor of a durable run.
// Responsible-human attribution never substitutes for that actor's read grants.
func (s *Store) HostRunReadContext(ctx context.Context, runID string) (context.Context, error) {
	var bound context.Context
	err := s.Read(ctx, func(tx ReadTx) error {
		var err error
		bound, err = hostRunReadContext(ctx, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, runID)
		return err
	})
	return bound, err
}
func hostRunReadContext(ctx context.Context, row discoveryRow, runID string) (context.Context, error) {
	var p identity.Principal
	var kind string
	var human, agent, session sql.NullString
	err := row(`SELECT a.principal_id,a.principal_method,p.principal_kind,a.responsible_human_principal_id,a.agent_name,a.agent_session_id FROM audit_events a JOIN effective_authorization_principals p ON p.principal_id=a.principal_id AND p.status='active' JOIN plan_runs r ON r.run_id=a.correlation_id WHERE a.event_type='run.created' AND r.run_id=? ORDER BY a.event_id LIMIT 1`, runID).Scan(&p.ID, &p.Method, &kind, &human, &agent, &session)
	p.Kind = identity.PrincipalKind(kind)
	if err != nil || !identity.ValidPrincipal(p) || !identity.ValidPrincipalKind(p.Kind) || p.Kind == identity.PrincipalAgent && (!human.Valid || human.String == "" || !agent.Valid || agent.String == "" || !session.Valid || session.String == "") {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return identity.WithVerifiedPrincipal(ctx, p), nil
}

// HostRoleReadiness is supplied by the server's common gate evaluator. Store
// rechecks that exact snapshot inside its existing writer transaction.
type HostRoleReadiness interface {
	VerifyRoleBaseline(context.Context, generated.Plan) (HostAdmissionSnapshot, error)
}

func (r *RunRepository) ConfigureHostRoles(gates *GateRepository, verifier HostRoleReadiness) {
	r.roleGates = gates
	r.roleReadiness = verifier
}
func (r *RunRepository) roleReservationSnapshot(ctx context.Context, runID string) (*HostAdmissionSnapshot, error) {
	var raw []byte
	err := r.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT p.canonical_bytes FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest WHERE r.run_id=?`, runID).Scan(&raw)
	})
	var p generated.Plan
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil, actionError(generated.ErrorCodeIntegrityFailure)
	}
	roleAction := p.HostAction != nil && linuxrole.IsAction(p.HostAction.ActionID)
	if roleAction != (p.HostRoleScope != nil) {
		return nil, actionError(generated.ErrorCodeIntegrityFailure)
	}
	if p.HostRoleScope == nil {
		return nil, nil
	}
	stored, err := NewPlanRepository(r.store).GetPlan(ctx, p.PlanID)
	if err != nil {
		return nil, err
	}
	p = stored.Plan
	if r.roleGates == nil || r.roleReadiness == nil {
		return nil, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	ctx, err = r.store.HostRunReadContext(ctx, runID)
	if err != nil {
		return nil, err
	}
	s, err := r.roleReadiness.VerifyRoleBaseline(ctx, p)
	if err != nil {
		return nil, err
	}
	if HostAdmissionSnapshotDigest(s) != p.HostRoleScope.BaselineSnapshotDigest || s.RoleBindingDigest != p.HostRoleScope.CurrentRoleBindingDigest {
		return nil, actionError(generated.ErrorCodePlanStale)
	}
	if p.HostAction == nil || p.HostAction.ActionID != "debian.role.apply" && p.HostRoleScope.RoleBindingDigest != s.RoleBindingDigest {
		return nil, actionError(generated.ErrorCodePlanStale)
	}
	return &s, nil
}
func (r *RunRepository) validateRoleReservation(ctx context.Context, tx *sql.Tx, p generated.Plan, runID string, s *HostAdmissionSnapshot) error {
	if p.HostRoleScope == nil {
		if s != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		return nil
	}
	if s == nil || r.roleGates == nil || HostAdmissionSnapshotDigest(*s) != p.HostRoleScope.BaselineSnapshotDigest {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
	bound, err := hostRunReadContext(ctx, row, runID)
	if err != nil {
		return err
	}
	if err := r.roleGates.validateHostAdmissionSnapshot(bound, ReadTx{handle: tx}, *s); err != nil {
		return err
	}
	if err := validateRoleCurrent(row, p); err != nil {
		return err
	}
	return authorizeRoleScope(ctx, row, p, runID)
}
