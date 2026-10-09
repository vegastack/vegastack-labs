package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"time"
)

func (r *HostReplacementRepository) execution(ctx context.Context, row discoveryRow, x HostReplacementExecution, operation string) (generated.Plan, error) {
	var raw, leaseRaw []byte
	var p generated.Plan
	var lease generated.ExecutorLease
	var human string
	err := row(`SELECT p.canonical_bytes,l.canonical_bytes,a.human_id FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id WHERE p.plan_id=? AND p.plan_digest=? AND r.run_id=? AND r.status='running' AND r.cancellation_requested=0 AND s.step_id=? AND s.status='running' AND s.effect_state='intent-recorded' AND s.operation_type=? AND s.adapter_id=? AND l.lease_id=? AND l.status='active' AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.plan_id=p.plan_id AND a.plan_digest=p.plan_digest AND a.recovery_epoch=r.recovery_epoch`, x.PlanID, x.PlanDigest, x.RunID, x.StepID, operation, hostreplacement.AdapterID, x.LeaseID).Scan(&raw, &leaseRaw, &human)
	if err != nil || json.Unmarshal(raw, &p) != nil || json.Unmarshal(leaseRaw, &lease) != nil || p.PlanID != x.PlanID || p.PlanDigest != x.PlanDigest || p.HostAction != nil || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || len(p.Operations) != 1 || p.Operations[0].OperationType != operation || p.Operations[0].TargetID != x.DraftID || p.Operations[0].AdapterID != hostreplacement.AdapterID {
		return p, replacementError(generated.ErrorCodeApprovalRequired)
	}
	if p.HostAccessSequence != nil || p.HostBaselineScope != nil || p.HostRoleScope != nil || (operation == hostreplacement.AliasClaimOperation && (p.HostAliasClaim == nil || p.HostReplacement != nil)) || (operation != hostreplacement.AliasClaimOperation && (p.HostReplacement == nil || p.HostAliasClaim != nil)) {
		return p, replacementError(generated.ErrorCodeIntegrityFailure)
	}
	op := p.Operations[0]
	var exact int
	if row(`SELECT COUNT(*) FROM plan_run_steps WHERE run_id=? AND step_id=? AND operation_id=? AND operation_type=? AND adapter_id=? AND target_id=? AND input_digest=? AND artifact_digest=?`, x.RunID, x.StepID, op.OperationID, op.OperationType, op.AdapterID, op.TargetID, op.InputDigest, op.ArtifactDigest).Scan(&exact) != nil || exact != 1 || lease.AdapterID != op.AdapterID || lease.ArtifactDigest != op.ArtifactDigest {
		return p, replacementError(generated.ErrorCodeIntegrityFailure)
	}
	var rev, epoch int64
	if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&rev, &epoch) != nil || rev != p.Binding.StateRevision || epoch != p.Binding.RecoveryEpoch {
		return p, replacementError(generated.ErrorCodePlanStale)
	}
	expiry, e1 := time.Parse(time.RFC3339, lease.LeaseExpiresAt)
	maximum, e2 := time.Parse(time.RFC3339, lease.MaximumExpiresAt)
	planExpiry, e3 := time.Parse(time.RFC3339, p.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || !r.store.config.Clock().Before(expiry) || !r.store.config.Clock().Before(maximum) || !r.store.config.Clock().Before(planExpiry) || lease.PlanDigest != p.PlanDigest || lease.PlanID != p.PlanID || lease.RunID != x.RunID || lease.StepID != x.StepID || lease.TargetID != x.DraftID || lease.OperationID != p.Operations[0].OperationID || lease.RecoveryEpoch != epoch {
		return p, replacementError(generated.ErrorCodePlanStale)
	}
	var actor, method string
	if row(`SELECT principal_id,principal_method FROM audit_events WHERE event_type='run.created' AND correlation_id=? ORDER BY event_id LIMIT 1`, x.RunID).Scan(&actor, &method) != nil || actor != x.Attribution.AuthenticatedPrincipalID || method != x.Attribution.AuthenticatedPrincipalMethod {
		return p, replacementError(generated.ErrorCodeAuthorizationDenied)
	}
	var attributed audit.Attribution
	var responsible, agent, session sql.NullString
	if row(`SELECT principal_id,principal_method,responsible_human_principal_id,agent_name,agent_session_id FROM audit_events WHERE event_type='run.created' AND correlation_id=? ORDER BY event_id LIMIT 1`, x.RunID).Scan(&attributed.AuthenticatedPrincipalID, &attributed.AuthenticatedPrincipalMethod, &responsible, &agent, &session) != nil {
		return p, replacementError(generated.ErrorCodeAuthorizationDenied)
	}
	if responsible.Valid {
		attributed.ResponsibleHumanPrincipalID = &responsible.String
	}
	if agent.Valid && session.Valid {
		attributed.Agent = &audit.AgentMetadata{Name: agent.String, SessionID: session.String}
	}
	if hostaction.Digest(attributed) != hostaction.Digest(x.Attribution) {
		return p, replacementError(generated.ErrorCodeAuthorizationDenied)
	}
	if err := authorizeBaselinePrincipal(ctx, row, p, human, x.DraftID, authorization.ActionAcknowledge, "plan.acknowledge", "plan-target"); err != nil {
		return p, err
	}
	if err := authorizeBaselinePrincipal(ctx, row, p, actor, x.DraftID, authorization.ActionExecute, operation, "execution-target"); err != nil {
		return p, err
	}
	bound, e := hostRunReadContext(ctx, row, x.RunID)
	if e != nil {
		return p, e
	}
	subjects := []string{}
	if p.HostReplacement != nil {
		subjects = []string{p.HostReplacement.OldHostID, p.HostReplacement.NewHostID}
	}
	if p.HostAliasClaim != nil {
		subjects = []string{p.HostAliasClaim.HostID}
	}
	if len(subjects) == 0 {
		return p, replacementError(generated.ErrorCodeIntegrityFailure)
	}
	for _, id := range subjects {
		if _, e = adoptionGrant(bound, row, id, "host", "author", "host.replacement.prepare", true); e != nil {
			return p, e
		}
		if _, e = adoptionGrant(bound, row, id, "host", "read", "host.read", false); e != nil {
			return p, e
		}
	}
	return p, nil
}
func (r *HostReplacementRepository) Freeze(ctx context.Context, x HostReplacementExecution) (generated.HostReplacementState, error) {
	var out generated.HostReplacementState
	intent := discoveryIntent(x.Attribution, "host.replacement.frozen", x.ReplacementID, hostaction.Digest(x), hostaction.Digest(x))
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		p, e := r.execution(ctx, row, x, hostreplacement.FreezeOperation)
		if e != nil {
			return e
		}
		d, e := readReplacementDraft(row, x.DraftID)
		if e != nil {
			return e
		}
		if d.Request.Operation != "freeze" || d.Request.ReplacementID != x.ReplacementID || p.HostReplacement == nil || hostaction.Digest(*p.HostReplacement) != d.Digest || p.Operations[0].InputDigest != d.Digest || p.Operations[0].ArtifactDigest != d.Digest {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		if e = validateReplacementHosts(row, d.Request); e != nil {
			return e
		}
		if e = r.validateReplacementOwnedScope(ctx, ReadTx{handle: tx}, d.Request); e != nil {
			return e
		}
		if e = requireHostUnfrozen(row, d.Request.OldHostID); e != nil {
			return e
		}
		for _, alias := range d.Request.AliasBindings {
			if e = validateAliasOwner(row, alias, false, x.ReplacementID); e != nil {
				return e
			}
		}
		bound, e := hostRunReadContext(ctx, row, x.RunID)
		if e != nil {
			return e
		}
		for _, id := range []string{d.Request.OldHostID, d.Request.NewHostID} {
			if _, e = adoptionGrant(bound, row, id, "host", "read", "host.read", false); e != nil {
				return e
			}
		}
		out = replacementState(d)
		out.AliasBindings = append([]generated.HostReplacementAliasBinding(nil), out.AliasBindings...)
		for i := range out.AliasBindings {
			out.AliasBindings[i].OwnerRevision++
		}
		out.Status = "frozen"
		out.NextAction = "resolve-fences"
		out.PlanID = &x.PlanID
		out.RunID = &x.RunID
		out.StateRevision = p.Binding.StateRevision
		out.DeclarationRevision = p.Binding.DeclarationRevision
		// Snapshot exact current authority and outstanding target execution rows. A
		// digest records what must be fenced, never asserts remote termination.
		authority, e := replacementAuthorityDigest(ctx, tx, d.Request.OldHostID)
		if e != nil {
			return e
		}
		event := HostReplacementEvent{ReplacementID: x.ReplacementID, Sequence: 1, Type: "frozen", Execution: x, State: out, AuthorityDigest: authority, At: replacementNow(r.store)}
		digest, e := insertReplacementEvent(ctx, tx, event)
		if e != nil {
			return e
		}
		out.FreezeEventDigest = digest
		for i, alias := range d.Request.AliasBindings {
			var previous string
			if e = row(`SELECT event_digest FROM host_alias_owners WHERE alias_id=?`, alias.AliasID).Scan(&previous); e != nil {
				return e
			}
			if e = insertAliasEvent(ctx, tx, HostAliasEvent{Alias: out.AliasBindings[i], PreviousDigest: previous, ReplacementID: x.ReplacementID, Execution: x, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch}); e != nil {
				return e
			}
			result, e := tx.ExecContext(ctx, `UPDATE host_alias_owners SET frozen_replacement_id=?,owner_revision=owner_revision+1,event_digest=(SELECT event_digest FROM host_alias_history WHERE alias_id=? AND owner_revision=?) WHERE alias_id=? AND owner_revision=? AND owner_host_id=? AND owner_identity_digest=? AND frozen_replacement_id IS NULL`, x.ReplacementID, alias.AliasID, alias.OwnerRevision+1, alias.AliasID, alias.OwnerRevision, alias.OwnerHostID, alias.OwnerIdentityDigest)
			if e != nil {
				return e
			}
			n, _ := result.RowsAffected()
			if n != 1 {
				return replacementError(generated.ErrorCodeStateConflict)
			}
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	if out.ReplacementID == "" {
		return r.Get(ctx, x.ReplacementID)
	}
	return out, nil
}
func replacementAuthorityDigest(ctx context.Context, tx *sql.Tx, hostID string) (string, error) {
	queries := []string{
		`SELECT reference_id,consumer_id,purpose_id,material_version,status FROM credential_reference_versions WHERE target_id=? ORDER BY reference_id,material_version`,
		`SELECT grant_id,principal_id,grant_revision,status FROM effective_authorization_grants WHERE resource_id=? ORDER BY grant_id`,
		`SELECT lease_id,run_id,step_id,status,maximum_expires_at FROM target_execution_leases WHERE target_id=? ORDER BY lease_id`,
		`SELECT run_id,step_id,operation_type,effect_state,status FROM plan_run_steps WHERE target_id=? ORDER BY run_id,step_id`,
	}
	all := [][][]string{}
	for _, query := range queries {
		rows, e := tx.QueryContext(ctx, query, hostID)
		if e != nil {
			return "", e
		}
		cols, e := rows.Columns()
		if e != nil {
			rows.Close()
			return "", e
		}
		group := [][]string{}
		for rows.Next() {
			values := make([]string, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if e = rows.Scan(ptrs...); e != nil {
				rows.Close()
				return "", e
			}
			group = append(group, values)
			if len(group) > 256 {
				rows.Close()
				return "", replacementError(generated.ErrorCodePrerequisiteBlocked)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return "", e
		}
		all = append(all, group)
	}
	return hostaction.Digest(all), nil
}

// Alias records preserve the full exact execution, not merely a mutable owner.
type HostAliasEvent struct {
	Ordinal                      int64
	Alias                        generated.HostReplacementAliasBinding
	PreviousDigest               string
	ReplacementID                string
	Execution                    HostReplacementExecution
	StateRevision, RecoveryEpoch int64
}

func insertAliasEvent(ctx context.Context, tx *sql.Tx, event HostAliasEvent) error {
	if event.Ordinal == 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(event_ordinal),0)+1 FROM host_alias_history`).Scan(&event.Ordinal); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(event)
	digest := hostaction.Digest(event)
	_, err := tx.ExecContext(ctx, `INSERT INTO host_alias_history VALUES(?,?,?,?,?,?,?,?,?)`, event.Ordinal, event.Alias.AliasID, event.Alias.OwnerRevision, event.Alias.OwnerHostID, event.Alias.OwnerIdentityDigest, event.Alias.OwnershipGeneration, nullReplacement(event.ReplacementID), digest, raw)
	return err
}
func nullReplacement(id string) any {
	if id == "" {
		return nil
	}
	return id
}
func (r *HostReplacementRepository) ClaimAliases(ctx context.Context, x HostReplacementExecution, snapshot HostAdmissionSnapshot) (generated.HostReplacementState, error) {
	intent := discoveryIntent(x.Attribution, "host.alias.claimed", x.DraftID, hostaction.Digest(x), hostaction.Digest(x))
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		p, e := r.execution(ctx, row, x, hostreplacement.AliasClaimOperation)
		if e != nil {
			return e
		}
		if p.HostAliasClaim == nil || hostreplacement.ValidateAliasClaim(*p.HostAliasClaim) != nil {
			return replacementError(generated.ErrorCodeIntegrityFailure)
		}
		q := p.HostAliasClaim
		if snapshot.Host.HostID != q.HostID || snapshot.IdentityDigest != q.HostIdentityDigest || snapshot.RoleBindingDigest == "" {
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
		bound, e := hostRunReadContext(ctx, row, x.RunID)
		if e != nil {
			return e
		}
		if e = r.gates.validateHostAdmissionSnapshot(bound, ReadTx{handle: tx}, snapshot); e != nil {
			return e
		}
		if e = requireHostUnfrozen(row, q.HostID); e != nil {
			return e
		}
		generation := int64(1)
		var current int64
		if e = row(`SELECT MAX(ownership_generation) FROM host_alias_owners WHERE owner_host_id=? AND owner_identity_digest=?`, q.HostID, q.HostIdentityDigest).Scan(&current); e == nil && current > 0 {
			generation = current
		}
		for _, id := range q.AliasIDs {
			var prior string
			e = row(`SELECT event_digest FROM host_alias_history WHERE alias_id=? LIMIT 1`, id).Scan(&prior)
			if !errors.Is(e, sql.ErrNoRows) {
				return replacementError(generated.ErrorCodeStateConflict)
			}
			alias := generated.HostReplacementAliasBinding{Schema: generated.SchemaIDHostReplacementAliasBinding, SchemaVersion: "1.0.0", AliasID: id, OwnerHostID: q.HostID, OwnerIdentityDigest: q.HostIdentityDigest, OwnerRevision: 1, OwnershipGeneration: generation}
			event := HostAliasEvent{Alias: alias, Execution: x, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch}
			if e = insertAliasEvent(ctx, tx, event); e != nil {
				return e
			}
			_, e = tx.ExecContext(ctx, `INSERT INTO host_alias_owners SELECT alias_id,owner_host_id,owner_identity_digest,owner_revision,ownership_generation,event_digest,NULL FROM host_alias_history WHERE alias_id=? AND owner_revision=1`, id)
			if e != nil {
				return e
			}
		}
		return nil
	})
	return generated.HostReplacementState{}, err
}

// VerifyExecution verifies durable completion without demanding the still-live
// native lease after the effect. Current actor scope remains mandatory.
func (r *HostReplacementRepository) VerifyExecution(ctx context.Context, x HostReplacementExecution, operation string) error {
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		bound, e := hostRunReadContext(ctx, row, x.RunID)
		if e != nil {
			return e
		}
		if operation == hostreplacement.AliasClaimOperation {
			var raw []byte
			var p generated.Plan
			if row(`SELECT canonical_bytes FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, x.PlanID, x.PlanDigest).Scan(&raw) != nil || json.Unmarshal(raw, &p) != nil || p.HostAliasClaim == nil {
				return replacementError(generated.ErrorCodeIntegrityFailure)
			}
			if _, e = adoptionGrant(bound, row, p.HostAliasClaim.HostID, "host", "read", "host.read", false); e != nil {
				return e
			}
			for _, alias := range p.HostAliasClaim.AliasIDs {
				var bytes []byte
				var event HostAliasEvent
				if row(`SELECT event_bytes FROM host_alias_history WHERE alias_id=? AND owner_revision=1`, alias).Scan(&bytes) != nil || json.Unmarshal(bytes, &event) != nil || hostaction.Digest(event.Execution) != hostaction.Digest(x) {
					return replacementError(generated.ErrorCodePrerequisiteBlocked)
				}
			}
			return nil
		}
		kind := ""
		switch operation {
		case hostreplacement.FreezeOperation:
			kind = "frozen"
		case hostreplacement.CommitOperation:
			kind = "committed"
		default:
			return replacementError(generated.ErrorCodeInputInvalid)
		}
		var raw []byte
		var event HostReplacementEvent
		if row(`SELECT event_bytes FROM host_replacement_events WHERE replacement_id=? AND event_type=?`, x.ReplacementID, kind).Scan(&raw) != nil || json.Unmarshal(raw, &event) != nil || hostaction.Digest(event.Execution) != hostaction.Digest(x) {
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
		for _, id := range []string{event.State.OldHostID, event.State.NewHostID} {
			if _, e = adoptionGrant(bound, row, id, "host", "read", "host.read", false); e != nil {
				return e
			}
		}
		return nil
	})
}
