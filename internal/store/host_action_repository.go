package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"slices"
	"time"
)

type HostActionRepository struct{ store *Store }

func NewHostActionRepository(s *Store) *HostActionRepository { return &HostActionRepository{store: s} }

type HostActionDraft struct {
	ID, Digest string
	Request    generated.HostActionRequest
}
type HostActionExecution struct {
	Plan                 generated.Plan
	Run                  generated.Run
	Step                 generated.RunStep
	Lease                generated.ExecutorLease
	Draft                HostActionDraft
	Target               generated.HostDiscoveryTarget
	VerificationEvidence *generated.AccessVerificationEvidence
}

func actionError(code string) error { return newStoreError(code, "host-action", false, nil) }
func actionTarget(row discoveryRow, req generated.HostActionRequest) (generated.HostDiscoveryTarget, error) {
	if hostaction.ValidateRequest(req) != nil {
		return generated.HostDiscoveryTarget{}, actionError(generated.ErrorCodeInputInvalid)
	}
	host, err := readManagedHost(row, req.HostID)
	if err != nil {
		return generated.HostDiscoveryTarget{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	target, err := discoveryTarget(row, host.TargetID)
	if err != nil {
		return generated.HostDiscoveryTarget{}, err
	}
	var identity string
	if row(`SELECT identity_digest FROM managed_hosts WHERE host_id=?`, req.HostID).Scan(&identity) != nil || identity != req.ConsoleConfirmation.HostIdentityDigest || target.Digest != req.TargetDigest || target.Binding.Revision != req.TargetRevision || target.Binding.RecoveryEpoch != req.RecoveryEpoch || host.RecoveryEpoch != req.RecoveryEpoch {
		return generated.HostDiscoveryTarget{}, actionError(generated.ErrorCodePlanStale)
	}
	return target.Binding, nil
}
func (r *HostActionRepository) StageDraft(ctx context.Context, req generated.HostActionRequest, a audit.Attribution) (_ HostActionDraft, outcome error) {
	defer r.actionPreparationFailure(ctx, req, &outcome)
	if r == nil || r.store == nil || hostaction.ValidateRequest(req) != nil {
		return HostActionDraft{}, actionError(generated.ErrorCodeInputInvalid)
	}
	validate := func(row discoveryRow) error {
		if _, err := actionTarget(row, req); err != nil {
			return err
		}
		p, err := adoptionGrant(ctx, row, req.HostID, "host", "author", "host.action.prepare", true)
		if err != nil {
			return err
		}
		if p != a.AuthenticatedPrincipalID {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		return nil
	}
	if err := r.store.Read(ctx, func(tx ReadTx) error {
		return validate(func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) })
	}); err != nil {
		return HostActionDraft{}, err
	}
	d := HostActionDraft{ID: hostaction.DraftID(req), Digest: hostaction.Digest(req), Request: req}
	raw, _ := json.Marshal(req)
	intent := discoveryIntent(a, "host.action.drafted", d.ID, hostdiscovery.Digest([]string{a.AuthenticatedPrincipalID, req.IdempotencyKey}), d.Digest)
	intent.Expected = &RevisionToken{StateRevision: req.ExpectedStateRevision, RecoveryEpoch: req.RecoveryEpoch}
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		if err := validate(func(q string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, q, args...) }); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO host_action_drafts VALUES(?,?,?,?,?,?) ON CONFLICT(draft_id) DO NOTHING`, d.ID, d.Digest, raw, a.AuthenticatedPrincipalID, req.ExpectedStateRevision, req.RecoveryEpoch)
		return err
	})
	return d, err
}
func readHostActionDraft(row discoveryRow, id string) (HostActionDraft, error) {
	d := HostActionDraft{ID: id}
	var raw []byte
	if row(`SELECT canonical_bytes,digest FROM host_action_drafts WHERE draft_id=?`, id).Scan(&raw, &d.Digest) != nil || json.Unmarshal(raw, &d.Request) != nil || hostaction.ValidateRequest(d.Request) != nil || hostaction.Digest(d.Request) != d.Digest {
		return HostActionDraft{}, actionError(generated.ErrorCodeIntegrityFailure)
	}
	return d, nil
}
func (r *HostActionRepository) GetDraft(ctx context.Context, id string) (HostActionDraft, error) {
	var d HostActionDraft
	if r == nil || r.store == nil {
		return d, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err := r.store.Read(ctx, func(tx ReadTx) error {
		var err error
		d, err = readHostActionDraft(func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }, id)
		return err
	})
	return d, err
}
func (r *HostActionRepository) CurrentExecution(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (HostActionExecution, error) {
	var out HostActionExecution
	if r == nil || r.store == nil || ctx == nil || adapter.ValidateOperation(op) != nil || op.AdapterID != hostaction.AdapterID || (op.OperationType != hostaction.OperationType && op.OperationType != debianaccess.LocalProbeOperation) {
		return out, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	err := r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }
		var raw []byte
		if row(`SELECT canonical_bytes FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, b.PlanID, b.PlanDigest).Scan(&raw) != nil || json.Unmarshal(raw, &out.Plan) != nil {
			return actionError(generated.ErrorCodePlanStale)
		}
		p := out.Plan
		if (p.HostAction == nil && p.HostAccessSequence == nil) || p.PlanID != b.PlanID || p.PlanDigest != b.PlanDigest || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Binding.StateRevision != b.StateRevision || p.Binding.RecoveryEpoch != b.RecoveryEpoch {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		var err error
		var planned generated.PlanOperation
		out.Draft, planned, err = actionDraftForPlan(row, p, op.OperationID)
		if err != nil {
			return err
		}
		if planned.OperationID != op.OperationID || planned.OperationType != op.OperationType || planned.AdapterID != op.AdapterID || planned.ExecutorID != op.ExecutorID || planned.TargetID != op.TargetID || planned.InputDigest != op.InputDigest || planned.ArtifactDigest != op.ArtifactDigest || planned.Idempotent != op.Idempotent {
			return actionError(generated.ErrorCodePlanStale)
		}
		d := out.Draft
		if p.HostAccessSequence == nil && (d.Request.ActionID == "debian.access.apply" || d.Request.ActionID == "debian.access.confirm" || d.Request.ActionID == "debian.access.probe-source" || d.Request.ActionID == "debian.access.probe.local") {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if d.Digest != op.ArtifactDigest || d.Request.HostID != op.TargetID {
			return actionError(generated.ErrorCodePlanStale)
		}
		out.Target, err = actionTarget(row, d.Request)
		if err != nil {
			return err
		}
		var revision, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&revision, &epoch) != nil || revision != b.StateRevision || epoch != b.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		if row(`SELECT canonical_bytes FROM plan_runs WHERE run_id=? AND plan_id=? AND plan_digest=? AND status='running' AND cancellation_requested=0`, b.RunID, b.PlanID, b.PlanDigest).Scan(&raw) != nil || json.Unmarshal(raw, &out.Run) != nil {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if row(`SELECT canonical_bytes FROM target_execution_leases WHERE lease_id=? AND run_id=? AND step_id=? AND status='active'`, b.LeaseID, b.RunID, b.StepID).Scan(&raw) != nil || json.Unmarshal(raw, &out.Lease) != nil {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		l := out.Lease
		now := r.store.config.Clock().UTC()
		expires, e1 := time.Parse(time.RFC3339, l.LeaseExpiresAt)
		maximum, e2 := time.Parse(time.RFC3339, l.MaximumExpiresAt)
		planExpiry, e3 := time.Parse(time.RFC3339, p.ExpiresAt)
		if e1 != nil || e2 != nil || e3 != nil || !now.Before(expires) || !now.Before(maximum) || !now.Before(planExpiry) || l.MaximumExpiresAt != b.MaximumExpiresAt || l.PlanID != b.PlanID || l.PlanDigest != b.PlanDigest || l.TargetID != op.TargetID || l.OperationID != op.OperationID || l.AdapterID != op.AdapterID || l.ArtifactDigest != op.ArtifactDigest || l.RecoveryEpoch != b.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		var human string
		err = row(`SELECT a.human_id FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN plan_run_steps s ON s.run_id=r.run_id WHERE r.run_id=? AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch AND s.step_id=? AND s.active_lease_id=? AND s.status='running' AND s.effect_state='intent-recorded' AND s.target_id=? AND s.operation_id=? AND s.operation_type=? AND s.adapter_id=? AND s.input_digest=? AND s.artifact_digest=?`, b.RunID, b.StepID, b.LeaseID, op.TargetID, op.OperationID, op.OperationType, op.AdapterID, op.InputDigest, op.ArtifactDigest).Scan(&human)
		if err != nil {
			return actionError(generated.ErrorCodeApprovalRequired)
		}

		if p.HostAccessSequence != nil {
			if e := validateAccessCurrentTargets(row, p, r.store.config.Clock()); e != nil {
				return e
			}
			for _, target := range p.HostAccessSequence.AuxiliaryTargets {
				var n int
				if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.status='active' AND g.status='active' AND g.branch='human' AND g.action='acknowledge' AND g.capability='plan.acknowledge' AND g.resource_kind='plan-target' AND g.resource_id=?`, human, target.HostID).Scan(&n) != nil || n == 0 {
					return actionError(generated.ErrorCodeAuthorizationDenied)
				}
				if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision JOIN audit_events a ON a.principal_id=p.principal_id WHERE a.event_type='run.created' AND a.correlation_id=? AND p.status='active' AND g.status='active' AND g.branch='human' AND g.action='execute' AND g.capability='host.action.execute' AND g.resource_kind='execution-target' AND g.resource_id=?`, b.RunID, target.HostID).Scan(&n) != nil || n == 0 {
					return actionError(generated.ErrorCodeAuthorizationDenied)
				}
			}
		}
		var count int
		if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind='human' AND p.status='active' AND g.status='active' AND g.role_id IN ('infrastructure-admin','control-plane-admin') AND g.action='acknowledge' AND g.branch='human' AND g.capability='plan.acknowledge' AND g.resource_kind='plan-target' AND g.resource_id=?`, human, op.TargetID).Scan(&count) != nil || count == 0 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision JOIN audit_events a ON a.principal_id=p.principal_id WHERE p.status='active' AND g.status='active' AND a.event_type='run.created' AND a.correlation_id=? AND g.action='execute' AND g.branch='human' AND g.capability='host.action.execute' AND g.resource_kind='execution-target' AND g.resource_id=?`, b.RunID, op.TargetID).Scan(&count) != nil || count == 0 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.status='active' AND g.status='active' AND g.action='execute' AND g.branch='human' AND g.capability='host.action.execute' AND g.resource_kind='execution-target' AND g.resource_id=?`, d.Request.AutomationPrincipalID, op.TargetID).Scan(&count) != nil || count == 0 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		out.Step = generated.RunStep{StepID: b.StepID, OperationID: op.OperationID, OperationType: op.OperationType, AdapterID: op.AdapterID, ExecutorID: op.ExecutorID, TargetID: op.TargetID, InputDigest: op.InputDigest, ArtifactDigest: op.ArtifactDigest, Status: "running", EffectState: "intent-recorded"}
		return nil
	})
	if err != nil {
		return HostActionExecution{}, err
	}
	refs := NewCredentialRepository(r.store)
	ref, err := refs.GetActiveVersion(ctx, out.Draft.Request.CredentialReferenceID, b.RecoveryEpoch)
	req := out.Draft.Request
	if err != nil || ref.ConsumerID != hostaction.AdapterID || ref.PurposeID != hostaction.PurposeID || ref.ResolverID != "native-systemd" || ref.TargetID != req.HostID || ref.MaterialVersion != req.CredentialMaterialVersion || ref.StateRevision > b.StateRevision || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, hostaction.AdapterID) {
		return HostActionExecution{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	bindings, err := refs.GetStepBindings(ctx, out.Plan, op.OperationID)
	if err != nil || len(bindings) != 1 {
		return HostActionExecution{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	expected := credentialref.StepBinding{OperationID: op.OperationID, AdapterID: hostaction.AdapterID, TargetID: req.HostID, ReferenceID: req.CredentialReferenceID, ConsumerID: hostaction.AdapterID, PurposeID: hostaction.PurposeID, MaterialVersion: req.CredentialMaterialVersion, ResolverID: "native-systemd", StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch}
	if bindings[0] != expected {
		return HostActionExecution{}, actionError(generated.ErrorCodePlanStale)
	}
	current, err := NewPlanRepository(r.store).CurrentRevision(ctx)
	if err != nil || current.StateRevision != b.StateRevision || current.RecoveryEpoch != b.RecoveryEpoch {
		return HostActionExecution{}, actionError(generated.ErrorCodePlanStale)
	}
	if out.Plan.HostAccessSequence != nil && out.Draft.Request.ActionID == "debian.access.confirm" {
		out.VerificationEvidence, err = r.AccessVerificationEvidence(ctx, out)
		if err != nil {
			return HostActionExecution{}, err
		}
	}
	return out, nil
}

func (r *HostActionRepository) ExecutionForBundle(ctx context.Context, b generated.HostActionBundle) (HostActionExecution, error) {
	if r == nil || r.store == nil {
		return HostActionExecution{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	stored, err := NewPlanRepository(r.store).GetPlan(ctx, b.PlanID)
	if err != nil || stored.Plan.PlanDigest != b.PlanDigest {
		return HostActionExecution{}, actionError(generated.ErrorCodePlanStale)
	}
	var p generated.PlanOperation
	var maximum, operationID string
	err = r.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT maximum_expires_at,operation_id FROM target_execution_leases WHERE lease_id=? AND run_id=? AND step_id=?`, b.LeaseID, b.RunID, b.StepID).Scan(&maximum, &operationID)
	})
	if err != nil {
		return HostActionExecution{}, err
	}
	for _, candidate := range stored.Plan.Operations {
		if candidate.OperationID == operationID {
			p = candidate
		}
	}
	if p.OperationType != hostaction.OperationType {
		return HostActionExecution{}, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return r.CurrentExecution(ctx, adapter.Operation{OperationID: p.OperationID, OperationType: p.OperationType, AdapterID: p.AdapterID, ExecutorID: p.ExecutorID, TargetID: p.TargetID, InputDigest: p.InputDigest, ArtifactDigest: p.ArtifactDigest, Idempotent: p.Idempotent}, adapter.ExactExecutionBinding{PlanID: b.PlanID, PlanDigest: b.PlanDigest, RunID: b.RunID, StepID: b.StepID, LeaseID: b.LeaseID, StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch, MaximumExpiresAt: maximum})
}

// VerifyHostActionConsole checks the administrator's exact plan-bound record
// against the current enrolled machine and pinned transport. It performs no
// connection and grants no admission, custody or global gate qualification.
func (r *HostActionRepository) VerifyHostActionConsole(ctx context.Context, hostID string, c generated.HostActionCredentialConfirmation, epoch int64) error {
	if r == nil || r.store == nil || c.Method != "administrator-verified-console" {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }
		h, err := readManagedHost(row, hostID)
		if err != nil {
			return err
		}
		t, err := discoveryTarget(row, h.TargetID)
		if err != nil {
			return err
		}
		var digest string
		if row(`SELECT identity_digest FROM managed_hosts WHERE host_id=?`, hostID).Scan(&digest) != nil || digest != c.HostIdentityDigest || t.Digest != c.TargetDigest || t.Binding.Revision != c.TargetRevision || h.RecoveryEpoch != epoch || t.Binding.RecoveryEpoch != epoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		return nil
	})
}
