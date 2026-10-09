package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"os"
	"path/filepath"
	"time"
)

type GrantBatchApply struct {
	PlanID, PlanDigest, RunID, StepID, LeaseID string
	Attribution                                audit.Attribution
}

func (r *GrantBatchRepository) Apply(ctx context.Context, in GrantBatchApply) (string, error) {
	if r == nil || r.store == nil {
		return "", actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	p, err := NewPlanRepository(r.store).GetPlan(ctx, in.PlanID)
	if err != nil {
		return "", err
	}
	batch := p.Plan.AuthorizationGrantBatch
	if batch == nil || p.Plan.PlanDigest != in.PlanDigest || ValidateAuthorizationGrantBatch(*batch) != nil {
		return "", actionError(generated.ErrorCodeInputInvalid)
	}
	digest := hostaction.Digest(batch)
	expected := RevisionToken{StateRevision: p.Plan.Binding.StateRevision, RecoveryEpoch: p.Plan.Binding.RecoveryEpoch}
	// This database-only mutation retains a verified, functionally restored local
	// preimage through the existing server-owned snapshot port. It works before
	// any managed host is enrolled and makes no node-loss readiness claim.
	preimage, before, err := r.prepareGrantRecovery(ctx, p.Plan, *batch, in)
	if err != nil {
		return "", err
	}
	event := audit.EventDraft{Type: "authorization.grants-applied", CorrelationID: in.RunID, Attribution: in.Attribution, Target: audit.Target{Kind: "authorization-policy", ID: batch.PrincipalID}, After: (*audit.Fingerprint)(&digest)}
	event.Before = (*audit.Fingerprint)(&before)
	intent := intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "authorization-grant-batch", KeyDigest: digestParts("authorization-grant-batch", in.RunID, in.StepID, in.LeaseID), RequestDigest: audit.Fingerprint(hostaction.Digest(struct{ Plan, Run, Step, Lease, Digest string }{in.PlanDigest, in.RunID, in.StepID, in.LeaseID, digest}))}, Event: event}
	_, err = r.store.writeIntent(ctx, intent, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		if err := validateGrantBatchExecution(ctx, row, p.Plan, *batch, in, r.store.config.Clock().UTC()); err != nil {
			return err
		}
		if err := validateGrantBatchChanges(row, *batch); err != nil {
			return err
		}
		if _, e := r.store.filesystem.InspectDatabase(ctx, preimage, r.store.config.ExpectedUID); e != nil {
			return actionError(generated.ErrorCodeRecoveryRequired)
		}
		actual, _, e := hashSnapshotFile(preimage)
		if e != nil || "sha256:"+hex.EncodeToString(actual[:]) != before {
			return actionError(generated.ErrorCodeRecoveryRequired)
		}
		var readRevision int64
		var readStatus string
		if row(`SELECT status,grant_revision FROM read_principals WHERE principal_id=?`, batch.PrincipalID).Scan(&readStatus, &readRevision) != nil || readStatus != "active" {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		next := batch.ExpectedGrantRevision + 1
		nextRead := readRevision + 1
		if next <= batch.ExpectedGrantRevision || nextRead <= readRevision {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		now := r.store.config.Clock().UTC().Format(time.RFC3339)
		for _, g := range batch.Changes {
			if g.Change == "revoke" {
				result, e := tx.ExecContext(ctx, `UPDATE effective_authorization_grants SET status='revoked',updated_at=? WHERE grant_id=? AND principal_id=? AND grant_revision=? AND status='active'`, now, g.GrantID, batch.PrincipalID, batch.ExpectedGrantRevision)
				if e != nil {
					return e
				}
				n, e := result.RowsAffected()
				if e != nil || n != 1 {
					return actionError(generated.ErrorCodeStateConflict)
				}
			} else {
				var branch any
				if g.Branch != "" {
					branch = g.Branch
				}
				if _, e := tx.ExecContext(ctx, `INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'active',?,?)`, g.GrantID, batch.PrincipalID, g.RoleID, g.Action, g.Capability, g.ResourceKind, g.ResourceID, branch, next, now, now); e != nil {
					return e
				}
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE effective_authorization_grants SET grant_revision=?,updated_at=? WHERE principal_id=? AND status='active'`, next, now, batch.PrincipalID); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE effective_authorization_principals SET grant_revision=?,updated_at=? WHERE principal_id=? AND grant_revision=? AND status='active'`, next, now, batch.PrincipalID, batch.ExpectedGrantRevision)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return actionError(generated.ErrorCodePlanStale)
		}
		for _, g := range batch.Changes {
			if g.Action != "read" {
				continue
			}
			var count int
			if row(`SELECT COUNT(*) FROM effective_authorization_grants WHERE principal_id=? AND status='active' AND grant_revision=? AND action='read' AND capability=? AND resource_kind=? AND resource_id=?`, batch.PrincipalID, next, g.Capability, g.ResourceKind, g.ResourceID).Scan(&count) != nil {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
			if count == 0 {
				if _, err = tx.ExecContext(ctx, `UPDATE read_grants SET status='revoked',grant_revision=?,updated_at=? WHERE principal_id=? AND capability=? AND resource_kind=? AND resource_id=?`, nextRead, now, batch.PrincipalID, g.Capability, g.ResourceKind, g.ResourceID); err != nil {
					return err
				}
			} else {
				if _, err = tx.ExecContext(ctx, `INSERT INTO read_grants(principal_id,capability,resource_kind,resource_id,grant_revision,status,created_at,updated_at) VALUES(?,?,?,?,?,'active',?,?) ON CONFLICT(principal_id,capability,resource_kind,resource_id) DO UPDATE SET grant_revision=excluded.grant_revision,updated_at=excluded.updated_at WHERE read_grants.status='active'`, batch.PrincipalID, g.Capability, g.ResourceKind, g.ResourceID, nextRead, now, now); err != nil {
					return err
				}
				var status string
				if row(`SELECT status FROM read_grants WHERE principal_id=? AND capability=? AND resource_kind=? AND resource_id=?`, batch.PrincipalID, g.Capability, g.ResourceKind, g.ResourceID).Scan(&status) != nil || status != "active" {
					return actionError(generated.ErrorCodeStateConflict)
				}
			}
		}
		if _, err = tx.ExecContext(ctx, `UPDATE read_grants SET grant_revision=?,updated_at=? WHERE principal_id=?`, nextRead, now, batch.PrincipalID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE read_principals SET grant_revision=?,updated_at=? WHERE principal_id=? AND status='active'`, nextRead, now, batch.PrincipalID); err != nil {
			return err
		}
		return nil
	})
	return digest, err
}

func (r *GrantBatchRepository) prepareGrantRecovery(ctx context.Context, p generated.Plan, b generated.AuthorizationGrantBatchRequest, in GrantBatchApply) (string, string, error) {
	// Refuse unauthorized calls before creating a private recovery artifact.
	if err := r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		return validateGrantBatchExecution(ctx, row, p, b, in, r.store.config.Clock().UTC())
	}); err != nil {
		return "", "", err
	}
	return r.prepareGrantSnapshot(ctx, p, in)
}

func (r *GrantBatchRepository) prepareGrantSnapshot(ctx context.Context, p generated.Plan, in GrantBatchApply) (string, string, error) {
	deny := func() (string, string, error) { return "", "", actionError(generated.ErrorCodeRecoveryRequired) }
	source, err := NewOnlineSnapshotSource(r.store)
	if err != nil {
		return deny()
	}
	expected, err := source.CurrentExpectation(ctx)
	if err != nil || expected.Revision != (RevisionToken{StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch}) {
		return deny()
	}
	port := source.(MigrationSource)
	name := string(digestParts("authorization-before", in.RunID, in.PlanDigest))[7:39]
	preimage := filepath.Join(filepath.Dir(r.store.config.DatabasePath), "authorization-before-"+name+".db")
	probe := filepath.Join(filepath.Dir(r.store.config.DatabasePath), "authorization-restore-check-"+name+".db")
	if _, err = os.Lstat(preimage); errors.Is(err, os.ErrNotExist) {
		if _, err = source.OnlineSnapshot(ctx, OnlineSnapshotRequest{Destination: preimage, Expected: expected}); err != nil {
			return deny()
		}
	} else if err != nil {
		return deny()
	}
	if inspection, e := port.InspectSnapshot(ctx, preimage, expected); e != nil || inspection.IntegrityStatus != IntegrityVerified {
		return deny()
	}
	if _, e := os.Lstat(probe); !errors.Is(e, os.ErrNotExist) {
		return deny()
	}
	if port.RestoreSnapshot(ctx, preimage, probe) != nil {
		return deny()
	}
	if inspection, e := port.InspectSnapshot(ctx, probe, expected); e != nil || inspection.IntegrityStatus != IntegrityVerified {
		return deny()
	}
	// Remove only this exact verified temporary restore probe; retain the preimage.
	if e := os.Remove(probe); e != nil {
		return deny()
	}
	sum, _, err := hashSnapshotFile(preimage)
	if err != nil {
		return deny()
	}
	return preimage, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validateGrantBatchExecution(ctx context.Context, row discoveryRow, p generated.Plan, b generated.AuthorizationGrantBatchRequest, in GrantBatchApply, now time.Time) error {
	deny := func() error { return actionError(generated.ErrorCodeAuthorizationDenied) }
	if p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Risk != "control-plane" || len(p.Operations) != 1 || p.PlanID != in.PlanID || p.PlanDigest != in.PlanDigest || hostaction.Digest(p.AuthorizationGrantBatch) != hostaction.Digest(b) {
		return deny()
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return actionError(generated.ErrorCodePlanStale)
	}
	op := p.Operations[0]
	if op.OperationID != "grant-batch" || op.OperationType != GrantBatchOperation || op.AdapterID != GrantBatchAdapter || op.TargetID != b.PrincipalID || op.InputDigest != hostaction.Digest(b) || op.ArtifactDigest != hostaction.Digest("core.authorization@1") {
		return deny()
	}
	var raw []byte
	var reason string
	var d generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, p.Binding.DeclarationRevision).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &d) || !ValidateGrantBatchDeclaration(d) || hostaction.Digest(d.AuthorizationGrantBatch) != hostaction.Digest(b) {
		return deny()
	}
	var original generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, b.ExpectedDeclarationRevision+1).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &original) || original.Status != "draft" || !ValidateGrantBatchDeclaration(original) || hostaction.Digest(original.AuthorizationGrantBatch) != hostaction.Digest(b) {
		return deny()
	}
	var human, kind string
	var grantRevision int64
	if row(`SELECT a.human_id FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND r.executor_mode='central' AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch AND s.step_id=? AND s.operation_id=? AND s.operation_type=? AND s.adapter_id=? AND s.target_id=? AND s.input_digest=? AND s.artifact_digest=? AND s.status='running' AND s.effect_state='intent-recorded' AND l.lease_id=? AND l.status='active' AND l.run_id=r.run_id AND l.step_id=s.step_id AND l.target_id=s.target_id AND l.recovery_epoch=r.recovery_epoch AND l.recovery_epoch=? AND l.expires_at>?`, in.RunID, in.PlanID, in.PlanDigest, in.StepID, op.OperationID, op.OperationType, op.AdapterID, op.TargetID, op.InputDigest, op.ArtifactDigest, in.LeaseID, p.Binding.RecoveryEpoch, now.Format(time.RFC3339)).Scan(&human) != nil {
		return actionError(generated.ErrorCodeApprovalRequired)
	}
	if in.Attribution.ResponsibleHumanPrincipalID == nil || *in.Attribution.ResponsibleHumanPrincipalID != human {
		return deny()
	}
	if row(`SELECT p.principal_kind FROM effective_authorization_principals p JOIN audit_events a ON a.principal_id=p.principal_id WHERE p.principal_id=? AND p.status='active' AND a.event_type='run.created' AND a.correlation_id=? AND a.principal_method=?`, in.Attribution.AuthenticatedPrincipalID, in.RunID, in.Attribution.AuthenticatedPrincipalMethod).Scan(&kind) != nil {
		return deny()
	}
	actor := identity.Principal{ID: in.Attribution.AuthenticatedPrincipalID, Method: in.Attribution.AuthenticatedPrincipalMethod, Kind: identity.PrincipalKind(kind)}
	if !identity.ValidPrincipal(actor) || (actor.Kind == identity.PrincipalAgent && in.Attribution.Agent == nil) {
		return deny()
	}
	if _, err := adoptionPrincipalGrant(actor, row, b.PrincipalID, "authorization-policy", "author", "authorization.policy.write", true); err != nil {
		return err
	}
	if _, err := adoptionPrincipalGrant(actor, row, b.PrincipalID, "execution-target", "execute", GrantBatchOperation, true); err != nil {
		return err
	}
	var count int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind='human' AND p.status='active' AND g.status='active' AND g.role_id IN ('control-plane-admin','infrastructure-admin') AND g.action='acknowledge' AND g.branch='human' AND g.capability='plan.acknowledge' AND g.resource_kind='plan-target' AND g.resource_id=?`, human, b.PrincipalID).Scan(&count) != nil || count == 0 {
		return deny()
	}
	if row(`SELECT grant_revision FROM effective_authorization_principals WHERE principal_id=? AND status='active'`, b.PrincipalID).Scan(&grantRevision) != nil || grantRevision != b.ExpectedGrantRevision {
		return actionError(generated.ErrorCodePlanStale)
	}
	for _, g := range b.Changes {
		if row(`SELECT COUNT(*) FROM desired_authorization_grants WHERE desired_grant_id=? AND principal_id=? AND proposed_by_principal_id=? AND role_id=? AND action=? AND capability=? AND resource_kind=? AND resource_id=? AND ifnull(branch,'')=? AND desired_revision=? AND status='draft'`, desiredBatchGrantID(b, g.GrantID), b.PrincipalID, original.CreatedBy, g.RoleID, g.Action, g.Capability, g.ResourceKind, g.ResourceID, g.Branch, b.ExpectedGrantRevision+1).Scan(&count) != nil || count != 1 {
			return deny()
		}
	}
	return nil
}

func (r *GrantBatchRepository) Verify(ctx context.Context, planID, runID, digest string) error {
	if r == nil || r.store == nil {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	p, err := NewPlanRepository(r.store).GetPlan(ctx, planID)
	if err != nil || p.Plan.AuthorizationGrantBatch == nil || hostaction.Digest(p.Plan.AuthorizationGrantBatch) != digest {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	b := p.Plan.AuthorizationGrantBatch
	return r.store.Read(ctx, func(tx ReadTx) error {
		var n, revision int64
		if tx.queryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE event_type='authorization.grants-applied' AND correlation_id=? AND target_id=? AND after_fingerprint=?`, runID, b.PrincipalID, digest).Scan(&n) != nil || n != 1 {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if tx.queryRow(ctx, `SELECT grant_revision FROM effective_authorization_principals WHERE principal_id=? AND status='active'`, b.PrincipalID).Scan(&revision) != nil || revision != b.ExpectedGrantRevision+1 {
			return actionError(generated.ErrorCodeStateConflict)
		}
		for _, g := range b.Changes {
			var status string
			var actual int64
			if tx.queryRow(ctx, `SELECT status,grant_revision FROM effective_authorization_grants WHERE grant_id=? AND principal_id=?`, g.GrantID, b.PrincipalID).Scan(&status, &actual) != nil || g.Change == "add" && (status != "active" || actual != revision) || g.Change == "revoke" && status != "revoked" {
				return actionError(generated.ErrorCodeStateConflict)
			}
		}
		return nil
	})
}
