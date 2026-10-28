package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"slices"
	"time"
)

type NotificationReadinessRepository struct {
	s       *Store
	Policy  generated.NotificationReadinessPolicy
	Primary generated.OperationsGithubDestination
	Digest  string
}

func NewNotificationReadinessRepository(s *Store, p generated.NotificationReadinessPolicy, g generated.OperationsGithubDestination) *NotificationReadinessRepository {
	return &NotificationReadinessRepository{s, p, g, operations.NotificationPolicyDigest(p, g)}
}
func (r *NotificationReadinessRepository) CheckPolicy(ctx context.Context) error {
	return r.s.Read(ctx, func(tx ReadTx) error {
		for _, id := range []string{r.Policy.PrimaryHumanID, r.Policy.SecondaryHumanID, r.Policy.PrimaryCredentialOwnerID, r.Policy.SecondaryCredentialOwnerID} {
			var count int
			if tx.queryRow(ctx, `SELECT COUNT(*) FROM effective_authorization_principals WHERE principal_id=? AND status='active' AND principal_kind='human'`, id).Scan(&count) != nil || count != 1 {
				return actionError(generated.ErrorCodeAuthorizationDenied)
			}
		}
		return nil
	})
}
func (r *NotificationReadinessRepository) Bindings(ctx context.Context, state, epoch int64) ([]credentialref.StepBinding, error) {
	var out []credentialref.StepBinding
	for _, entry := range []struct{ id, material, purpose string }{{r.Policy.PrimaryReferenceID, r.Policy.PrimaryMaterialVersion, operations.ReadinessGithubPurpose}, {r.Policy.SecondaryReferenceID, r.Policy.SecondaryMaterialVersion, operations.ReadinessSlackPurpose}} {
		ref, e := NewCredentialRepository(r.s).GetActiveVersion(ctx, entry.id, epoch)
		if e != nil || ref.ConsumerID != operations.ReadinessAdapter || ref.PurposeID != entry.purpose || ref.TargetID != r.Policy.TargetID || ref.MaterialVersion != entry.material || ref.ResolverID != "native-systemd" || ref.Status != "active" || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, operations.ReadinessAdapter) {
			return nil, actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		out = append(out, credentialref.StepBinding{OperationID: "notification-readiness", AdapterID: operations.ReadinessAdapter, ConsumerID: operations.ReadinessAdapter, PurposeID: entry.purpose, TargetID: r.Policy.TargetID, ReferenceID: entry.id, MaterialVersion: entry.material, ResolverID: "native-systemd", StateRevision: state, RecoveryEpoch: epoch})
	}
	return out, nil
}
func (r *NotificationReadinessRepository) Current(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (generated.Plan, string, error) {
	var p generated.Plan
	var human string
	deny := func() (generated.Plan, string, error) {
		return p, "", actionError(generated.ErrorCodeAuthorizationDenied)
	}
	if adapter.ValidateOperation(op) != nil || op.OperationType != operations.ReadinessOperation || op.AdapterID != operations.ReadinessAdapter || op.OperationID != "notification-readiness" || op.TargetID != r.Policy.TargetID || op.ArtifactDigest != r.Digest || op.Idempotent {
		return deny()
	}
	bound, e := NewCIJobRepository(r.s).executionContext(ctx, b.RunID)
	if e != nil {
		return deny()
	}
	actor, _ := identity.PrincipalFromContext(bound)
	e = r.s.Read(bound, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(bound, q, a...) }
		var raw []byte
		var readable string
		if row(`SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, b.PlanID, b.PlanDigest).Scan(&raw, &readable) != nil || !decodeStoredPlan(raw, readable, &p) || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || len(p.Operations) != 1 || p.Binding.RecoveryEpoch != b.RecoveryEpoch || p.Binding.StateRevision != b.StateRevision {
			return actionError(generated.ErrorCodePlanStale)
		}
		expires, expireErr := time.Parse(time.RFC3339, p.ExpiresAt)
		if expireErr != nil || !r.s.config.Clock().UTC().Before(expires) {
			return actionError(generated.ErrorCodePlanStale)
		}
		po := p.Operations[0]
		if po.OperationID != op.OperationID || po.OperationType != op.OperationType || po.AdapterID != op.AdapterID || po.TargetID != op.TargetID || po.InputDigest != op.InputDigest || po.ArtifactDigest != op.ArtifactDigest || po.ExecutorID != op.ExecutorID || po.Idempotent {
			return actionError(generated.ErrorCodePlanStale)
		}
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != b.StateRevision || epoch != b.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		now := r.s.config.Clock().UTC().Format(time.RFC3339)
		if row(`SELECT a.human_id FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND r.recovery_epoch=? AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch AND s.step_id=? AND s.operation_id=? AND s.status='running' AND s.effect_state IN ('intent-recorded','receipt-recorded') AND l.lease_id=? AND l.run_id=r.run_id AND l.step_id=s.step_id AND l.target_id=s.target_id AND l.recovery_epoch=r.recovery_epoch AND l.status='active' AND l.expires_at>? AND l.maximum_expires_at>?`, b.RunID, b.PlanID, b.PlanDigest, b.RecoveryEpoch, b.StepID, op.OperationID, b.LeaseID, now, now).Scan(&human) != nil {
			return actionError(generated.ErrorCodeApprovalRequired)
		}
		if e := authorizeBaselinePrincipal(bound, row, p, actor.ID, op.TargetID, authorization.ActionExecute, operations.ReadinessOperation, "execution-target"); e != nil {
			return e
		}
		return authorizeBaselinePrincipal(bound, row, p, human, op.TargetID, authorization.ActionAcknowledge, "plan.acknowledge", "plan-target")
	})
	if e != nil {
		return p, "", e
	}
	refs, e := r.Bindings(ctx, b.StateRevision, b.RecoveryEpoch)
	if e != nil || credentialref.OperationManifestDigest(refs, op.OperationID) != op.InputDigest {
		return deny()
	}
	if e = r.CheckPolicy(ctx); e != nil {
		return deny()
	}
	refDigest, e := r.ReferenceDigest(ctx, b.RecoveryEpoch)
	if e != nil {
		return deny()
	}
	var stored string
	e = r.s.Read(ctx, func(tx ReadTx) error {
		err := tx.queryRow(ctx, `SELECT json_extract(receipt_json,'$.referenceDigest') FROM notification_readiness_receipts WHERE run_id=?`, b.RunID).Scan(&stored)
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	})
	if e != nil || stored != "" && stored != refDigest {
		return deny()
	}
	return p, human, nil
}
func (r *NotificationReadinessRepository) ActivePlan(ctx context.Context, p generated.Plan) (adapter.ExactExecutionBinding, error) {
	var b adapter.ExactExecutionBinding
	if len(p.Operations) != 1 {
		return b, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	op := p.Operations[0]
	var count int
	e := r.s.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT COALESCE(MIN(r.run_id),''),COALESCE(MIN(s.step_id),''),COALESCE(MIN(l.lease_id),''),COUNT(*) FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id WHERE r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND s.operation_id=? AND s.status='running' AND s.effect_state='intent-recorded' AND l.status='active'`, p.PlanID, p.PlanDigest, op.OperationID).Scan(&b.RunID, &b.StepID, &b.LeaseID, &count)
	})
	if e != nil || count != 1 {
		return b, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	b.PlanID = p.PlanID
	b.PlanDigest = p.PlanDigest
	b.StateRevision = p.Binding.StateRevision
	b.RecoveryEpoch = p.Binding.RecoveryEpoch
	_, _, e = r.Current(ctx, adapter.Operation{OperationID: op.OperationID, OperationType: op.OperationType, AdapterID: op.AdapterID, ExecutorID: op.ExecutorID, TargetID: op.TargetID, InputDigest: op.InputDigest, ArtifactDigest: op.ArtifactDigest}, b)
	return b, e
}
func (r *NotificationReadinessRepository) Record(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, receipts []operations.NotificationReceipt, begin bool) error {
	_, human, e := r.Current(ctx, op, b)
	if e != nil {
		return e
	}
	a, e := r.s.HostAccessRunAttribution(ctx, b.RunID)
	if e != nil {
		return e
	}
	refDigest, e := r.ReferenceDigest(ctx, b.RecoveryEpoch)
	if e != nil {
		return e
	}
	record := operations.NotificationReceipts{ReferenceDigest: refDigest, RunID: b.RunID, PlanID: b.PlanID, PlanDigest: b.PlanDigest, StepID: b.StepID, LeaseID: b.LeaseID, PolicyDigest: r.Digest, HumanID: human, RecoveryEpoch: b.RecoveryEpoch, Receipts: receipts}
	raw, _ := json.Marshal(record)
	if len(raw) > 8192 || len(receipts) > 4 {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	status := "attempted"
	if len(receipts) == 4 {
		if _, e = operations.ValidateNotificationReceipts(record, r.Digest, b.RecoveryEpoch, r.s.config.Clock().UTC()); e != nil {
			return e
		}
		status = "completed"
	}
	digest := operations.NotificationDigest(record)
	in := discoveryIntent(a, "operations.notification-test-observed", b.RunID, operations.NotificationDigest([]any{b.RunID, len(receipts)}), digest)
	_, e = r.s.executeAuditIntent(ctx, in, false, func(ctx context.Context, tx *sql.Tx) error {
		if begin {
			_, err := tx.ExecContext(ctx, `INSERT INTO notification_readiness_receipts VALUES(?,?,?,?,?,'attempted',?,?)`, b.RunID, b.StepID, b.LeaseID, r.Digest, b.RecoveryEpoch, raw, digest)
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE notification_readiness_receipts SET receipt_json=?,receipt_digest=?,status=? WHERE run_id=? AND step_id=? AND lease_id=? AND policy_digest=? AND recovery_epoch=? AND status='attempted'`, raw, digest, status, b.RunID, b.StepID, b.LeaseID, r.Digest, b.RecoveryEpoch)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil || n != 1 {
			return actionError(generated.ErrorCodeStateConflict)
		}
		return nil
	})
	return e
}
func (r *NotificationReadinessRepository) Receipts(ctx context.Context, runID string, epoch int64) (out operations.NotificationReceipts, err error) {
	err = r.s.Read(ctx, func(tx ReadTx) error {
		var raw []byte
		var digest string
		if tx.queryRow(ctx, `SELECT n.receipt_json,n.receipt_digest FROM notification_readiness_receipts n JOIN plan_runs r ON r.run_id=n.run_id JOIN plan_run_steps s ON s.run_id=r.run_id AND s.step_id=n.step_id JOIN execution_receipts e ON e.run_id=r.run_id AND e.step_id=s.step_id AND e.lease_id=n.lease_id WHERE n.run_id=? AND n.recovery_epoch=? AND n.policy_digest=? AND n.status='completed' AND r.status='succeeded' AND r.verification_status='verified' AND r.recovery_epoch=n.recovery_epoch AND s.status='succeeded' AND s.effect_state='verified' AND e.status='succeeded' AND e.result_digest=n.receipt_digest AND s.result_digest=n.receipt_digest AND r.plan_id=json_extract(n.receipt_json,'$.planId') AND r.plan_digest=json_extract(n.receipt_json,'$.planDigest')`, runID, epoch, r.Digest).Scan(&raw, &digest) != nil || json.Unmarshal(raw, &out) != nil || operations.NotificationDigest(out) != digest {
			return actionError(generated.ErrorCodeEvidenceInvalid)
		}
		_, e := operations.ValidateNotificationReceipts(out, r.Digest, epoch, r.s.config.Clock().UTC())
		return e
	})
	if err == nil {
		current, e := r.ReferenceDigest(ctx, epoch)
		if e != nil || current != out.ReferenceDigest {
			return operations.NotificationReceipts{}, actionError(generated.ErrorCodeEvidenceInvalid)
		}
	}
	return
}
func (r *NotificationReadinessRepository) ForEvidence(ctx context.Context, id string, epoch int64) (operations.NotificationReceipts, error) {
	d, e := NewGateRepository(r.s).GetGateDraft(ctx, id)
	if e != nil {
		return operations.NotificationReceipts{}, e
	}
	digest := ""
	for _, f := range d.Bundle.Facts {
		if f.FactID == "provider-accepted-receipts" {
			digest = f.ValueDigest
		}
	}
	var runID string
	e = r.s.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT run_id FROM notification_readiness_receipts WHERE receipt_digest=? AND policy_digest=? AND recovery_epoch=? AND status='completed'`, digest, r.Digest, epoch).Scan(&runID)
	})
	if e != nil {
		return operations.NotificationReceipts{}, e
	}
	return r.Receipts(ctx, runID, epoch)
}

func IsNotificationReadiness(p generated.Plan) bool {
	return len(p.Operations) == 1 && p.Operations[0].OperationType == operations.ReadinessOperation && p.Operations[0].AdapterID == operations.ReadinessAdapter
}
func (r *NotificationReadinessRepository) VerifyExecuting(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, digest string) error {
	if _, _, e := r.Current(ctx, op, b); e != nil {
		return e
	}
	return r.s.Read(ctx, func(tx ReadTx) error {
		var raw []byte
		var got string
		var out operations.NotificationReceipts
		if tx.queryRow(ctx, `SELECT receipt_json,receipt_digest FROM notification_readiness_receipts WHERE run_id=? AND step_id=? AND lease_id=? AND policy_digest=? AND recovery_epoch=? AND status='completed'`, b.RunID, b.StepID, b.LeaseID, r.Digest, b.RecoveryEpoch).Scan(&raw, &got) != nil || json.Unmarshal(raw, &out) != nil || operations.NotificationDigest(out) != got || got != digest {
			return actionError(generated.ErrorCodeEvidenceInvalid)
		}
		_, e := operations.ValidateNotificationReceipts(out, r.Digest, b.RecoveryEpoch, r.s.config.Clock().UTC())
		return e
	})
}

func (r *NotificationReadinessRepository) ReferenceDigest(ctx context.Context, epoch int64) (string, error) {
	var refs []generated.CredentialReference
	for _, id := range []string{r.Policy.PrimaryReferenceID, r.Policy.SecondaryReferenceID} {
		ref, e := NewCredentialRepository(r.s).GetActiveVersion(ctx, id, epoch)
		if e != nil {
			return "", e
		}
		refs = append(refs, ref)
	}
	return operations.NotificationDigest(refs), nil
}
