package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type CIManagedDeploymentAdmission struct {
	ExecutionBinding                                  generated.CiJobExecutionBinding
	Enrollment                                        CIEnrollmentPolicy
	ProviderRunID, JobID, RunnerID, ObservationDigest string
	Attempt                                           int64
}

// ManagedDeploymentAdmission derives job identity exclusively from the current
// controller admission journal. Caller supplied job IDs are never accepted.
func (r *CIJobRepository) ManagedDeploymentAdmission(ctx context.Context, parent adapter.ExactExecutionBinding, child generated.Plan, requested generated.RunStep) (CIManagedDeploymentAdmission, error) {
	return r.managedDeploymentAdmission(ctx, parent, child, requested, nil)
}

// Receipt validation is read-only and requires the terminal observation already
// persisted by the external executor. Claims and renewals retain their earlier state.
func (r *CIJobRepository) ManagedDeploymentReceiptAdmission(ctx context.Context, parent adapter.ExactExecutionBinding, child generated.Plan, requested generated.RunStep, observation adapter.ReceiptObservation) (CIManagedDeploymentAdmission, error) {
	if adapter.ValidateReceiptObservation(observation) != nil || observation.Status == "running" {
		return CIManagedDeploymentAdmission{}, actionError(generated.ErrorCodeInputInvalid)
	}
	return r.managedDeploymentAdmission(ctx, parent, child, requested, &observation)
}
func (r *CIJobRepository) managedDeploymentAdmission(ctx context.Context, parent adapter.ExactExecutionBinding, child generated.Plan, requested generated.RunStep, receipt *adapter.ReceiptObservation) (out CIManagedDeploymentAdmission, err error) {
	if r == nil || r.store == nil || r.readiness == nil || r.gates == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	stored, e := NewPlanRepository(r.store).GetPlan(ctx, parent.PlanID)
	if e != nil || stored.Plan.CIJob == nil || len(stored.Plan.Operations) != 1 {
		return out, actionError(generated.ErrorCodePlanStale)
	}
	planned := stored.Plan.Operations[0]
	op := adapter.Operation{OperationID: planned.OperationID, OperationType: planned.OperationType, AdapterID: planned.AdapterID, ExecutorID: planned.ExecutorID, TargetID: planned.TargetID, InputDigest: planned.InputDigest, ArtifactDigest: planned.ArtifactDigest, Idempotent: planned.Idempotent}
	// This repeats transport credentials, applied host admission and all original
	// controller grants before examining the protected deployment companion.
	if _, e = r.CurrentExecution(ctx, op, parent); e != nil {
		return out, newStoreError(Code(e), "ci-managed-controller-current", false, e)
	}
	bound, e := r.executionContext(ctx, parent.RunID)
	if e != nil {
		return out, e
	}
	snapshot, e := r.readiness.CheckCIJobHost(bound, op.TargetID)
	if e != nil {
		return out, e
	}
	err = r.store.Read(bound, func(tx ReadTx) error {
		x, e := r.currentExecutionTx(bound, tx, op, parent, snapshot)
		if e != nil {
			return e
		}
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(bound, q, a...) }
		policy, e := r.ExternalDeploymentPolicy(x.Plan.CIJob.ExecutionBindingID)
		if e != nil || policy.Binding.BindingID == "" || policy.Digest() != x.Plan.CIJob.DeploymentDigest || child.ExecutorMode != "external" || child.ExecutorID == nil || *child.ExecutorID != policy.Binding.ExecutorID || len(child.Operations) != 1 || planExtension(child, "x-ci-controller-plan") != x.Plan.PlanDigest || planExtension(child, "x-external-deployment") != policy.Digest() {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-policy", false, nil)
		}
		var raw []byte
		var readable string
		var actual generated.Plan
		if row(`SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=? AND idempotency_key_digest=?`, child.PlanID, hostaction.Digest([]string{"ci-companion", parent.PlanID})).Scan(&raw, &readable) != nil || !decodeStoredPlan(raw, readable, &actual) || actual.PlanDigest != child.PlanDigest {
			return newStoreError(generated.ErrorCodePlanStale, "ci-managed-companion", false, nil)
		}
		pb := x.Plan.Binding
		pb.TargetDigest = hostaction.Digest([]string{policy.Definition.ServiceID})
		if actual.Binding != pb || actual.DeclarationID != x.Plan.DeclarationID {
			return newStoreError(generated.ErrorCodePlanStale, "ci-managed-binding", false, nil)
		}
		if planExtension(actual, "x-credential-bindings") != planExtension(x.Plan, "x-credential-bindings") || planExtension(actual, "x-external-deployment-credentials") != credentialref.ManifestDigest([]credentialref.StepBinding{policy.Credential(parent.StateRevision, parent.RecoveryEpoch)}) {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-manifest", false, nil)
		}
		childOp := actual.Operations[0]
		if requested.OperationID != childOp.OperationID || requested.OperationType != childOp.OperationType || requested.AdapterID != childOp.AdapterID || requested.ExecutorID != childOp.ExecutorID || requested.TargetID != childOp.TargetID || requested.InputDigest != childOp.InputDigest || requested.ArtifactDigest != childOp.ArtifactDigest {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-operation", false, nil)
		}
		out.ExecutionBinding, e = r.binding(x.Plan.CIJob.ExecutionBindingID)
		if e != nil {
			return e
		}
		if out.ExecutionBinding.AutomationPrincipalID != *child.ExecutorID {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-executor", false, nil)
		}
		enroll := NewCIEnrollmentRepository(r.store)
		if _, e = enroll.appliedPolicy(row, x.Plan.CIJob.Definition, RevisionToken{StateRevision: parent.StateRevision, RecoveryEpoch: parent.RecoveryEpoch}); e != nil {
			return e
		}
		out.Enrollment, e = enroll.policy(x.Plan.CIJob.Definition)
		if e != nil {
			return e
		}
		if out.Enrollment.Binding.JobClass != "deployment" {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-job-class", false, nil)
		}
		if row(`SELECT provider_run_id,attempt,job_id,runner_id,observation_digest FROM ci_job_executions WHERE run_id=? AND step_id=? AND lease_id=? AND lifecycle_id=? AND admission_consumed=1 AND cleanup_status!='verified' AND recovery_epoch=?`, parent.RunID, parent.StepID, parent.LeaseID, CIJobLifecycleID(parent), parent.RecoveryEpoch).Scan(&out.ProviderRunID, &out.Attempt, &out.JobID, &out.RunnerID, &out.ObservationDigest) != nil {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-admission-journal", false, nil)
		}
		for _, v := range []string{out.ProviderRunID, out.JobID, out.RunnerID} {
			n, e := strconv.ParseInt(v, 10, 64)
			if e != nil || n <= 0 || strconv.FormatInt(n, 10) != v {
				return newStoreError(generated.ErrorCodeIntegrityFailure, "ci-managed-numeric-id", false, nil)
			}
		}
		if out.ProviderRunID != x.Plan.CIJob.RunID || out.Attempt != x.Plan.CIJob.Attempt || len(out.ObservationDigest) != 71 {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "ci-managed-observed-job", false, nil)
		}
		var run generated.Run
		if row(`SELECT canonical_bytes FROM plan_runs WHERE plan_id=? AND plan_digest=? AND status='running' AND cancellation_requested=0`, child.PlanID, child.PlanDigest).Scan(&raw) != nil || json.Unmarshal(raw, &run) != nil {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-child-run", false, nil)
		}
		step := findStep(&run, requested.StepID)
		if step == nil || *step != requested || run.RecoveryEpoch != parent.RecoveryEpoch || run.StateRevision != parent.StateRevision || run.AcknowledgementID == nil {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-child-step", false, nil)
		}
		var human string
		if row(`SELECT human_id FROM acknowledgement_requests WHERE acknowledgement_id=? AND plan_id=? AND plan_digest=? AND recovery_epoch=? AND status='approved' AND consumed_at IS NOT NULL`, *run.AcknowledgementID, child.PlanID, child.PlanDigest, parent.RecoveryEpoch).Scan(&human) != nil {
			return newStoreError(generated.ErrorCodeApprovalRequired, "ci-managed-child-ack", false, nil)
		}
		if e = authorizeBaselinePrincipal(bound, row, child, human, step.TargetID, authorization.ActionAcknowledge, "plan.acknowledge", "plan-target"); e != nil {
			return newStoreError(Code(e), "ci-managed-human-grant", false, e)
		}
		if e = authorizeCIManagedExecutor(row, child, *child.ExecutorID, step.TargetID); e != nil {
			return newStoreError(Code(e), "ci-managed-executor-grant", false, e)
		}
		if receipt == nil && step.Status == "queued" && step.EffectState == "not-started" {
			var n int
			if row(`SELECT COUNT(*) FROM target_execution_leases WHERE step_id=?`, step.StepID).Scan(&n) != nil || n != 0 {
				return newStoreError(generated.ErrorCodeRecoveryRequired, "ci-managed-prior-lease", false, nil)
			}
			return nil
		}
		wantState := "intent-recorded"
		if receipt != nil {
			wantState = "receipt-recorded"
		}
		if step.Status != "running" || step.EffectState != wantState {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-effect-state", false, nil)
		}
		var lease generated.ExecutorLease
		if row(`SELECT l.canonical_bytes FROM target_execution_leases l JOIN plan_run_steps s ON s.active_lease_id=l.lease_id AND s.step_id=l.step_id WHERE l.step_id=? AND l.run_id=? AND l.status='active' AND l.lease_kind='external'`, step.StepID, run.RunID).Scan(&raw) != nil || json.Unmarshal(raw, &lease) != nil || generated.ValidateExecutorLeaseBinding(child, run, lease) != nil {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-child-lease", false, nil)
		}
		if receipt != nil {
			var count int
			if row(`SELECT COUNT(*) FROM external_execution_observations WHERE lease_id=? AND run_id=? AND step_id=? AND status=? AND result_digest=?`, lease.LeaseID, run.RunID, step.StepID, receipt.Status, receipt.ResultDigest).Scan(&count) != nil || count != 1 {
				return newStoreError(generated.ErrorCodeAuthorizationDenied, "ci-managed-receipt-observation", false, nil)
			}
		}
		for _, v := range []string{lease.LeaseExpiresAt, lease.MaximumExpiresAt, child.ExpiresAt} {
			at, e := time.Parse(time.RFC3339, v)
			if e != nil || !r.store.config.Clock().UTC().Before(at) {
				return newStoreError(generated.ErrorCodePlanStale, "ci-managed-lease-expiry", false, nil)
			}
		}
		return nil
	})
	if err != nil {
		return CIManagedDeploymentAdmission{}, err
	}
	return out, nil
}
