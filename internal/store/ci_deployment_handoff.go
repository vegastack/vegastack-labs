package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strings"
	"time"
)

// ConsumeDeploymentHandoff records one private delivery intent on the existing
// immutable external lease. A lost stream is uncertain and cannot be redelivered.
func (r *CIJobRepository) ConsumeDeploymentHandoff(ctx context.Context, parent adapter.ExactExecutionBinding, p generated.Plan, lease generated.ExecutorLease) error {
	if len(p.Operations) != 1 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	op := p.Operations[0]
	step := generated.RunStep{Sequence: op.Sequence, OperationID: op.OperationID, OperationType: op.OperationType, AdapterID: op.AdapterID, ExecutorID: op.ExecutorID, TargetID: op.TargetID, InputDigest: op.InputDigest, ArtifactDigest: op.ArtifactDigest, Idempotent: op.Idempotent, StepID: lease.StepID, Status: "running", EffectState: "intent-recorded"}
	if _, e := r.ManagedDeploymentAdmission(ctx, parent, p, step); e != nil {
		return e
	}
	stored, e := NewPlanRepository(r.store).GetPlan(ctx, parent.PlanID)
	if e != nil || len(stored.Plan.Operations) != 1 {
		return actionError(generated.ErrorCodePlanStale)
	}
	po := stored.Plan.Operations[0]
	operation := adapter.Operation{OperationID: po.OperationID, OperationType: po.OperationType, AdapterID: po.AdapterID, ExecutorID: po.ExecutorID, TargetID: po.TargetID, InputDigest: po.InputDigest, ArtifactDigest: po.ArtifactDigest, Idempotent: po.Idempotent}
	return r.mutate(ctx, operation, parent, "deployment-handoff", func(ctx context.Context, tx *sql.Tx, x HostActionExecution) error {
		run, actual, e := runAndPlanInTx(ctx, tx, lease.RunID)
		if e != nil || actual.PlanDigest != p.PlanDigest || planExtension(actual, "x-ci-controller-plan") != x.Plan.PlanDigest {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		current, status, _, e := readExecutorLeaseInTx(ctx, tx, lease.LeaseID)
		if e != nil || status != "active" || current.BindingDigest != lease.BindingDigest || generated.ValidateExecutorLeaseBinding(actual, run, current) != nil {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		for _, v := range []string{current.LeaseExpiresAt, current.MaximumExpiresAt, actual.ExpiresAt} {
			at, e := time.Parse(time.RFC3339, v)
			if e != nil || !r.store.config.Clock().UTC().Before(at) {
				return actionError(generated.ErrorCodePlanStale)
			}
		}
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		if e = authorizeCIManagedExecutor(row, actual, current.ExecutorID, current.TargetID); e != nil {
			return e
		}
		for _, extension := range current.Extensions {
			if extension.Name == "x-ci-deployment-handoff" {
				return actionError(generated.ErrorCodeStateConflict)
			}
		}
		var used int
		if row(`SELECT admission_consumed FROM ci_job_executions WHERE run_id=? AND step_id=? AND lease_id=? AND cleanup_status!='verified'`, parent.RunID, parent.StepID, parent.LeaseID).Scan(&used) != nil || used != 1 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		old, _ := json.Marshal(current)
		current.Extensions = append(current.Extensions, generated.ContractExtension{Name: "x-ci-deployment-handoff", ValueDigest: hostaction.Digest([]string{parent.PlanDigest, parent.LeaseID, p.PlanDigest, lease.LeaseID, planExtension(p, "x-external-deployment-credentials")})})
		next, _ := json.Marshal(current)
		result, e := tx.ExecContext(ctx, `UPDATE target_execution_leases SET canonical_bytes=? WHERE lease_id=? AND status='active' AND canonical_bytes=?`, next, lease.LeaseID, old)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return actionError(generated.ErrorCodeStateConflict)
		}
		return nil
	})
}

func ciHandoffStage(stage string) bool { return strings.HasPrefix(stage, "deployment-handoff") }
