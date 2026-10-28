package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/cijobrunner"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func CIJobLifecycleID(b adapter.ExactExecutionBinding) string {
	return "ci-" + hostaction.Digest([]string{b.PlanID, b.RunID, b.StepID, b.LeaseID})[7:39]
}
func CIJobRunnerName(b adapter.ExactExecutionBinding) string {
	return "vsk-" + hostaction.Digest(CIJobLifecycleID(b))[7:39]
}
func (r *CIJobRepository) CurrentExecution(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (HostActionExecution, error) {
	empty := HostActionExecution{}
	if r == nil || r.store == nil || r.gates == nil || r.readiness == nil || adapter.ValidateOperation(op) != nil || op.AdapterID != hostaction.AdapterID || op.OperationType != CIJobOperation {
		return empty, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	bound, e := r.executionContext(ctx, b.RunID)
	if e != nil {
		return empty, e
	}
	snapshot, e := r.readiness.CheckCIJobHost(bound, op.TargetID)
	if e != nil {
		return empty, e
	}
	var out HostActionExecution
	e = r.store.Read(bound, func(tx ReadTx) error {
		var e error
		out, e = r.currentExecutionTx(bound, tx, op, b, snapshot)
		return e
	})
	if e != nil {
		return empty, e
	}
	refs := NewCredentialRepository(r.store)
	bindings, e := refs.GetStepBindings(bound, out.Plan, op.OperationID)
	if e != nil {
		return empty, e
	}
	expected, e := r.StepBindings(*out.Plan.CIJob)
	if e != nil || len(bindings) != len(expected) {
		return empty, actionError(generated.ErrorCodePlanStale)
	}
	for i := range expected {
		expected[i].StateRevision = b.StateRevision
		found := false
		for _, actual := range bindings {
			if actual == expected[i] {
				found = true
			}
		}
		if !found {
			return empty, actionError(generated.ErrorCodePlanStale)
		}
		ref, e := refs.GetActiveVersion(bound, expected[i].ReferenceID, b.RecoveryEpoch)
		if e != nil || ref.ConsumerID != hostaction.AdapterID || ref.PurposeID != expected[i].PurposeID || ref.MaterialVersion != expected[i].MaterialVersion || ref.TargetID != op.TargetID || ref.ResolverID != "native-systemd" || ref.ActivatedAt == nil || ref.StateRevision > b.StateRevision || !slices.Contains(ref.VerifiedConsumerIDs, hostaction.AdapterID) {
			return empty, actionError(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	return out, nil
}
func (r *CIJobRepository) currentExecutionTx(ctx context.Context, tx ReadTx, op adapter.Operation, b adapter.ExactExecutionBinding, snapshot HostAdmissionSnapshot) (HostActionExecution, error) {
	out := HostActionExecution{}
	row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
	deny := func() (HostActionExecution, error) {
		return HostActionExecution{}, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	var raw []byte
	var readable string
	if row(`SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, b.PlanID, b.PlanDigest).Scan(&raw, &readable) != nil || !decodeStoredPlan(raw, readable, &out.Plan) {
		return deny()
	}
	p := out.Plan
	in := p.CIJob
	if in == nil || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Binding.StateRevision != b.StateRevision || p.Binding.RecoveryEpoch != b.RecoveryEpoch || len(p.Operations) != 1 {
		return deny()
	}
	planned := p.Operations[0]
	if planned.OperationID != op.OperationID || planned.OperationType != CIJobOperation || planned.AdapterID != op.AdapterID || planned.TargetID != op.TargetID || planned.InputDigest != op.InputDigest || planned.ArtifactDigest != op.ArtifactDigest || planned.ExecutorID != op.ExecutorID || planned.Idempotent || op.Idempotent || op.ArtifactDigest != hostaction.Digest(in) {
		return deny()
	}
	var state, epoch int64
	if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != b.StateRevision || epoch != b.RecoveryEpoch {
		return HostActionExecution{}, actionError(generated.ErrorCodePlanStale)
	}
	var original generated.DeclarationRevision
	var reason string
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, p.Binding.DeclarationRevision).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &original) || !ValidateCIJobDeclaration(original) || hostaction.Digest(original.CIJob) != hostaction.Digest(in) {
		return deny()
	}
	if row(`SELECT canonical_bytes FROM plan_runs WHERE run_id=? AND plan_id=? AND plan_digest=? AND status='running' AND cancellation_requested=0`, b.RunID, b.PlanID, b.PlanDigest).Scan(&raw) != nil || json.Unmarshal(raw, &out.Run) != nil {
		return deny()
	}
	if row(`SELECT canonical_bytes FROM target_execution_leases WHERE lease_id=? AND run_id=? AND step_id=? AND status='active'`, b.LeaseID, b.RunID, b.StepID).Scan(&raw) != nil || json.Unmarshal(raw, &out.Lease) != nil {
		return deny()
	}
	l := out.Lease
	now := r.store.config.Clock().UTC()
	for _, value := range []string{l.LeaseExpiresAt, l.MaximumExpiresAt, p.ExpiresAt} {
		at, e := time.Parse(time.RFC3339, value)
		if e != nil || !now.Before(at) {
			return HostActionExecution{}, actionError(generated.ErrorCodePlanStale)
		}
	}
	if l.MaximumExpiresAt != b.MaximumExpiresAt || l.PlanID != b.PlanID || l.PlanDigest != b.PlanDigest || l.TargetID != op.TargetID || l.OperationID != op.OperationID || l.AdapterID != op.AdapterID || l.ArtifactDigest != op.ArtifactDigest || l.RecoveryEpoch != b.RecoveryEpoch {
		return deny()
	}
	var human string
	if row(`SELECT a.human_id FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN plan_run_steps s ON s.run_id=r.run_id WHERE r.run_id=? AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch AND s.step_id=? AND s.active_lease_id=? AND s.status='running' AND s.effect_state='intent-recorded' AND s.target_id=? AND s.operation_id=? AND s.operation_type=? AND s.adapter_id=? AND s.input_digest=? AND s.artifact_digest=?`, b.RunID, b.StepID, b.LeaseID, op.TargetID, op.OperationID, op.OperationType, op.AdapterID, op.InputDigest, op.ArtifactDigest).Scan(&human) != nil {
		return HostActionExecution{}, actionError(generated.ErrorCodeApprovalRequired)
	}
	actor, e := serviceActor(ctx)
	if e != nil {
		return deny()
	}
	if e = r.validate(actor, row, *in); e != nil {
		return HostActionExecution{}, e
	}
	for _, who := range []struct {
		id, action, cap, kind string
		admin                 bool
	}{{actor.ID, "execute", CIJobOperation, "execution-target", true}, {human, "acknowledge", "plan.acknowledge", "plan-target", true}} {
		var n int
		if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.status='active' AND g.status='active' AND g.action=? AND g.branch='human' AND g.capability=? AND g.resource_kind=? AND g.resource_id=? AND g.role_id IN ('infrastructure-admin','control-plane-admin')`, who.id, who.action, who.cap, who.kind, in.HostID).Scan(&n) != nil || n == 0 {
			return deny()
		}
	}
	if HostAdmissionSnapshotDigest(snapshot) != in.HostAdmissionDigest || snapshot.IdentityDigest != in.HostIdentityDigest || snapshot.Host.HostID != in.HostID {
		return HostActionExecution{}, actionError(generated.ErrorCodePlanStale)
	}
	if e = r.gates.validateHostAdmissionSnapshot(ctx, tx, snapshot); e != nil {
		return HostActionExecution{}, e
	}
	runtime, e := r.binding(in.ExecutionBindingID)
	if e != nil {
		return HostActionExecution{}, e
	}
	var automation int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.status='active' AND g.status='active' AND g.action='execute' AND g.branch='human' AND g.capability=? AND g.resource_kind='execution-target' AND g.resource_id=?`, runtime.AutomationPrincipalID, CIJobOperation, in.HostID).Scan(&automation) != nil || automation == 0 {
		return deny()
	}
	req := ciJobHostRequest(*in, runtime)
	out.Target, e = actionTarget(row, req)
	if e != nil {
		return HostActionExecution{}, e
	}
	created, e := time.Parse(time.RFC3339, p.CreatedAt)
	if e != nil {
		return deny()
	}
	deadline := created.Add(time.Duration(runtime.MaximumSeconds) * time.Second)
	for _, v := range []string{p.ExpiresAt, l.MaximumExpiresAt, l.LeaseExpiresAt} {
		at, _ := time.Parse(time.RFC3339, v)
		if at.Before(deadline) {
			deadline = at
		}
	}
	if !now.Before(deadline) {
		return HostActionExecution{}, actionError(generated.ErrorCodePlanStale)
	}
	spec := cijobrunner.Spec{Binding: cijobrunner.LaunchBinding{LifecycleID: CIJobLifecycleID(b), RunID: in.RunID, Attempt: uint32(in.Attempt), PlanID: b.PlanID, LeaseID: b.LeaseID, Epoch: uint64(b.RecoveryEpoch)}, Deadline: deadline, RuntimeProfileID: runtime.RuntimeProfileID, RuntimeDigest: runtime.RuntimeDigest, Organization: "", RunnerName: CIJobRunnerName(b), RunnerGroup: runtime.RunnerGroupName, Labels: nil}
	policy, e := NewCIEnrollmentRepository(r.store).appliedPolicy(row, in.Definition, RevisionToken{StateRevision: state, RecoveryEpoch: epoch})
	if e != nil {
		return HostActionExecution{}, e
	}
	spec.Organization = strings.Split(policy.Policy.Repository, "/")[0]
	spec.Labels = slices.Clone(policy.Policy.Labels)
	encoded, _ := json.Marshal(spec)
	req.ActionInput = string(encoded)
	req.ActionInputDigest = hostaction.BytesDigest(encoded)
	out.Draft = HostActionDraft{ID: p.DeclarationID, Digest: op.ArtifactDigest, Request: req}
	out.Step = generated.RunStep{StepID: b.StepID, OperationID: op.OperationID, OperationType: op.OperationType, AdapterID: op.AdapterID, ExecutorID: op.ExecutorID, TargetID: op.TargetID, InputDigest: op.InputDigest, ArtifactDigest: op.ArtifactDigest, Status: "running", EffectState: "intent-recorded"}
	return out, nil
}
func (r *CIJobRepository) ExecutionForBundle(ctx context.Context, b generated.HostActionBundle) (HostActionExecution, error) {
	stored, e := NewPlanRepository(r.store).GetPlan(ctx, b.PlanID)
	if e != nil || stored.Plan.CIJob == nil || len(stored.Plan.Operations) != 1 {
		return HostActionExecution{}, actionError(generated.ErrorCodePlanStale)
	}
	var maximum string
	e = r.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT maximum_expires_at FROM target_execution_leases WHERE lease_id=? AND run_id=? AND step_id=?`, b.LeaseID, b.RunID, b.StepID).Scan(&maximum)
	})
	if e != nil {
		return HostActionExecution{}, e
	}
	p := stored.Plan.Operations[0]
	return r.CurrentExecution(ctx, adapter.Operation{OperationID: p.OperationID, OperationType: p.OperationType, AdapterID: p.AdapterID, ExecutorID: p.ExecutorID, TargetID: p.TargetID, InputDigest: p.InputDigest, ArtifactDigest: p.ArtifactDigest, Idempotent: p.Idempotent}, adapter.ExactExecutionBinding{PlanID: b.PlanID, PlanDigest: b.PlanDigest, RunID: b.RunID, StepID: b.StepID, LeaseID: b.LeaseID, StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch, MaximumExpiresAt: maximum})
}
func (r *CIJobRepository) executionContext(ctx context.Context, runID string) (context.Context, error) {
	bound, e := r.store.HostRunReadContext(ctx, runID)
	if e != nil {
		return nil, e
	}
	p, _ := identity.PrincipalFromContext(bound)
	e = r.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT device_id FROM service_import_run_actors WHERE run_id=? AND principal_id=? AND principal_method=?`, runID, p.ID, p.Method).Scan(&p.DeviceID)
	})
	if e != nil {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return identity.WithVerifiedPrincipal(ctx, p), nil
}
func (r *CIJobRepository) attribution(ctx context.Context, runID string) (audit.Attribution, error) {
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return audit.Attribution{}, actionError(generated.ErrorCodeAuthenticationRequired)
	}
	var human string
	e := r.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT a.human_id FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id WHERE r.run_id=?`, runID).Scan(&human)
	})
	if e != nil {
		return audit.Attribution{}, e
	}
	h := identity.Principal{ID: human, Kind: identity.PrincipalHuman, Method: identity.SlackSocketModeMethod}
	var agent *audit.AgentMetadata
	if identity.EffectivePrincipalKind(p) == identity.PrincipalAgent {
		agent = &audit.AgentMetadata{Name: p.ID, SessionID: runID}
	}
	return audit.NewAttribution(p, &h, agent)
}
func (r *CIJobRepository) mutate(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, stage string, fn func(context.Context, *sql.Tx, HostActionExecution) error) error {
	bound, e := r.executionContext(ctx, b.RunID)
	if e != nil {
		return e
	}
	snapshot, e := r.readiness.CheckCIJobHost(bound, op.TargetID)
	if e != nil {
		return e
	}
	a, e := r.attribution(bound, b.RunID)
	if e != nil {
		return e
	}
	expected := RevisionToken{StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch}
	result, e := r.store.executeAuditIntent(bound, intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "ci-job-" + stage, KeyDigest: audit.Fingerprint(hostaction.Digest([]string{b.RunID, b.StepID, b.LeaseID, stage})), RequestDigest: audit.Fingerprint(hostaction.Digest(b))}, Event: audit.EventDraft{Type: audit.EventType("ci.job." + strings.ReplaceAll(stage, "_", "-")), CorrelationID: b.RunID, Attribution: a, Target: audit.Target{Kind: "host", ID: op.TargetID}}}, false, func(ctx context.Context, tx *sql.Tx) error {
		x, e := r.currentExecutionTx(ctx, ReadTx{handle: tx}, op, b, snapshot)
		if e != nil {
			return e
		}
		return fn(ctx, tx, x)
	})
	if e == nil && !result.Created && (stage == "started" || stage == "admitted" || stage == "configured" || ciHandoffStage(stage)) {
		return actionError(generated.ErrorCodeStateConflict)
	}
	return e
}
func (r *CIJobRepository) Begin(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) error {
	return r.mutate(ctx, op, b, "started", func(ctx context.Context, tx *sql.Tx, x HostActionExecution) error {
		in := x.Plan.CIJob
		var n int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ci_job_executions j JOIN immutable_plans p ON p.plan_id=(SELECT plan_id FROM plan_runs WHERE run_id=j.run_id) WHERE json_extract(p.canonical_bytes,'$.ciJob.hostId')=? AND j.cleanup_status!='verified'`, in.HostID).Scan(&n) != nil || n != 0 {
			return actionError(generated.ErrorCodeRecoveryRequired)
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO ci_job_executions(run_id,step_id,lifecycle_id,lease_id,enrollment_id,provider_run_id,attempt,recovery_epoch) VALUES(?,?,?,?,?,?,?,?)`, b.RunID, b.StepID, CIJobLifecycleID(b), b.LeaseID, in.Definition.EnrollmentID, in.RunID, in.Attempt, b.RecoveryEpoch)
		return e
	})
}
func (r *CIJobRepository) Policy(ctx context.Context, b adapter.ExactExecutionBinding, in generated.CiJobRequest) (out CIEnrollmentExecutionPolicy, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var e error
		out, e = NewCIEnrollmentRepository(r.store).appliedPolicy(func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, in.Definition, RevisionToken{StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch})
		return e
	})
	return
}
func (r *CIJobRepository) ConsumeAdmission(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, o ci.Observation) error {
	for _, id := range []string{o.RunID, o.JobID, o.Binding.RunnerID} {
		n, e := strconv.ParseInt(id, 10, 64)
		if e != nil || n <= 0 || strconv.FormatInt(n, 10) != id {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
	}
	// Refuse replay even when the audit intent idempotency key was already committed.
	var used int
	e := r.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT admission_consumed FROM ci_job_executions WHERE run_id=? AND step_id=? AND lease_id=?`, b.RunID, b.StepID, b.LeaseID).Scan(&used)
	})
	if e != nil || used != 0 {
		return actionError(generated.ErrorCodeStateConflict)
	}
	return r.mutate(ctx, op, b, "admitted", func(ctx context.Context, tx *sql.Tx, x HostActionExecution) error {
		policy, e := NewCIEnrollmentRepository(r.store).appliedPolicy(func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }, x.Plan.CIJob.Definition, RevisionToken{StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch})
		if e != nil {
			return e
		}
		p := policy.Policy
		expected := ci.Enrollment{ID: policy.Definition.EnrollmentID, Binding: ci.Binding{RepositoryID: p.RepositoryID, OwnerID: p.OwnerID, Repository: p.Repository, WorkflowID: p.WorkflowID, WorkflowPath: p.WorkflowPath, WorkflowDigest: p.WorkflowDigest, Revision: p.Revision, Ref: p.Ref, Event: p.Event, JobName: p.JobName, RunnerID: o.Binding.RunnerID, RunnerGroupID: p.RunnerGroupID, Labels: p.Labels}}
		if o.RunID != x.Plan.CIJob.RunID || o.Attempt != uint32(x.Plan.CIJob.Attempt) {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if _, e = ci.Match(expected, o, r.store.config.Clock().UTC()); e != nil {
			return e
		}
		var owned string
		if tx.QueryRowContext(ctx, `SELECT runner_id FROM ci_job_executions WHERE run_id=? AND step_id=? AND lease_id=?`, b.RunID, b.StepID, b.LeaseID).Scan(&owned) != nil || owned != o.Binding.RunnerID {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		result, e := tx.ExecContext(ctx, `UPDATE ci_job_executions SET admission_consumed=1,job_id=?,runner_id=?,observation_digest=? WHERE run_id=? AND step_id=? AND lease_id=? AND lifecycle_id=? AND admission_consumed=0 AND recovery_epoch=?`, o.JobID, o.Binding.RunnerID, hostaction.Digest(o), b.RunID, b.StepID, b.LeaseID, CIJobLifecycleID(b), b.RecoveryEpoch)
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
func (r *CIJobRepository) RecordEvent(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, event cijobrunner.LifecycleEvent) error {
	first := event
	first.Sequence = 1
	if _, e := cijobrunner.LifecycleEventDigest([]cijobrunner.LifecycleEvent{first}); e != nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	return r.mutate(ctx, op, b, "event-"+strconv.FormatUint(uint64(event.Sequence), 10), func(ctx context.Context, tx *sql.Tx, x HostActionExecution) error {
		if event.Sequence < 1 || event.Sequence > 256 {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		var count int
		if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ci_job_events WHERE run_id=? AND step_id=?`, b.RunID, b.StepID).Scan(&count) != nil || count+1 != int(event.Sequence) {
			return actionError(generated.ErrorCodeStateConflict)
		}
		raw, _ := json.Marshal(event)
		_, e := tx.ExecContext(ctx, `INSERT INTO ci_job_events VALUES(?,?,?,?,?)`, b.RunID, b.StepID, event.Sequence, raw, hostaction.BytesDigest(raw))
		return e
	})
}
func (r *CIJobRepository) RecordCompletion(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, digest, eventDigest string, verified bool) error {
	return r.mutate(ctx, op, b, "completed", func(ctx context.Context, tx *sql.Tx, x HostActionExecution) error {
		status := "uncertain"
		if verified {
			status = "verified"
		}
		_, e := tx.ExecContext(ctx, `UPDATE ci_job_executions SET completion_digest=?,event_digest=?,cleanup_status=? WHERE run_id=? AND step_id=? AND lease_id=?`, digest, eventDigest, status, b.RunID, b.StepID, b.LeaseID)
		return e
	})
}

func (r *CIJobRepository) RecordConfigured(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, runnerID uint64, runnerName string) error {
	if runnerID == 0 || runnerID > uint64(^uint64(0)>>1) || runnerName != CIJobRunnerName(b) {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	return r.mutate(ctx, op, b, "configured", func(ctx context.Context, tx *sql.Tx, x HostActionExecution) error {
		result, e := tx.ExecContext(ctx, `UPDATE ci_job_executions SET registration_stage='configured',runner_id=? WHERE run_id=? AND step_id=? AND lease_id=? AND runner_id IS NULL AND admission_consumed=0`, strconv.FormatUint(runnerID, 10), b.RunID, b.StepID, b.LeaseID)
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

func (r *CIJobRepository) RecordRegistrationStage(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, stage string) error {
	switch stage {
	case "registration_attempted", "registration_input_attempted", "registration_secret_delivered":
	default:
		return actionError(generated.ErrorCodeInputInvalid)
	}
	return r.mutate(ctx, op, b, stage, func(ctx context.Context, tx *sql.Tx, x HostActionExecution) error {
		_, e := tx.ExecContext(ctx, `UPDATE ci_job_executions SET registration_stage=? WHERE run_id=? AND step_id=? AND lease_id=? AND admission_consumed=0`, stage, b.RunID, b.StepID, b.LeaseID)
		return e
	})
}

// ExecutionReadContext restores the original server-owned run actor and device
// for current-authority readback; it grants no new execution authority.
func (r *CIJobRepository) ExecutionReadContext(ctx context.Context, runID string) (context.Context, error) {
	return r.executionContext(ctx, runID)
}
