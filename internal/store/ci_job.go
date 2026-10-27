package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/ci"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const CIJobOperation = "ci.job.execute"
const CIJobRegistrationPurpose = "ci.runner.registration"
const CIJobObserverPurpose = "ci.assignment.read"

type CIJobHostReadiness interface {
	CheckCIJobHost(context.Context, string) (HostAdmissionSnapshot, error)
}
type CIJobRepository struct {
	store     *Store
	gates     *GateRepository
	readiness CIJobHostReadiness
}

func NewCIJobRepository(s *Store) *CIJobRepository { return &CIJobRepository{store: s} }
func (r *CIJobRepository) ConfigureAdmission(g *GateRepository, v CIJobHostReadiness) {
	r.gates = g
	r.readiness = v
}

type CIEnrollmentExecutionPolicy struct {
	Definition generated.CiEnrollmentDefinition
	Policy     ci.PolicyBinding
}

func (r *CIEnrollmentRepository) appliedPolicy(row discoveryRow, d generated.CiEnrollmentDefinition, expected RevisionToken) (CIEnrollmentExecutionPolicy, error) {
	empty := CIEnrollmentExecutionPolicy{}
	rec, e := readCIEnrollment(row, d.EnrollmentID)
	if e != nil {
		return empty, e
	}
	p, e := r.policy(d)
	if e != nil {
		return empty, e
	}
	var raw []byte
	var digest string
	var epoch, state int64
	if rec.Definition != d || rec.RecoveryEpoch != expected.RecoveryEpoch || rec.StateRevision > expected.StateRevision || row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != expected.StateRevision || epoch != expected.RecoveryEpoch {
		return empty, actionError(generated.ErrorCodePlanStale)
	}
	if row(`SELECT binding_bytes,binding_digest FROM ci_enrollments WHERE enrollment_id=?`, d.EnrollmentID).Scan(&raw, &digest) != nil || digest != d.BindingDigest {
		return empty, actionError(generated.ErrorCodeIntegrityFailure)
	}
	var b generated.CiEnrollmentBinding
	if json.Unmarshal(raw, &b) != nil || hostaction.Digest(b) != digest || hostaction.Digest(p.Binding) != digest {
		return empty, actionError(generated.ErrorCodePlanStale)
	}
	var n int
	if row(`SELECT COUNT(*) FROM ci_enrollments e JOIN immutable_plans p ON p.plan_id=e.plan_id JOIN plan_runs r ON r.run_id=e.run_id AND r.plan_id=p.plan_id JOIN audit_events a ON a.correlation_id=e.run_id AND a.event_type='ci.enrollment.register-applied' AND a.after_fingerprint=e.import_digest WHERE e.enrollment_id=?`, d.EnrollmentID).Scan(&n) != nil || n != 1 {
		return empty, actionError(generated.ErrorCodeIntegrityFailure)
	}
	var originalRaw []byte
	var readable, status string
	var original generated.Plan
	if row(`SELECT p.canonical_bytes,p.readable_plan,r.status FROM ci_enrollments e JOIN immutable_plans p ON p.plan_id=e.plan_id JOIN plan_runs r ON r.run_id=e.run_id AND r.plan_id=p.plan_id WHERE e.enrollment_id=?`, d.EnrollmentID).Scan(&originalRaw, &readable, &status) != nil || !decodeStoredPlan(originalRaw, readable, &original) || original.CIEnrollment == nil || original.CIEnrollment.Definition != d || original.CIEnrollment.RecoveryEpoch != rec.RecoveryEpoch || original.Binding.StateRevision+1 != rec.StateRevision || status != "succeeded" {
		return empty, actionError(generated.ErrorCodeIntegrityFailure)
	}
	return CIEnrollmentExecutionPolicy{Definition: d, Policy: ci.PolicyBinding{RepositoryID: b.RepositoryID, OwnerID: b.RepositoryOwnerID, Repository: b.Repository, WorkflowID: b.WorkflowID, WorkflowPath: b.WorkflowPath, WorkflowDigest: b.WorkflowDigest, Revision: b.Revision, Ref: b.Ref, Event: b.Event, JobName: b.JobName, RunnerGroupID: b.RunnerGroupID, Labels: slices.Clone(b.Labels)}}, nil
}
func (r *CIJobRepository) binding(id string) (generated.CiJobExecutionBinding, error) {
	if r != nil && r.store != nil {
		for _, b := range r.store.config.CIJobBindings {
			if b.BindingID == id {
				return b, nil
			}
		}
	}
	return generated.CiJobExecutionBinding{}, actionError(generated.ErrorCodePrerequisiteBlocked)
}
func ciJobID(in generated.CiJobRequest) string { return "ci-job-" + hostaction.Digest(in)[7:39] }
func validCIJobRequest(in generated.CiJobRequest) bool {
	raw, _ := json.Marshal(in)
	n, e := strconv.ParseInt(in.RunID, 10, 64)
	return e == nil && n > 0 && strconv.FormatInt(n, 10) == in.RunID && in.Attempt > 0 && in.Attempt <= int64(^uint32(0)) && generated.ValidateContractJSON(generated.SchemaIDCiJobRequest, raw, generated.ContractExact) == nil
}
func (r *CIJobRepository) validate(actor identity.Principal, row discoveryRow, in generated.CiJobRequest) error {
	if !validCIJobRequest(in) {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	b, e := r.binding(in.ExecutionBindingID)
	if e != nil {
		return e
	}
	if hostaction.Digest(b) != in.ExecutionBindingDigest || b.HostID != in.HostID || b.HostIdentityDigest != in.HostIdentityDigest || slices.Contains(r.store.config.NetworkConnectExcludedHostIDs, b.HostID) {
		return actionError(generated.ErrorCodePlanStale)
	}
	if _, e = NewCIEnrollmentRepository(r.store).appliedPolicy(row, in.Definition, RevisionToken{StateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch}); e != nil {
		// After inert staging, the exact plan state can advance, but private policy must remain current.
		var current RevisionToken
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&current.StateRevision, &current.RecoveryEpoch) != nil {
			return e
		}
		if current.RecoveryEpoch != in.RecoveryEpoch || current.StateRevision < in.ExpectedStateRevision {
			return e
		}
		if _, e = NewCIEnrollmentRepository(r.store).appliedPolicy(row, in.Definition, current); e != nil {
			return e
		}
	}
	var active int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN read_principals r ON r.principal_id=p.principal_id WHERE p.principal_id=? AND p.status='active' AND r.status='active'`, actor.ID).Scan(&active) != nil || active != 1 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	if e = authorizeDeviceRow(row, actor); e != nil {
		return e
	}
	for _, g := range []struct {
		id, kind, action, cap string
		admin                 bool
	}{{in.Definition.EnrollmentID, "ci-enrollment", "author", "ci.job.prepare", false}, {in.HostID, "host", "read", "host.read", false}, {in.HostID, "host", "author", "host.action.prepare", true}} {
		if _, e = adoptionPrincipalGrant(actor, row, g.id, g.kind, g.action, g.cap, g.admin); e != nil {
			return e
		}
	}
	var owner int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals WHERE principal_id=? AND status='active'`, in.Definition.OwnerID).Scan(&owner) != nil || owner != 1 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	req := ciJobHostRequest(in, b)
	_, e = actionTarget(row, req)
	return e
}
func ciJobHostRequest(in generated.CiJobRequest, b generated.CiJobExecutionBinding) generated.HostActionRequest {
	return generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: CIJobOperation, ActionVersion: "1.0.0", ActionInput: "{}", ActionInputDigest: hostaction.BytesDigest([]byte("{}")), HostID: b.HostID, TargetRevision: b.TargetRevision, TargetDigest: b.TargetDigest, AutomationPrincipalID: b.AutomationPrincipalID, CallerUID: b.CallerUID, CredentialReferenceID: b.SSHReferenceID, CredentialMaterialVersion: b.SSHMaterialVersion, ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: b.TargetDigest, HostIdentityDigest: b.HostIdentityDigest}, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, IdempotencyKey: in.IdempotencyKey}
}
func (r *CIJobRepository) Prepare(ctx context.Context, in generated.CiJobDraftRequest) (out generated.CiJobRequest, err error) {
	raw, _ := json.Marshal(in)
	if generated.ValidateContractJSON(generated.SchemaIDCiJobDraftRequest, raw, generated.ContractExact) != nil {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	actor, e := serviceActor(ctx)
	if e != nil {
		return out, e
	}
	b, e := r.binding(in.ExecutionBindingID)
	if e != nil {
		return out, e
	}
	if r.gates == nil || r.readiness == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	snapshot, e := r.readiness.CheckCIJobHost(ctx, b.HostID)
	if e != nil {
		return out, e
	}
	out = generated.CiJobRequest{Schema: generated.SchemaIDCiJobRequest, SchemaVersion: "1.0.0", ExecutionBindingID: b.BindingID, ExecutionBindingDigest: hostaction.Digest(b), HostID: b.HostID, HostIdentityDigest: b.HostIdentityDigest, HostAdmissionDigest: HostAdmissionSnapshotDigest(snapshot), RunID: in.RunID, Attempt: in.Attempt, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, IdempotencyKey: in.IdempotencyKey, ReasonDigest: in.ReasonDigest}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		rec, e := readCIEnrollment(row, in.EnrollmentID)
		if e != nil {
			return e
		}
		out.Definition = rec.Definition
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != in.ExpectedStateRevision || epoch != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		if e = r.validate(actor, row, out); e != nil {
			return e
		}
		return r.gates.validateHostAdmissionSnapshot(ctx, tx, snapshot)
	})
	if err != nil {
		out = generated.CiJobRequest{}
	}
	return
}
func (r *CIJobRepository) StepBindings(in generated.CiJobRequest) ([]credentialref.StepBinding, error) {
	b, e := r.binding(in.ExecutionBindingID)
	if e != nil {
		return nil, e
	}
	if hostaction.Digest(b) != in.ExecutionBindingDigest {
		return nil, actionError(generated.ErrorCodePlanStale)
	}
	refs := []struct{ id, version, purpose string }{{b.SSHReferenceID, b.SSHMaterialVersion, hostaction.PurposeID}, {b.RegistrationReferenceID, b.RegistrationMaterialVersion, CIJobRegistrationPurpose}, {b.ObserverReferenceID, b.ObserverMaterialVersion, CIJobObserverPurpose}}
	out := []credentialref.StepBinding{}
	for _, ref := range refs {
		out = append(out, credentialref.StepBinding{OperationID: "ci-job", AdapterID: hostaction.AdapterID, TargetID: in.HostID, ReferenceID: ref.id, ConsumerID: hostaction.AdapterID, PurposeID: ref.purpose, MaterialVersion: ref.version, ResolverID: "native-systemd", StateRevision: in.ExpectedStateRevision + 3, RecoveryEpoch: in.RecoveryEpoch})
	}
	return out, nil
}
func (r *CIJobRepository) Stage(ctx context.Context, in generated.CiJobRequest) (generated.DeclarationRevisionRequest, error) {
	actor, e := serviceActor(ctx)
	if e != nil {
		return generated.DeclarationRevisionRequest{}, e
	}
	e = r.store.Read(ctx, func(tx ReadTx) error {
		return r.validate(actor, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, in)
	})
	if e != nil {
		return generated.DeclarationRevisionRequest{}, e
	}
	bindings, e := r.StepBindings(in)
	if e != nil {
		return generated.DeclarationRevisionRequest{}, e
	}
	return generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", CIJob: &in, DeclarationID: ciJobID(in), DeclarationType: CIJobOperation, ExpectedRevision: 1, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, ReasonDigest: in.ReasonDigest, Extensions: []generated.ContractExtension{{Name: "x-credential-bindings", ValueDigest: credentialref.ManifestDigest(bindings)}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "ci-job", OperationType: CIJobOperation, AdapterID: hostaction.AdapterID, TargetID: in.HostID, InputDigest: credentialref.OperationManifestDigest(bindings, "ci-job"), ArtifactDigest: hostaction.Digest(in), Idempotent: false}}}, nil
}
func ValidateCIJobDeclaration(d generated.DeclarationRevision) bool {
	present := d.CIJob != nil || d.DeclarationType == CIJobOperation
	for _, op := range d.Operations {
		present = present || op.OperationType == CIJobOperation
	}
	if !present {
		return true
	}
	in := d.CIJob
	if in == nil || !validCIJobRequest(*in) || d.CIEnrollment != nil || d.HostingLifecycle != nil || d.ServiceRecovery != nil || d.ServiceDeployment != nil || d.ServiceImport != nil || d.NetworkEndpoint != nil || d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil || d.DeclarationID != ciJobID(*in) || d.DeclarationType != CIJobOperation || len(d.Operations) != 1 || len(d.Extensions) != 1 || d.Extensions[0].Name != "x-credential-bindings" || d.RecoveryEpoch != in.RecoveryEpoch {
		return false
	}
	if d.Status == "draft" && (d.Revision != 1 || d.StateRevision != in.ExpectedStateRevision+1) {
		return false
	}
	op := d.Operations[0]
	return op.Sequence == 1 && op.OperationID == "ci-job" && op.OperationType == CIJobOperation && op.AdapterID == hostaction.AdapterID && op.TargetID == in.HostID && op.ArtifactDigest == hostaction.Digest(in) && !op.Idempotent && op.OffsiteRunSpec == nil
}

// ValidatePlan repeats current protected policy and host gate proof before JIT
// credential delivery. It does not issue admission or open a provider connection.
func (r *CIJobRepository) ValidatePlan(ctx context.Context, p generated.Plan) error {
	if r == nil || r.gates == nil || r.readiness == nil || p.CIJob == nil || len(p.Operations) != 1 || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	// The engine deliberately drops the request context after durable admission.
	// Restore its exact current run actor rather than treating context loss as
	// authority, or preventing every server-owned CI execution.
	if _, ok := identity.PrincipalFromContext(ctx); !ok {
		var runID string
		var count int
		err := r.store.Read(ctx, func(tx ReadTx) error {
			return tx.queryRow(ctx, `SELECT COALESCE(MIN(r.run_id),''),COUNT(*) FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.run_id=r.run_id AND l.step_id=s.step_id AND l.lease_id=s.active_lease_id WHERE r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND s.status='running' AND s.effect_state='intent-recorded' AND s.operation_id=? AND s.operation_type=? AND s.adapter_id='host-action' AND s.target_id=? AND s.input_digest=? AND s.artifact_digest=? AND l.status='active' AND l.target_id=? AND l.recovery_epoch=? AND l.expires_at>? AND l.maximum_expires_at>?`, p.PlanID, p.PlanDigest, p.Operations[0].OperationID, CIJobOperation, p.CIJob.HostID, p.Operations[0].InputDigest, p.Operations[0].ArtifactDigest, p.CIJob.HostID, p.Binding.RecoveryEpoch, r.store.config.Clock().UTC().Format(time.RFC3339), r.store.config.Clock().UTC().Format(time.RFC3339)).Scan(&runID, &count)
		})
		if err != nil || count != 1 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		ctx, err = r.executionContext(ctx, runID)
		if err != nil {
			return err
		}
	}
	snapshot, e := r.readiness.CheckCIJobHost(ctx, p.CIJob.HostID)
	if e != nil {
		return e
	}
	if HostAdmissionSnapshotDigest(snapshot) != p.CIJob.HostAdmissionDigest {
		return actionError(generated.ErrorCodePlanStale)
	}
	actor, e := serviceActor(ctx)
	if e != nil {
		return e
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != p.Binding.StateRevision || epoch != p.Binding.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		if e = r.validate(actor, row, *p.CIJob); e != nil {
			return e
		}
		return r.gates.validateHostAdmissionSnapshot(ctx, tx, snapshot)
	})
}
