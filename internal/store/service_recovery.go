package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
)

type ServiceRecoveryRepository struct{ store *Store }

func NewServiceRecoveryRepository(s *Store) *ServiceRecoveryRepository {
	return &ServiceRecoveryRepository{s}
}
func serviceRecoveryDeclarationID(in generated.ServiceRecoveryRequest) string {
	return "service-recovery-" + servicerecovery.Digest(in)[7:39]
}
func normalizeServiceRecoveryPolicies(c *Config) error {
	if len(c.ServiceRecoveryPolicies) > 128 {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	seen := map[string]bool{}
	for _, p := range c.ServiceRecoveryPolicies {
		raw, _ := json.Marshal(p.Binding)
		if generated.ValidateContractJSON(generated.SchemaIDServiceRecoveryBinding, raw, generated.ContractExact) != nil || seen[p.Binding.PolicyID] || p.Binding.ConsistencyProcedureID != servicerecovery.ConsistencyProcedureID {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		seen[p.Binding.PolicyID] = true
	}
	c.ServiceRecoveryPolicies = append([]servicerecovery.Policy(nil), c.ServiceRecoveryPolicies...)
	return nil
}
func (r *ServiceRecoveryRepository) policy(id string) (servicerecovery.Policy, error) {
	if r == nil || r.store == nil {
		return servicerecovery.Policy{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	for _, p := range r.store.config.ServiceRecoveryPolicies {
		if p.Binding.PolicyID == id {
			return p, nil
		}
	}
	return servicerecovery.Policy{}, actionError(generated.ErrorCodePrerequisiteBlocked)
}
func serviceRecoveryRevision(row discoveryRow, id string) (int64, error) {
	var n int64
	err := row(`SELECT COALESCE(MAX(revision),0) FROM service_recoveries WHERE service_id=?`, id).Scan(&n)
	return n, err
}
func (r *ServiceRecoveryRepository) validate(p identity.Principal, row discoveryRow, in generated.ServiceRecoveryRequest, preparing ...bool) error {
	if servicerecovery.ValidateRequest(in) != nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	policy, e := r.policy(in.Binding.PolicyID)
	if e != nil {
		return e
	}
	if policy.Binding != in.Binding {
		return actionError(generated.ErrorCodePlanStale)
	}
	if in.Binding.DataClass == "platform" {
		if e = r.platformAuthorize(p, row, in.Definition, in.Binding.PolicyID); e != nil {
			return e
		}
	} else {
		current, e := readService(row, in.Definition.ServiceID)
		if e != nil {
			return e
		}
		if current.Definition != in.Definition {
			return actionError(generated.ErrorCodePlanStale)
		}
		if e = NewServiceRepository(r.store).authorize(p, row, in.Definition, "author", "service.recovery.prepare"); e != nil {
			return e
		}
	}

	revision, e := serviceRecoveryRevision(row, in.Definition.ServiceID)
	if e != nil {
		return e
	}
	if revision != in.ExpectedRecoveryRevision {
		return actionError(generated.ErrorCodePlanStale)
	}
	if in.Action != "backup" && in.Action != "migration-freeze" {
		var count int
		if row(`SELECT COUNT(*) FROM service_recoveries WHERE service_id=? AND policy_id=? AND recovery_epoch=? AND status='succeeded' AND json_extract(canonical_bytes,'$.backupPointId')=?`, in.Definition.ServiceID, in.Binding.PolicyID, in.RecoveryEpoch, in.BackupPointID).Scan(&count) != nil || count == 0 {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	return nil
}
func (r *ServiceRecoveryRepository) Prepare(ctx context.Context, in generated.ServiceRecoveryDraftRequest) (out generated.ServiceRecoveryRequest, err error) {
	raw, _ := json.Marshal(in)
	if generated.ValidateContractJSON(generated.SchemaIDServiceRecoveryDraftRequest, raw, generated.ContractExact) != nil {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	actor, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	policy, err := r.policy(in.PolicyID)
	if err != nil {
		return out, err
	}
	out = generated.ServiceRecoveryRequest{Schema: generated.SchemaIDServiceRecoveryRequest, SchemaVersion: "1.0.0", Binding: policy.Binding, Action: in.Action, BackupPointID: in.BackupPointID, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, IdempotencyKey: in.IdempotencyKey, ReasonDigest: in.ReasonDigest}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != in.ExpectedStateRevision || epoch != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		record, e := readService(row, in.ServiceID)
		if policy.Binding.DataClass == "platform" {
			host, he := readManagedHost(row, policy.Binding.SourceHostID)
			e = he
			record.Definition = generated.ServiceDefinition{Schema: generated.SchemaIDServiceDefinition, SchemaVersion: "1.0.0", ServiceID: in.ServiceID, EnvironmentID: "platform", OwnerID: policy.PlatformOwnerID, HostID: host.HostID, HostIdentityDigest: managedRecoveryIdentity(row, host.HostID), BindingID: policy.Binding.PolicyID, BindingDigest: policy.Binding.ConfigurationDigest}
		}
		if e != nil {
			return e
		}
		out.Definition = record.Definition
		out.ExpectedRecoveryRevision, e = serviceRecoveryRevision(row, in.ServiceID)
		if e != nil {
			return e
		}
		return r.validate(actor, row, out, true)
	})
	return
}
func (r *ServiceRecoveryRepository) Stage(ctx context.Context, in generated.ServiceRecoveryRequest) (out generated.DeclarationRevisionRequest, err error) {
	actor, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != in.ExpectedStateRevision || epoch != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		return r.validate(actor, row, in)
	})
	if err != nil {
		return out, err
	}
	digest := servicerecovery.Digest(in)
	return generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", ServiceRecovery: &in, DeclarationID: serviceRecoveryDeclarationID(in), DeclarationType: "service.recovery", ExpectedRevision: 1, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, ReasonDigest: in.ReasonDigest, Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: servicerecovery.OperationID, OperationType: servicerecovery.Operation, AdapterID: servicerecovery.AdapterID, TargetID: in.Definition.ServiceID, InputDigest: digest, ArtifactDigest: digest, Idempotent: false}}}, nil
}
func ValidateServiceRecoveryDeclaration(d generated.DeclarationRevision) bool {
	present := d.ServiceRecovery != nil || d.DeclarationType == "service.recovery"
	for _, op := range d.Operations {
		present = present || op.AdapterID == servicerecovery.AdapterID
	}
	if !present {
		return true
	}
	in := d.ServiceRecovery
	if in == nil || d.CIEnrollment != nil || servicerecovery.ValidateRequest(*in) != nil || d.ServiceImport != nil || d.NetworkEndpoint != nil || d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil || d.DeclarationType != "service.recovery" || d.DeclarationID != serviceRecoveryDeclarationID(*in) || len(d.Operations) != 1 || len(d.Extensions) != 0 || d.RecoveryEpoch != in.RecoveryEpoch {
		return false
	}
	if d.Status == "draft" && (d.StateRevision != in.ExpectedStateRevision+1 || d.Revision != 1) {
		return false
	}
	op := d.Operations[0]
	return op.Sequence == 1 && op.OperationID == servicerecovery.OperationID && op.OperationType == servicerecovery.Operation && op.AdapterID == servicerecovery.AdapterID && op.TargetID == in.Definition.ServiceID && op.InputDigest == servicerecovery.Digest(in) && op.ArtifactDigest == op.InputDigest && !op.Idempotent && op.OffsiteRunSpec == nil
}
func (r *ServiceRecoveryRepository) Get(ctx context.Context, id string) (out generated.ServiceRecoveryRecord, err error) {
	platform := false
	for _, policy := range r.store.config.ServiceRecoveryPolicies {
		if policy.Binding.ServiceID == id && policy.Binding.DataClass == "platform" {
			platform = true
			if _, e := r.PlatformDefinition(ctx, policy.Binding.PolicyID, false); e != nil {
				return out, e
			}
		}
	}
	if !platform {
		if _, err = NewServiceRepository(r.store).Get(ctx, id); err != nil {
			return out, err
		}
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var pending int
		if tx.queryRow(ctx, `SELECT COUNT(*) FROM service_recovery_attempts WHERE service_id=? AND status='attempted'`, id).Scan(&pending) != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if pending != 0 {
			return actionError(generated.ErrorCodeRecoveryRequired)
		}
		var raw []byte
		var digest string
		err := tx.queryRow(ctx, `SELECT canonical_bytes,digest FROM service_recoveries WHERE service_id=? ORDER BY revision DESC LIMIT 1`, id).Scan(&raw, &digest)
		if errors.Is(err, sql.ErrNoRows) {
			return actionError(generated.ErrorCodeResourceNotFound)
		}
		if err != nil {
			return err
		}
		if json.Unmarshal(raw, &out) != nil || servicerecovery.Digest(out) != digest || generated.ValidateContractJSON(generated.SchemaIDServiceRecoveryRecord, raw, generated.ContractExact) != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		return nil
	})
	return
}

// Authorize repeats the current resource, actor, device, epoch and execution
// grant checks at each protected adapter boundary. It never substitutes for
// the exact plan, consumed acknowledgement and active lease required by Begin.
func (r *ServiceRecoveryRepository) Authorize(ctx context.Context, in generated.ServiceRecoveryRequest) error {
	actor, err := serviceActor(ctx)
	if err != nil {
		return err
	}
	if r == nil || r.store == nil {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if err := r.validate(actor, row, in); err != nil {
			return err
		}
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || epoch != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		p := generated.Plan{Risk: "production-like", AuthorizationBranch: "human", ExecutorMode: "central", Binding: generated.PlanBinding{StateRevision: state, RecoveryEpoch: epoch}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: servicerecovery.OperationID, OperationType: servicerecovery.Operation, AdapterID: servicerecovery.AdapterID, TargetID: in.Definition.ServiceID}}}
		if err := authorizeBaselinePrincipal(ctx, row, p, actor.ID, in.Definition.ServiceID, authorization.ActionExecute, servicerecovery.Operation, "execution-target"); err != nil {
			return err
		}
		// During provider execution also repeat the exact active run/lease and
		// consumed human acknowledgement. Draft preparation has no attempt.
		var count int
		if row(`SELECT COUNT(*) FROM service_recovery_attempts WHERE request_digest=? AND status='attempted'`, servicerecovery.Digest(in)).Scan(&count) != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if count == 0 {
			return nil
		}
		var canonical []byte
		var readable, human string
		var name, session sql.NullString
		apply := ServiceRecoveryApply{}
		if row(`SELECT p.canonical_bytes,p.readable_plan,r.run_id,s.step_id,s.active_lease_id,a.human_id,e.agent_name,e.agent_session_id FROM service_recovery_attempts d JOIN immutable_plans p ON p.plan_id=d.plan_id JOIN plan_runs r ON r.run_id=d.run_id JOIN plan_run_steps s ON s.run_id=r.run_id AND s.step_id=d.step_id JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN audit_events e ON e.correlation_id=r.run_id AND e.event_type='run.created' WHERE d.request_digest=? AND d.status='attempted' AND e.principal_id=? AND e.principal_method=?`, servicerecovery.Digest(in), actor.ID, actor.Method).Scan(&canonical, &readable, &apply.RunID, &apply.StepID, &apply.LeaseID, &human, &name, &session) != nil || !decodeStoredPlan(canonical, readable, &p) {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		apply.PlanID = p.PlanID
		apply.PlanDigest = p.PlanDigest
		apply.Attribution = audit.Attribution{AuthenticatedPrincipalID: actor.ID, AuthenticatedPrincipalMethod: actor.Method, ResponsibleHumanPrincipalID: &human}
		if name.Valid && session.Valid {
			apply.Attribution.Agent = &audit.AgentMetadata{Name: name.String, SessionID: session.String}
		}
		return r.validateServiceRecoveryExecution(ctx, row, p, in, apply, r.store.config.Clock().UTC())
	})
}

func (r *ServiceRecoveryRepository) AuthorizeConfiguration(ctx context.Context, in generated.ServiceRecoveryRequest, preparing bool) error {
	p, e := serviceActor(ctx)
	if e != nil {
		return e
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if preparing {
			return r.validate(p, row, in, true)
		}
		return r.validate(p, row, in)
	})
}
