package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostinglifecycle"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type HostingLifecycleRepository struct{ store *Store }

func NewHostingLifecycleRepository(s *Store) *HostingLifecycleRepository {
	return &HostingLifecycleRepository{s}
}
func hostingLifecycleDeclarationID(in generated.HostingLifecycleRequest) string {
	return "hosting-" + hostinglifecycle.Digest(in)[7:39]
}
func normalizeHostingLifecycleProfiles(c *Config) error {
	seen := map[string]bool{}
	if len(c.HostingLifecycleProfiles) > 128 {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	for _, p := range c.HostingLifecycleProfiles {
		b, _ := json.Marshal(p.Binding)
		if seen[p.Binding.TargetID] || generated.ValidateContractJSON(generated.SchemaIDHostingLifecycleProfile, b, generated.ContractExact) != nil {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		seen[p.Binding.TargetID] = true
	}
	c.HostingLifecycleProfiles = append([]hostinglifecycle.Profile(nil), c.HostingLifecycleProfiles...)
	return nil
}
func (r *HostingLifecycleRepository) policy(id string) (hostinglifecycle.Profile, error) {
	if r != nil && r.store != nil {
		for _, p := range r.store.config.HostingLifecycleProfiles {
			if p.Binding.TargetID == id {
				return p, nil
			}
		}
	}
	return hostinglifecycle.Profile{}, actionError(generated.ErrorCodePrerequisiteBlocked)
}
func hostingLifecycleRevision(row discoveryRow, id string) (int64, error) {
	var n int64
	e := row(`SELECT COALESCE(MAX(revision),0) FROM hosting_lifecycle_records WHERE target_id=?`, id).Scan(&n)
	return n, e
}
func (r *HostingLifecycleRepository) validate(p identity.Principal, row discoveryRow, in generated.HostingLifecycleRequest) error {
	if hostinglifecycle.ValidateRequest(in) != nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	if e := authorizeDeviceRow(row, p); e != nil {
		return e
	}
	policy, e := r.policy(in.TargetID)
	if e != nil {
		return e
	}
	if policy.Binding.BindingID != in.BindingID || policy.Binding.ConfigurationDigest != in.ConfigurationDigest {
		return actionError(generated.ErrorCodePlanStale)
	}
	if _, e = adoptionPrincipalGrant(p, row, in.TargetID, "hosting", "author", "hosting.lifecycle.prepare", true); e != nil {
		return e
	}
	rev, e := hostingLifecycleRevision(row, in.TargetID)
	if e != nil {
		return e
	}
	if rev != in.ExpectedLifecycleRevision {
		return actionError(generated.ErrorCodePlanStale)
	}
	return nil
}
func (r *HostingLifecycleRepository) Prepare(ctx context.Context, in generated.HostingLifecycleDraftRequest) (out generated.HostingLifecycleRequest, err error) {
	raw, _ := json.Marshal(in)
	if generated.ValidateContractJSON(generated.SchemaIDHostingLifecycleDraftRequest, raw, generated.ContractExact) != nil {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	actor, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	p, err := r.policy(in.TargetID)
	if err != nil {
		return out, err
	}
	out = generated.HostingLifecycleRequest{Schema: generated.SchemaIDHostingLifecycleRequest, SchemaVersion: "1.0.0", TargetID: in.TargetID, BindingID: p.Binding.BindingID, ConfigurationDigest: p.Binding.ConfigurationDigest, ObservedDigest: hostinglifecycle.Digest("unobserved"), Action: in.Action, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, IdempotencyKey: in.IdempotencyKey, ReasonDigest: in.ReasonDigest}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != in.ExpectedStateRevision || epoch != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		var e error
		out.ExpectedLifecycleRevision, e = hostingLifecycleRevision(row, in.TargetID)
		if e != nil {
			return e
		}
		return r.validate(actor, row, out)
	})
	return
}
func (r *HostingLifecycleRepository) Stage(ctx context.Context, in generated.HostingLifecycleRequest) (out generated.DeclarationRevisionRequest, err error) {
	actor, err := serviceActor(ctx)
	if err != nil {
		return out, err
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
	digest := hostinglifecycle.Digest(in)
	return generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", HostingLifecycle: &in, DeclarationID: hostingLifecycleDeclarationID(in), DeclarationType: "hosting.lifecycle", ExpectedRevision: 1, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, ReasonDigest: in.ReasonDigest, Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: hostinglifecycle.OperationID, OperationType: hostinglifecycle.Operation, AdapterID: hostinglifecycle.AdapterID, TargetID: in.TargetID, InputDigest: digest, ArtifactDigest: digest, Idempotent: false}}}, nil
}
func ValidateHostingLifecycleDeclaration(d generated.DeclarationRevision) bool {
	present := d.HostingLifecycle != nil || d.DeclarationType == "hosting.lifecycle"
	for _, op := range d.Operations {
		present = present || op.AdapterID == hostinglifecycle.AdapterID
	}
	if !present {
		return true
	}
	in := d.HostingLifecycle
	if in == nil || d.ServiceRecovery != nil || d.ServiceDeployment != nil || d.ServiceImport != nil || d.NetworkEndpoint != nil || d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil || hostinglifecycle.ValidateRequest(*in) != nil || d.DeclarationType != "hosting.lifecycle" || d.DeclarationID != hostingLifecycleDeclarationID(*in) || len(d.Operations) != 1 || len(d.Extensions) != 0 || d.RecoveryEpoch != in.RecoveryEpoch {
		return false
	}
	if d.Status == "draft" && (d.StateRevision != in.ExpectedStateRevision+1 || d.Revision != 1) {
		return false
	}
	op := d.Operations[0]
	return op.Sequence == 1 && op.OperationID == hostinglifecycle.OperationID && op.OperationType == hostinglifecycle.Operation && op.AdapterID == hostinglifecycle.AdapterID && op.TargetID == in.TargetID && op.InputDigest == hostinglifecycle.Digest(in) && op.ArtifactDigest == op.InputDigest && !op.Idempotent && op.OffsiteRunSpec == nil
}
func (r *HostingLifecycleRepository) Get(ctx context.Context, id string) (out generated.HostingLifecycleRecord, err error) {
	actor, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if _, e := adoptionPrincipalGrant(actor, row, id, "hosting", "read", "hosting.read", true); e != nil {
			return e
		}
		var pending int
		if row(`SELECT COUNT(*) FROM hosting_lifecycle_attempts WHERE target_id=? AND status='attempted'`, id).Scan(&pending) != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if pending != 0 {
			return actionError(generated.ErrorCodeRecoveryRequired)
		}
		var raw []byte
		var digest string
		e := row(`SELECT canonical_bytes,digest FROM hosting_lifecycle_records WHERE target_id=? ORDER BY revision DESC LIMIT 1`, id).Scan(&raw, &digest)
		if errors.Is(e, sql.ErrNoRows) {
			return actionError(generated.ErrorCodeResourceNotFound)
		}
		if e != nil {
			return e
		}
		if json.Unmarshal(raw, &out) != nil || hostinglifecycle.Digest(out) != digest || generated.ValidateContractJSON(generated.SchemaIDHostingLifecycleRecord, raw, generated.ContractExact) != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		return nil
	})
	return
}

// Authorize repeats the current resource, actor, device, epoch and execution
// grant checks at each protected adapter boundary. It never substitutes for
// the exact plan, consumed acknowledgement and active lease required by Begin.
func (r *HostingLifecycleRepository) Authorize(ctx context.Context, in generated.HostingLifecycleRequest) error {
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
		p := generated.Plan{Risk: "control-plane", AuthorizationBranch: "human", ExecutorMode: "central", Binding: generated.PlanBinding{StateRevision: state, RecoveryEpoch: epoch}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: hostinglifecycle.OperationID, OperationType: hostinglifecycle.Operation, AdapterID: hostinglifecycle.AdapterID, TargetID: in.TargetID}}}
		if err := authorizeBaselinePrincipal(ctx, row, p, actor.ID, in.TargetID, authorization.ActionExecute, hostinglifecycle.Operation, "execution-target"); err != nil {
			return err
		}
		// During provider execution also repeat the exact active run/lease and
		// consumed human acknowledgement. Draft preparation has no attempt.
		var count int
		if row(`SELECT COUNT(*) FROM hosting_lifecycle_attempts WHERE request_digest=? AND status='attempted'`, hostinglifecycle.Digest(in)).Scan(&count) != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if count == 0 {
			return nil
		}
		var canonical []byte
		var readable, human string
		var name, session sql.NullString
		apply := HostingLifecycleApply{}
		if row(`SELECT p.canonical_bytes,p.readable_plan,r.run_id,s.step_id,s.active_lease_id,a.human_id,e.agent_name,e.agent_session_id FROM hosting_lifecycle_attempts d JOIN immutable_plans p ON p.plan_id=d.plan_id JOIN plan_runs r ON r.run_id=d.run_id JOIN plan_run_steps s ON s.run_id=r.run_id AND s.step_id=d.step_id JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN audit_events e ON e.correlation_id=r.run_id AND e.event_type='run.created' WHERE d.request_digest=? AND d.status='attempted' AND e.principal_id=? AND e.principal_method=?`, hostinglifecycle.Digest(in), actor.ID, actor.Method).Scan(&canonical, &readable, &apply.RunID, &apply.StepID, &apply.LeaseID, &human, &name, &session) != nil || !decodeStoredPlan(canonical, readable, &p) {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		apply.PlanID = p.PlanID
		apply.PlanDigest = p.PlanDigest
		apply.Attribution = audit.Attribution{AuthenticatedPrincipalID: actor.ID, AuthenticatedPrincipalMethod: actor.Method, ResponsibleHumanPrincipalID: &human}
		if name.Valid && session.Valid {
			apply.Attribution.Agent = &audit.AgentMetadata{Name: name.String, SessionID: session.String}
		}
		return r.validateHostingLifecycleExecution(ctx, row, p, in, apply, r.store.config.Clock().UTC())
	})
}

// OwnedResources is an internal current-authority read for the active executor.
// Operator Get remains blocked while an uncertain attempt is outstanding.
func (r *HostingLifecycleRepository) OwnedResources(ctx context.Context, in generated.HostingLifecycleRequest) (out []generated.HostingOwnedResource, err error) {
	if err = r.Authorize(ctx, in); err != nil {
		return nil, err
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var raw []byte
		var digest string
		e := tx.queryRow(ctx, `SELECT canonical_bytes,digest FROM hosting_lifecycle_records WHERE target_id=? ORDER BY revision DESC LIMIT 1`, in.TargetID).Scan(&raw, &digest)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		var record generated.HostingLifecycleRecord
		if json.Unmarshal(raw, &record) != nil || hostinglifecycle.Digest(record) != digest || record.Request.ConfigurationDigest != in.ConfigurationDigest || record.Status != "succeeded" {
			return actionError(generated.ErrorCodeRecoveryRequired)
		}
		out = append([]generated.HostingOwnedResource(nil), record.OwnedResources...)
		return nil
	})
	return
}

func (r *HostingLifecycleRepository) CheckTarget(ctx context.Context, in generated.HostingLifecycleRequest, hostID, identityDigest string) error {
	if e := r.Authorize(ctx, in); e != nil {
		return e
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var target, digest string
		var epoch int64
		if row(`SELECT target_id,identity_digest,recovery_epoch FROM managed_hosts WHERE host_id=?`, hostID).Scan(&target, &digest, &epoch) != nil || digest != identityDigest || epoch != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		if e := requireHostUnfrozen(row, hostID); e != nil {
			return e
		}
		for _, id := range r.store.config.NetworkConnectExcludedHostIDs {
			const hosts = `SELECT h.host_id FROM managed_hosts h WHERE h.host_id=?1 OR h.target_id=?1 OR h.host_id IN (SELECT owner_host_id FROM host_alias_owners WHERE alias_id=?1) OR h.identity_digest IN (SELECT owner_identity_digest FROM host_alias_owners WHERE alias_id=?1) OR h.host_id IN (SELECT owner_host_id FROM host_alias_history WHERE alias_id=?1) OR h.identity_digest IN (SELECT owner_identity_digest FROM host_alias_history WHERE alias_id=?1)`
			var n int
			if row(`SELECT COUNT(*) FROM managed_hosts h WHERE h.host_id IN (`+hosts+`) AND (h.host_id=?2 OR h.identity_digest=?3 OR h.target_id=?4)`, id, hostID, identityDigest, target).Scan(&n) != nil || n != 0 {
				return actionError(generated.ErrorCodeAuthorizationDenied)
			}
		}
		return nil
	})
}
