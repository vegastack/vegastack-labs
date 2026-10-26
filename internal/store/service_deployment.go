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
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
)

type DeploymentRepository struct{ store *Store }

func NewDeploymentRepository(s *Store) *DeploymentRepository { return &DeploymentRepository{s} }
func deploymentDeclarationID(in generated.ServiceDeploymentRequest) string {
	return "service-deploy-" + servicecatalog.Digest(in)[7:39]
}
func normalizeDeploymentPolicies(c *Config) error {
	if len(c.ServiceDeploymentPolicies) > 128 {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	seen := map[string]bool{}
	out := append([]servicecatalog.DeploymentPolicy(nil), c.ServiceDeploymentPolicies...)
	for i, p := range out {
		raw, _ := json.Marshal(p.Binding)
		if seen[p.Binding.ServiceID] || generated.ValidateContractJSON(generated.SchemaIDServiceDeploymentBinding, raw, generated.ContractExact) != nil || len(p.Artifacts) == 0 || len(p.Artifacts) > 128 {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		seen[p.Binding.ServiceID] = true
		ids := map[string]bool{}
		for _, a := range p.Artifacts {
			raw, _ = json.Marshal(a)
			if ids[a.ArtifactID] || a.Digest != a.ManifestSHA || generated.ValidateContractJSON(generated.SchemaIDServiceDeploymentArtifact, raw, generated.ContractExact) != nil {
				return actionError(generated.ErrorCodeInputInvalid)
			}
			ids[a.ArtifactID] = true
		}
		out[i].Artifacts = append([]generated.ServiceDeploymentArtifact(nil), p.Artifacts...)
	}
	c.ServiceDeploymentPolicies = out
	return nil
}
func (r *DeploymentRepository) policy(id string) (servicecatalog.DeploymentPolicy, error) {
	if r == nil || r.store == nil {
		return servicecatalog.DeploymentPolicy{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	for _, p := range r.store.config.ServiceDeploymentPolicies {
		if p.Binding.ServiceID == id {
			return p, nil
		}
	}
	return servicecatalog.DeploymentPolicy{}, actionError(generated.ErrorCodePrerequisiteBlocked)
}
func deploymentRevision(row discoveryRow, id string) (int64, error) {
	var n int64
	err := row(`SELECT COALESCE(MAX(revision),0) FROM service_deployments WHERE service_id=?`, id).Scan(&n)
	return n, err
}
func (r *DeploymentRepository) validate(p identity.Principal, row discoveryRow, in generated.ServiceDeploymentRequest) error {
	if servicecatalog.ValidateDeploymentRequest(in) != nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	policy, err := r.policy(in.Definition.ServiceID)
	if err != nil {
		return err
	}
	if policy.Binding != in.Binding {
		return actionError(generated.ErrorCodePlanStale)
	}
	found := false
	for _, a := range policy.Artifacts {
		found = found || a == in.Artifact
	}
	if !found {
		return actionError(generated.ErrorCodePlanStale)
	}
	current, err := readService(row, in.Definition.ServiceID)
	if err != nil {
		return err
	}
	if current.Definition != in.Definition {
		return actionError(generated.ErrorCodePlanStale)
	}
	if err := NewServiceRepository(r.store).authorize(p, row, in.Definition, "author", "service.deploy.prepare"); err != nil {
		return err
	}
	revision, err := deploymentRevision(row, in.Definition.ServiceID)
	if err != nil {
		return err
	}
	if revision != in.ExpectedDeploymentRevision {
		return actionError(generated.ErrorCodePlanStale)
	}
	if in.Binding.DataPolicy != "stateless" && in.Binding.DataPolicy != "compatible" {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	if in.Action == "rollback" {
		if in.Binding.DataPolicy != "stateless" && in.Binding.DataPolicy != "compatible" {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		var count int
		if row(`SELECT COUNT(*) FROM service_deployments WHERE service_id=? AND status='succeeded' AND artifact_digest=? AND recovery_epoch=?`, in.Definition.ServiceID, in.Artifact.Digest, in.RecoveryEpoch).Scan(&count) != nil || count == 0 {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	return nil
}
func (r *DeploymentRepository) Prepare(ctx context.Context, in generated.ServiceDeploymentDraftRequest) (out generated.ServiceDeploymentRequest, err error) {
	raw, _ := json.Marshal(in)
	if generated.ValidateContractJSON(generated.SchemaIDServiceDeploymentDraftRequest, raw, generated.ContractExact) != nil {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	actor, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	policy, err := r.policy(in.ServiceID)
	if err != nil {
		return out, err
	}
	out = generated.ServiceDeploymentRequest{Schema: generated.SchemaIDServiceDeploymentRequest, SchemaVersion: "1.0.0", Binding: policy.Binding, Action: in.Action, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, IdempotencyKey: in.IdempotencyKey, ReasonDigest: in.ReasonDigest}
	for _, a := range policy.Artifacts {
		if a.ArtifactID == in.ArtifactID {
			out.Artifact = a
		}
	}
	out.ArtifactProofDigest = servicecatalog.Digest(out.Artifact)
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != in.ExpectedStateRevision || epoch != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		record, e := readService(row, in.ServiceID)
		if e != nil {
			return e
		}
		out.Definition = record.Definition
		out.ExpectedDeploymentRevision, e = deploymentRevision(row, in.ServiceID)
		if e != nil {
			return e
		}
		return r.validate(actor, row, out)
	})
	// Only the server's offline artifact verifier can seal the proof.
	out.ArtifactProofDigest = ""
	return
}
func (r *DeploymentRepository) Stage(ctx context.Context, in generated.ServiceDeploymentRequest) (out generated.DeclarationRevisionRequest, err error) {
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
	digest := servicecatalog.Digest(in)
	return generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", ServiceDeployment: &in, DeclarationID: deploymentDeclarationID(in), DeclarationType: "service.deployment", ExpectedRevision: 1, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, ReasonDigest: in.ReasonDigest, Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: servicecatalog.DeploymentOperationID, OperationType: servicecatalog.DeploymentOperation, AdapterID: servicecatalog.DeploymentAdapterID, TargetID: in.Definition.ServiceID, InputDigest: digest, ArtifactDigest: digest, Idempotent: false}}}, nil
}
func ValidateServiceDeploymentDeclaration(d generated.DeclarationRevision) bool {
	present := d.ServiceDeployment != nil || d.DeclarationType == "service.deployment"
	for _, op := range d.Operations {
		present = present || op.AdapterID == servicecatalog.DeploymentAdapterID
	}
	if !present {
		return true
	}
	in := d.ServiceDeployment
	if in == nil || servicecatalog.ValidateDeploymentRequest(*in) != nil || d.ServiceImport != nil || d.NetworkEndpoint != nil || d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil || d.DeclarationType != "service.deployment" || d.DeclarationID != deploymentDeclarationID(*in) || len(d.Operations) != 1 || len(d.Extensions) != 0 || d.RecoveryEpoch != in.RecoveryEpoch {
		return false
	}
	if d.Status == "draft" && (d.StateRevision != in.ExpectedStateRevision+1 || d.Revision != 1) {
		return false
	}
	op := d.Operations[0]
	return op.Sequence == 1 && op.OperationID == servicecatalog.DeploymentOperationID && op.OperationType == servicecatalog.DeploymentOperation && op.AdapterID == servicecatalog.DeploymentAdapterID && op.TargetID == in.Definition.ServiceID && op.InputDigest == servicecatalog.Digest(in) && op.ArtifactDigest == op.InputDigest && !op.Idempotent && op.OffsiteRunSpec == nil
}
func (r *DeploymentRepository) Get(ctx context.Context, id string) (out generated.ServiceDeploymentRecord, err error) {
	if _, err = NewServiceRepository(r.store).Get(ctx, id); err != nil {
		return out, err
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var pending int
		if tx.queryRow(ctx, `SELECT COUNT(*) FROM service_deployment_attempts WHERE service_id=? AND status='attempted'`, id).Scan(&pending) != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if pending != 0 {
			return actionError(generated.ErrorCodeRecoveryRequired)
		}
		var raw []byte
		var digest string
		err := tx.queryRow(ctx, `SELECT canonical_bytes,digest FROM service_deployments WHERE service_id=? ORDER BY revision DESC LIMIT 1`, id).Scan(&raw, &digest)
		if errors.Is(err, sql.ErrNoRows) {
			return actionError(generated.ErrorCodeResourceNotFound)
		}
		if err != nil {
			return err
		}
		if json.Unmarshal(raw, &out) != nil || servicecatalog.Digest(out) != digest || generated.ValidateContractJSON(generated.SchemaIDServiceDeploymentRecord, raw, generated.ContractExact) != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		return nil
	})
	return
}

// Authorize repeats the current resource, actor, device, epoch and execution
// grant checks at each protected adapter boundary. It never substitutes for
// the exact plan, consumed acknowledgement and active lease required by Begin.
func (r *DeploymentRepository) Authorize(ctx context.Context, in generated.ServiceDeploymentRequest) error {
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
		p := generated.Plan{Risk: "production-like", AuthorizationBranch: "human", ExecutorMode: "central", Binding: generated.PlanBinding{StateRevision: state, RecoveryEpoch: epoch}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: servicecatalog.DeploymentOperationID, OperationType: servicecatalog.DeploymentOperation, AdapterID: servicecatalog.DeploymentAdapterID, TargetID: in.Definition.ServiceID}}}
		if err := authorizeBaselinePrincipal(ctx, row, p, actor.ID, in.Definition.ServiceID, authorization.ActionExecute, servicecatalog.DeploymentOperation, "execution-target"); err != nil {
			return err
		}
		// During provider execution also repeat the exact active run/lease and
		// consumed human acknowledgement. Draft preparation has no attempt.
		var count int
		if row(`SELECT COUNT(*) FROM service_deployment_attempts WHERE request_digest=? AND status='attempted'`, servicecatalog.Digest(in)).Scan(&count) != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if count == 0 {
			return nil
		}
		var canonical []byte
		var readable, human string
		var name, session sql.NullString
		apply := ServiceDeploymentApply{}
		if row(`SELECT p.canonical_bytes,p.readable_plan,r.run_id,s.step_id,s.active_lease_id,a.human_id,e.agent_name,e.agent_session_id FROM service_deployment_attempts d JOIN immutable_plans p ON p.plan_id=d.plan_id JOIN plan_runs r ON r.run_id=d.run_id JOIN plan_run_steps s ON s.run_id=r.run_id AND s.step_id=d.step_id JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN audit_events e ON e.correlation_id=r.run_id AND e.event_type='run.created' WHERE d.request_digest=? AND d.status='attempted' AND e.principal_id=? AND e.principal_method=?`, servicecatalog.Digest(in), actor.ID, actor.Method).Scan(&canonical, &readable, &apply.RunID, &apply.StepID, &apply.LeaseID, &human, &name, &session) != nil || !decodeStoredPlan(canonical, readable, &p) {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		apply.PlanID = p.PlanID
		apply.PlanDigest = p.PlanDigest
		apply.Attribution = audit.Attribution{AuthenticatedPrincipalID: actor.ID, AuthenticatedPrincipalMethod: actor.Method, ResponsibleHumanPrincipalID: &human}
		if name.Valid && session.Valid {
			apply.Attribution.Agent = &audit.AgentMetadata{Name: name.String, SessionID: session.String}
		}
		return r.validateDeploymentExecution(ctx, row, p, in, apply, r.store.config.Clock().UTC())
	})
}
