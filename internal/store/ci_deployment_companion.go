package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type CICompanionCommit struct {
	ParentPlanID string
	Plan         generated.Plan
	Readable     string
	Attribution  audit.Attribution
}

func planExtension(p generated.Plan, name string) string {
	for _, x := range p.Extensions {
		if x.Name == name {
			return x.ValueDigest
		}
	}
	return ""
}

// CommitCICompanion writes only an inert immutable companion at the parent's
// exact current declaration/state. It never advances state or approves either
// plan. The controller cannot start without this exact companion.
func (r *PlanRepository) CommitCICompanion(ctx context.Context, q CICompanionCommit) (out PlanCommitResult, err error) {
	if r == nil || r.store == nil || q.ParentPlanID == "" || !validPlanDigests(q.Plan, q.Readable) || q.Plan.ExecutorMode != "external" || q.Plan.AuthorizationBranch != "human" || q.Plan.Risk != "production-like" || q.Plan.CIJob != nil || len(q.Plan.Operations) != 1 {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	raw, e := json.Marshal(q.Plan)
	if e != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, raw, generated.ContractExact) != nil {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	expected := RevisionToken{StateRevision: q.Plan.Binding.StateRevision, RecoveryEpoch: q.Plan.Binding.RecoveryEpoch}
	result, e := r.store.executeAuditIntent(ctx, intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "ci-companion-plan", KeyDigest: audit.Fingerprint(hostaction.Digest(q.ParentPlanID)), RequestDigest: audit.Fingerprint(q.Plan.PlanDigest)}, Event: audit.EventDraft{Type: "ci.deployment.plan-created", CorrelationID: q.ParentPlanID, Attribution: q.Attribution, Target: audit.Target{Kind: "plan", ID: q.Plan.PlanID}}}, false, func(ctx context.Context, tx *sql.Tx) error {
		var parentRaw []byte
		var readable string
		var parent generated.Plan
		if tx.QueryRowContext(ctx, `SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=?`, q.ParentPlanID).Scan(&parentRaw, &readable) != nil || !decodeStoredPlan(parentRaw, readable, &parent) || parent.CIJob == nil || parent.CIJob.DeploymentDigest == "" {
			return actionError(generated.ErrorCodePlanStale)
		}
		p := q.Plan
		parentBinding := parent.Binding
		parentBinding.TargetDigest = hostaction.Digest([]string{p.Operations[0].TargetID})
		if parentBinding != p.Binding || parent.DeclarationID != p.DeclarationID || parent.ExpiresAt != p.ExpiresAt || parent.CreatedAt != p.CreatedAt || parent.CIJob.DeploymentDigest != planExtension(p, "x-external-deployment") || parent.PlanDigest != planExtension(p, "x-ci-controller-plan") || planExtension(parent, "x-credential-bindings") != planExtension(p, "x-credential-bindings") {
			return actionError(generated.ErrorCodePlanStale)
		}
		policy, e := NewCIJobRepository(r.store).ExternalDeploymentPolicy(parent.CIJob.ExecutionBindingID)
		if e != nil || policy.Digest() != parent.CIJob.DeploymentDigest {
			return actionError(generated.ErrorCodePlanStale)
		}
		actor, e := serviceActor(ctx)
		if e != nil {
			return e
		}
		row := func(q string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, q, args...) }
		if e = NewServiceRepository(r.store).authorize(actor, row, policy.Definition, "author", "service.deploy.prepare"); e != nil {
			return e
		}
		b := policy.Credential(p.Binding.StateRevision, p.Binding.RecoveryEpoch)
		op := p.Operations[0]
		if p.ExecutorID == nil || *p.ExecutorID != policy.Binding.ExecutorID || op.ExecutorID != *p.ExecutorID || op.OperationID != CIExternalDeploymentOperationID || op.OperationType != CIExternalDeploymentOperation || op.AdapterID != CIExternalDeploymentAdapter || op.TargetID != policy.Definition.ServiceID || op.ArtifactDigest != policy.Artifact.Digest || op.InputDigest != credentialref.OperationManifestDigest([]credentialref.StepBinding{b}, op.OperationID) || planExtension(p, "x-external-deployment-credentials") != credentialref.ManifestDigest([]credentialref.StepBinding{b}) {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.PlanID, p.PlanDigest, p.DeclarationID, p.Binding.DeclarationRevision, p.Binding.StateRevision, p.Binding.RecoveryEpoch, p.Binding.ObservationFingerprint, hostaction.Digest([]string{"ci-companion", parent.PlanID}), p.PlanDigest, raw, q.Readable, p.ReadableDigest, p.CreatedAt, p.ExpiresAt)
		return e
	})
	if e != nil {
		return out, e
	}
	if !result.Created {
		return r.CICompanion(ctx, q.ParentPlanID)
	}
	return PlanCommitResult{Plan: q.Plan, Canonical: raw, Readable: q.Readable, Created: true, Commit: result.Commit}, nil
}
func (r *PlanRepository) CICompanion(ctx context.Context, parentID string) (out PlanCommitResult, err error) {
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var parentRaw []byte
		var parentReadable string
		var parent generated.Plan
		if tx.queryRow(ctx, `SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=?`, parentID).Scan(&parentRaw, &parentReadable) != nil || !decodeStoredPlan(parentRaw, parentReadable, &parent) || parent.CIJob == nil {
			return actionError(generated.ErrorCodePlanStale)
		}
		var canonical []byte
		var readable string
		if tx.queryRow(ctx, `SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE idempotency_key_digest=?`, hostaction.Digest([]string{"ci-companion", parentID})).Scan(&canonical, &readable) != nil || !decodeStoredPlan(canonical, readable, &out.Plan) || planExtension(out.Plan, "x-ci-controller-plan") != parent.PlanDigest {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		out.Canonical = canonical
		out.Readable = readable
		return nil
	})
	return
}

func (r *PlanRepository) ExternalDeploymentPolicy(id string) (CIExternalDeploymentPolicy, error) {
	return NewCIJobRepository(r.store).ExternalDeploymentPolicy(id)
}

// ValidateManagedDeploymentPlan authorizes reservation only; it cannot deliver
// a credential, claim a lease, or admit a job.
func (r *PlanRepository) ValidateManagedDeploymentPlan(ctx context.Context, p generated.Plan) error {
	if r == nil || r.store == nil || p.ExecutorMode != "external" || p.AuthorizationBranch != "human" || len(p.Operations) != 1 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	actor, e := serviceActor(ctx)
	if e != nil {
		return e
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var raw []byte
		var readable string
		var parent generated.Plan
		if row(`SELECT p.canonical_bytes,p.readable_plan FROM immutable_plans p WHERE p.plan_digest=?`, planExtension(p, "x-ci-controller-plan")).Scan(&raw, &readable) != nil || !decodeStoredPlan(raw, readable, &parent) || parent.CIJob == nil {
			return actionError(generated.ErrorCodePlanStale)
		}
		var actual generated.Plan
		if row(`SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=? AND idempotency_key_digest=?`, p.PlanID, hostaction.Digest([]string{"ci-companion", parent.PlanID})).Scan(&raw, &readable) != nil || !decodeStoredPlan(raw, readable, &actual) || actual.PlanDigest != p.PlanDigest {
			return actionError(generated.ErrorCodePlanStale)
		}
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != p.Binding.StateRevision || epoch != p.Binding.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		policy, e := NewCIJobRepository(r.store).ExternalDeploymentPolicy(parent.CIJob.ExecutionBindingID)
		if e != nil || policy.Binding.BindingID == "" || policy.Digest() != parent.CIJob.DeploymentDigest || planExtension(p, "x-external-deployment") != policy.Digest() {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		b := policy.Credential(state, epoch)
		op := p.Operations[0]
		if p.ExecutorID == nil || *p.ExecutorID != policy.Binding.ExecutorID || op.AdapterID != CIExternalDeploymentAdapter || op.OperationType != CIExternalDeploymentOperation || op.TargetID != policy.Definition.ServiceID || op.InputDigest != credentialref.OperationManifestDigest([]credentialref.StepBinding{b}, op.OperationID) || planExtension(p, "x-external-deployment-credentials") != credentialref.ManifestDigest([]credentialref.StepBinding{b}) || planExtension(p, "x-credential-bindings") != planExtension(parent, "x-credential-bindings") {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		return NewServiceRepository(r.store).authorize(actor, row, policy.Definition, "author", "service.deploy.prepare")
	})
}
