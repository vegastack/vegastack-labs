package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"slices"
	"strings"
	"time"
)

const ManualPublicationOperation = "artifact.publish.manual"
const ManualPublicationAdapter = "oci-registry-manual"
const ManualPublicationPurpose = "artifact.publish.manual"
const ManualPublicationExtension = "x-manual-publication"

type ManualPublicationRepository struct{ store *Store }

func NewManualPublicationRepository(s *Store) *ManualPublicationRepository {
	return &ManualPublicationRepository{s}
}
func (r *ManualPublicationRepository) binding(id string) (generated.ManualPublicationBinding, error) {
	if r != nil && r.store != nil {
		for _, b := range r.store.config.ManualPublicationBindings {
			if b.BindingID == id {
				return b, nil
			}
		}
	}
	return generated.ManualPublicationBinding{}, actionError(generated.ErrorCodePrerequisiteBlocked)
}
func (r *ManualPublicationRepository) authorize(actor identity.Principal, row discoveryRow, b generated.ManualPublicationBinding, epoch int64) error {
	if _, e := adoptionPrincipalGrant(actor, row, b.BindingID, "manual-publication", "author", "artifact.publication.prepare", true); e != nil {
		return e
	}
	var n int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN read_principals r ON r.principal_id=p.principal_id WHERE p.principal_id=? AND p.status='active' AND r.status='active'`, actor.ID).Scan(&n) != nil || n != 1 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	if e := authorizeDeviceRow(row, actor); e != nil {
		return e
	}
	var currentEpoch int64
	if row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentEpoch) != nil || currentEpoch != epoch {
		return actionError(generated.ErrorCodePlanStale)
	}
	return nil
}
func ManualPublicationBindings(b generated.ManualPublicationBinding, state, epoch int64) []credentialref.StepBinding {
	return []credentialref.StepBinding{{OperationID: "manual-publication", AdapterID: ManualPublicationAdapter, TargetID: b.BindingID, ReferenceID: b.ReferenceID, ConsumerID: ManualPublicationAdapter, PurposeID: ManualPublicationPurpose, MaterialVersion: b.MaterialVersion, ResolverID: "native-systemd", StateRevision: state, RecoveryEpoch: epoch}}
}
func ManualPublicationDigest(b generated.ManualPublicationBinding) string {
	return hostaction.Digest(b)
}
func IsManualPublication(p generated.Plan) bool {
	return len(p.Operations) == 1 && p.Operations[0].OperationType == ManualPublicationOperation
}
func ValidManualPublicationDeclaration(d generated.DeclarationRevision) bool {
	candidate := d.DeclarationType == ManualPublicationOperation
	for _, o := range d.Operations {
		candidate = candidate || o.OperationType == ManualPublicationOperation || o.AdapterID == ManualPublicationAdapter
	}
	if !candidate {
		return true
	}
	if d.DeclarationType != ManualPublicationOperation || len(d.Operations) != 1 || len(d.Extensions) != 2 || d.CIJob != nil || d.CIEnrollment != nil || d.ServiceDeployment != nil || d.HostingLifecycle != nil || d.ServiceRecovery != nil || d.ServiceImport != nil || d.NetworkEndpoint != nil || d.AuthorizationGrantBatch != nil {
		return false
	}
	o := d.Operations[0]
	if o.Sequence != 1 || o.OffsiteRunSpec != nil || o.OperationID != "manual-publication" || o.AdapterID != ManualPublicationAdapter || o.OperationType != ManualPublicationOperation || o.Idempotent {
		return false
	}
	seen := map[string]bool{}
	for _, x := range d.Extensions {
		if seen[x.Name] {
			return false
		}
		seen[x.Name] = true
		if x.Name == ManualPublicationExtension {
			if x.ValueDigest != o.ArtifactDigest {
				return false
			}
		} else if x.Name == "x-credential-bindings" {
			if x.ValueDigest != o.InputDigest {
				return false
			}
		} else {
			return false
		}
	}
	return true
}
func (r *ManualPublicationRepository) Draft(ctx context.Context, in generated.ManualPublicationDraftRequest) (out generated.DeclarationRevisionRequest, bindings []credentialref.StepBinding, err error) {
	raw, _ := json.Marshal(in)
	if generated.ValidateContractJSON(generated.SchemaIDManualPublicationDraftRequest, raw, generated.ContractExact) != nil {
		return out, nil, actionError(generated.ErrorCodeInputInvalid)
	}
	b, e := r.binding(in.BindingID)
	if e != nil {
		return out, nil, e
	}
	actor, e := serviceActor(ctx)
	if e != nil {
		return out, nil, e
	}
	e = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		var state, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != in.ExpectedStateRevision || epoch != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		var e error
		e = r.authorize(actor, row, b, epoch)
		return e
	})
	if e != nil {
		return out, nil, e
	}
	bindings = ManualPublicationBindings(b, in.ExpectedStateRevision+3, in.RecoveryEpoch)
	digest := ManualPublicationDigest(b)
	manifest := credentialref.ManifestDigest(bindings)
	out = generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: "manual-publication-" + hostaction.Digest([]string{digest, in.IdempotencyKey})[7:39], DeclarationType: ManualPublicationOperation, ExpectedRevision: 1, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, ReasonDigest: in.ReasonDigest, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "manual-publication", OperationType: ManualPublicationOperation, AdapterID: ManualPublicationAdapter, TargetID: b.BindingID, InputDigest: manifest, ArtifactDigest: digest, Idempotent: false}}, Extensions: []generated.ContractExtension{{Name: ManualPublicationExtension, ValueDigest: digest}, {Name: "x-credential-bindings", ValueDigest: manifest}}}
	return out, bindings, nil
}
func (r *ManualPublicationRepository) validate(actor identity.Principal, row discoveryRow, d generated.DeclarationRevision) error {
	if !ValidManualPublicationDeclaration(d) || d.DeclarationType != ManualPublicationOperation {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	b, e := r.binding(d.Operations[0].TargetID)
	if e != nil {
		return e
	}
	if e := r.authorize(actor, row, b, d.RecoveryEpoch); e != nil {
		return e
	}
	if d.Operations[0].ArtifactDigest != ManualPublicationDigest(b) {
		return actionError(generated.ErrorCodePlanStale)
	}
	return nil
}

type ManualPublicationExecution struct {
	Binding generated.ManualPublicationBinding
	Plan    generated.Plan
}

func (r *ManualPublicationRepository) current(ctx context.Context, row discoveryRow, actor identity.Principal, op adapter.Operation, b adapter.ExactExecutionBinding) (out ManualPublicationExecution, err error) {
	deny := func() (ManualPublicationExecution, error) {
		return ManualPublicationExecution{}, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	var raw []byte
	var readable string
	if row(`SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, b.PlanID, b.PlanDigest).Scan(&raw, &readable) != nil || !decodeStoredPlan(raw, readable, &out.Plan) {
		return deny()
	}
	p := out.Plan
	if !IsManualPublication(p) || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Binding.StateRevision != b.StateRevision || p.Binding.RecoveryEpoch != b.RecoveryEpoch {
		return deny()
	}
	po := p.Operations[0]
	if po.OperationID != op.OperationID || po.OperationType != op.OperationType || po.AdapterID != op.AdapterID || po.TargetID != op.TargetID || po.InputDigest != op.InputDigest || po.ArtifactDigest != op.ArtifactDigest || po.ExecutorID != op.ExecutorID || po.Idempotent || op.Idempotent {
		return deny()
	}
	var state, epoch int64
	if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != b.StateRevision || epoch != b.RecoveryEpoch {
		return ManualPublicationExecution{}, actionError(generated.ErrorCodePlanStale)
	}
	var human string
	now := r.store.config.Clock().UTC().Format(time.RFC3339)
	if row(`SELECT a.human_id FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND r.recovery_epoch=? AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch AND s.step_id=? AND s.operation_id=? AND s.operation_type=? AND s.adapter_id=? AND s.target_id=? AND s.input_digest=? AND s.artifact_digest=? AND s.status='running' AND s.effect_state='intent-recorded' AND l.lease_id=? AND l.run_id=r.run_id AND l.step_id=s.step_id AND l.target_id=s.target_id AND l.recovery_epoch=r.recovery_epoch AND l.status='active' AND l.expires_at>? AND l.maximum_expires_at>?`, b.RunID, b.PlanID, b.PlanDigest, b.RecoveryEpoch, b.StepID, op.OperationID, op.OperationType, op.AdapterID, op.TargetID, op.InputDigest, op.ArtifactDigest, b.LeaseID, now, now).Scan(&human) != nil {
		return deny()
	}
	expires, e := time.Parse(time.RFC3339, p.ExpiresAt)
	if e != nil || !r.store.config.Clock().Before(expires) {
		return deny()
	}
	var reason string
	var d generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, p.Binding.DeclarationRevision).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &d) || !ValidManualPublicationDeclaration(d) {
		return deny()
	}
	if e = r.validate(actor, row, d); e != nil {
		return out, e
	}
	if e = authorizeBaselinePrincipal(ctx, row, p, actor.ID, op.TargetID, authorization.ActionExecute, ManualPublicationOperation, "execution-target"); e != nil {
		return out, e
	}
	if e = authorizeBaselinePrincipal(ctx, row, p, human, op.TargetID, authorization.ActionAcknowledge, "plan.acknowledge", "plan-target"); e != nil {
		return out, e
	}
	out.Binding, e = r.binding(op.TargetID)
	if e != nil {
		return out, e
	}
	if ManualPublicationDigest(out.Binding) != op.ArtifactDigest {
		return deny()
	}
	var count int
	if row(`SELECT COUNT(*) FROM credential_reference_versions v WHERE version_id=(SELECT v2.version_id FROM credential_reference_versions v2 WHERE v2.reference_id=v.reference_id AND v2.material_version=v.material_version AND v2.recovery_epoch=v.recovery_epoch ORDER BY v2.state_revision DESC,v2.version_id DESC LIMIT 1) AND reference_id=? AND consumer_id=? AND purpose_id=? AND target_id=? AND resolver_id='native-systemd' AND material_version=? AND status='active' AND activated_at IS NOT NULL AND recovery_epoch=? AND state_revision<=? AND EXISTS(SELECT 1 FROM json_each(verified_consumers_bytes) WHERE value=?)`, out.Binding.ReferenceID, ManualPublicationAdapter, ManualPublicationPurpose, op.TargetID, out.Binding.MaterialVersion, b.RecoveryEpoch, b.StateRevision, ManualPublicationAdapter).Scan(&count) != nil || count != 1 {
		return deny()
	}
	return out, nil
}
func (r *ManualPublicationRepository) Current(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (out ManualPublicationExecution, err error) {
	if r == nil || r.store == nil || adapter.ValidateOperation(op) != nil || op.OperationType != ManualPublicationOperation || op.AdapterID != ManualPublicationAdapter {
		return out, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	bound, e := NewCIJobRepository(r.store).executionContext(ctx, b.RunID)
	if e != nil {
		return out, e
	}
	actor, _ := identity.PrincipalFromContext(bound)
	err = r.store.Read(bound, func(tx ReadTx) error {
		var e error
		out, e = r.current(bound, func(q string, a ...any) *sql.Row { return tx.queryRow(bound, q, a...) }, actor, op, b)
		return e
	})
	if err != nil {
		return ManualPublicationExecution{}, err
	}
	active, e := NewCredentialRepository(r.store).GetActiveVersion(bound, out.Binding.ReferenceID, b.RecoveryEpoch)
	if e != nil || active.Status != "active" || active.ConsumerID != ManualPublicationAdapter || active.PurposeID != ManualPublicationPurpose || active.TargetID != op.TargetID || active.MaterialVersion != out.Binding.MaterialVersion || active.ResolverID != "native-systemd" || active.ActivatedAt == nil || active.StateRevision > b.StateRevision || !slices.Contains(active.VerifiedConsumerIDs, ManualPublicationAdapter) {
		return ManualPublicationExecution{}, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	refs, e := NewCredentialRepository(r.store).GetStepBindings(bound, out.Plan, op.OperationID)
	expected := ManualPublicationBindings(out.Binding, b.StateRevision, b.RecoveryEpoch)
	if e != nil || len(refs) != 1 || refs[0] != expected[0] || credentialref.OperationManifestDigest(refs, op.OperationID) != op.InputDigest {
		return ManualPublicationExecution{}, actionError(generated.ErrorCodePlanStale)
	}
	return out, nil
}

// Journal writes before network effects and never advances global desired state.
// A repeated attempted intent is denied even after a lost/uncertain response.
func (r *ManualPublicationRepository) Journal(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, stage, digest string) error {
	if strings.HasPrefix(stage, "uncertain-") {
		return r.recordUncertain(ctx, op, b, stage, digest)
	}
	if stage != "attempted" && stage != "received" && stage != "uncertain" {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	if !audit.ValidFingerprint(audit.Fingerprint(digest)) {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	bound, e := NewCIJobRepository(r.store).executionContext(ctx, b.RunID)
	if e != nil {
		return e
	}
	actor, _ := identity.PrincipalFromContext(bound)
	a, e := NewCIJobRepository(r.store).attribution(bound, b.RunID)
	if e != nil {
		return e
	}
	expected := RevisionToken{b.StateRevision, b.RecoveryEpoch}
	result, e := r.store.executeAuditIntent(bound, intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "manual-publication-" + stage, KeyDigest: manualPublicationIntentKey(b, stage), RequestDigest: audit.Fingerprint(hostaction.Digest([]string{op.ArtifactDigest, digest}))}, Event: audit.EventDraft{Type: audit.EventType("artifact.publication." + stage), CorrelationID: b.RunID, Attribution: a, Target: audit.Target{Kind: "manual-publication", ID: op.TargetID}, After: (*audit.Fingerprint)(&digest)}}, false, func(ctx context.Context, tx *sql.Tx) error {
		_, e := r.current(ctx, func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }, actor, op, b)
		return e
	})
	if e == nil && stage == "attempted" && !result.Created {
		return actionError(generated.ErrorCodeStateConflict)
	}
	return e
}

func (r *ManualPublicationRepository) Snapshot(ctx context.Context, id string, epoch int64) (out ManualPublicationExecution, err error) {
	out.Binding, err = r.binding(id)
	if err != nil {
		return out, err
	}
	actor, e := serviceActor(ctx)
	if e != nil {
		return out, e
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var e error
		e = r.authorize(actor, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, out.Binding, epoch)
		return e
	})
	return out, err
}

// CheckPlan locates only the exact running publication step; its durable actor
// is restored by Current and no request identity is invented for the engine.
func (r *ManualPublicationRepository) CheckPlan(ctx context.Context, p generated.Plan) error {
	_, _, e := r.ActivePlan(ctx, p)
	return e
}
func (r *ManualPublicationRepository) ActivePlan(ctx context.Context, p generated.Plan) (ManualPublicationExecution, adapter.ExactExecutionBinding, error) {
	if !IsManualPublication(p) || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" {
		return ManualPublicationExecution{}, adapter.ExactExecutionBinding{}, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	op := p.Operations[0]
	var b adapter.ExactExecutionBinding
	var count int
	e := r.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT COALESCE(MIN(r.run_id),''),COALESCE(MIN(s.step_id),''),COALESCE(MIN(l.lease_id),''),COUNT(*) FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id AND l.run_id=r.run_id AND l.step_id=s.step_id WHERE r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND s.operation_id=? AND s.status='running' AND s.effect_state='intent-recorded' AND l.status='active'`, p.PlanID, p.PlanDigest, op.OperationID).Scan(&b.RunID, &b.StepID, &b.LeaseID, &count)
	})
	if e != nil || count != 1 {
		return ManualPublicationExecution{}, adapter.ExactExecutionBinding{}, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	b.PlanID = p.PlanID
	b.PlanDigest = p.PlanDigest
	b.StateRevision = p.Binding.StateRevision
	b.RecoveryEpoch = p.Binding.RecoveryEpoch
	out, e := r.Current(ctx, adapter.Operation{OperationID: op.OperationID, OperationType: op.OperationType, AdapterID: op.AdapterID, ExecutorID: op.ExecutorID, TargetID: op.TargetID, InputDigest: op.InputDigest, ArtifactDigest: op.ArtifactDigest, Idempotent: op.Idempotent}, b)
	return out, b, e
}

// A bounded uncertain outcome is a fact about an already journaled attempt,
// never a new effect authorization. Retain it even if its lease/grant was
// revoked while the registry response was in flight; it cannot permit a retry.
func (r *ManualPublicationRepository) recordUncertain(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, stage, digest string) error {
	switch stage {
	case "uncertain-unstarted", "uncertain-validated", "uncertain-blob-upload-start-attempted", "uncertain-blob-upload-attempted", "uncertain-manifest-put-attempted", "uncertain-manifest-put-acknowledged", "uncertain-manifest-verified":
	default:
		return actionError(generated.ErrorCodeInputInvalid)
	}
	if r == nil || r.store == nil || adapter.ValidateOperation(op) != nil || op.OperationType != ManualPublicationOperation || op.AdapterID != ManualPublicationAdapter || !audit.ValidFingerprint(audit.Fingerprint(digest)) {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	var attribution audit.Attribution
	var human, agent, session sql.NullString
	query := func(row discoveryRow) error {
		var raw []byte
		var readable string
		var plan generated.Plan
		if row(`SELECT canonical_bytes,readable_plan FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, b.PlanID, b.PlanDigest).Scan(&raw, &readable) != nil || !decodeStoredPlan(raw, readable, &plan) || !IsManualPublication(plan) || plan.Binding.StateRevision != b.StateRevision || plan.Binding.RecoveryEpoch != b.RecoveryEpoch {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		p := plan.Operations[0]
		if p.OperationID != op.OperationID || p.OperationType != op.OperationType || p.AdapterID != op.AdapterID || p.TargetID != op.TargetID || p.InputDigest != op.InputDigest || p.ArtifactDigest != op.ArtifactDigest {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if row(`SELECT a.principal_id,a.principal_method,a.responsible_human_principal_id,a.agent_name,a.agent_session_id FROM audit_events a JOIN plan_runs r ON r.run_id=a.correlation_id JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.run_id=r.run_id AND l.step_id=s.step_id WHERE a.event_type='artifact.publication.attempted' AND a.target_id=? AND a.after_fingerprint=? AND r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND s.step_id=? AND s.operation_id=? AND s.artifact_digest=? AND l.lease_id=?`, op.TargetID, op.ArtifactDigest, b.RunID, b.PlanID, b.PlanDigest, b.StepID, op.OperationID, op.ArtifactDigest, b.LeaseID).Scan(&attribution.AuthenticatedPrincipalID, &attribution.AuthenticatedPrincipalMethod, &human, &agent, &session) != nil {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if human.Valid {
			attribution.ResponsibleHumanPrincipalID = &human.String
		}
		if agent.Valid && session.Valid {
			attribution.Agent = &audit.AgentMetadata{Name: agent.String, SessionID: session.String}
		}
		return nil
	}
	if e := r.store.Read(ctx, func(tx ReadTx) error {
		return query(func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) })
	}); e != nil {
		return e
	}
	_, e := r.store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: "manual-publication-outcome", KeyDigest: digestParts("manual-publication-outcome", b.PlanID, b.RunID, b.StepID, b.LeaseID), RequestDigest: audit.Fingerprint(hostaction.Digest([]string{stage, digest}))}, Event: audit.EventDraft{Type: audit.EventType("artifact.publication." + stage), CorrelationID: b.RunID, Attribution: attribution, Target: audit.Target{Kind: "manual-publication", ID: op.TargetID}, After: (*audit.Fingerprint)(&digest)}}, false, func(ctx context.Context, tx *sql.Tx) error {
		return query(func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) })
	})
	return e
}

func manualPublicationIntentKey(b adapter.ExactExecutionBinding, stage string) audit.Fingerprint {
	if stage == "attempted" {
		return digestParts("manual-publication-attempt", b.PlanID)
	}
	return digestParts("manual-publication", b.PlanID, b.RunID, b.StepID, b.LeaseID, stage)
}
