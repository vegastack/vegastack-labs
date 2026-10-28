package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"slices"
	"time"
)

type IngressRepository struct {
	store   *Store
	allowed []string
}

func NewIngressRepository(s *Store, allowed []string) *IngressRepository {
	return &IngressRepository{s, slices.Clone(allowed)}
}
func ingressError(code string) error { return newStoreError(code, "network-ingress", false, nil) }
func ingressGrant(ctx context.Context, row discoveryRow, profile, action string) (identity.Principal, error) {
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok || !identity.ValidPrincipal(p) || p.DeviceID == "" {
		return p, ingressError(generated.ErrorCodeAuthenticationRequired)
	}
	var n int
	err := row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision JOIN operator_devices d ON d.principal_id=p.principal_id AND d.device_id=? AND d.status='approved' WHERE p.principal_id=? AND p.status='active' AND g.status='active' AND g.action=? AND g.capability=? AND g.resource_kind='ingress-profile' AND g.resource_id=? AND g.role_id IN ('infrastructure-admin','control-plane-admin')`, p.DeviceID, p.ID, action, "network.ingress."+map[string]string{"author": "prepare", "read": "read"}[action], profile).Scan(&n)
	if err != nil || n == 0 {
		return p, ingressError(generated.ErrorCodeAuthorizationDenied)
	}
	return p, nil
}
func ingressOwner(row discoveryRow, c generated.IngressChange) error {
	var n int
	if row(`SELECT COUNT(*) FROM operator_devices d JOIN effective_authorization_principals p ON p.principal_id=d.principal_id WHERE d.device_id=? AND d.principal_id=? AND d.status='approved' AND p.status='active'`, c.DeviceID, c.OwnerID).Scan(&n) != nil || n != 1 {
		return ingressError(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}
func ingressOwnership(row discoveryRow, c generated.IngressChange, epoch int64) error {
	if ingress.IsBootstrap(c) {
		return bootstrapDependencies(row, c, epoch)
	}
	var rev int64
	var scope string
	var oldEpoch int64
	err := row(`SELECT revision,scope_digest,recovery_epoch FROM ingress_ownership WHERE profile_id=? ORDER BY revision DESC LIMIT 1`, c.ProfileID).Scan(&rev, &scope, &oldEpoch)
	if errors.Is(err, sql.ErrNoRows) && c.Action == "import" && c.ExpectedOwnershipRevision == 0 {
		var n int
		if row(`SELECT COUNT(*) FROM ingress_ownership WHERE resource_key=?`, ingress.ResourceKey(c)).Scan(&n) != nil || n != 0 {
			return ingressError(generated.ErrorCodeStateConflict)
		}
		return nil
	}
	if err != nil || oldEpoch != epoch || rev != c.ExpectedOwnershipRevision || scope != ingress.OwnershipDigest(c) || c.Action == "import" {
		return ingressError(generated.ErrorCodeStateConflict)
	}
	return nil
}
func (r *IngressRepository) Stage(ctx context.Context, q generated.IngressDraftRequest, a audit.Attribution) (ingress.Staged, error) {
	var out ingress.Staged
	raw, _ := json.Marshal(q)
	if generated.ValidateContractJSON(generated.SchemaIDIngressDraftRequest, raw, generated.ContractExact) != nil || ingress.Validate(q.Change) != nil || !slices.Contains(r.allowed, ingress.ScopeDigest(q.Change)) {
		return out, ingressError(generated.ErrorCodeInputInvalid)
	}
	if ingress.IsBootstrap(q.Change) {
		if e := r.CheckBootstrapUnattempted(ctx, q.Change, q.RecoveryEpoch); e != nil {
			return out, e
		}
	}
	d := ingress.Digest(q)
	out = ingress.Staged{ID: "ingress-" + d[7:39], Digest: d, Request: q}
	refs := NewCredentialRepository(r.store)
	ids := []string{q.Change.ObservationReferenceID}
	if q.Change.Action != "import" {
		ids = append(ids, q.Change.MutationReferenceID)
	}
	if q.Change.Action == "token-rotate" {
		ids = append(ids, q.Change.ReplacementReferenceID)
	}
	for i, id := range ids {
		ref, e := refs.GetActiveVersion(ctx, id, q.RecoveryEpoch)
		purpose := ingress.PurposeRead
		if i == 1 {
			purpose = ingress.PurposeWrite
		}
		if i == 2 {
			purpose = ingress.PurposeReplacement
		}
		if e != nil || ref.ConsumerID != ingress.AdapterID || ref.PurposeID != purpose || ref.TargetID != q.Change.ProfileID || ref.Status != "active" || ref.StateRevision > q.ExpectedStateRevision || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, ingress.AdapterID) {
			return out, ingressError(generated.ErrorCodePrerequisiteBlocked)
		}
		out.Bindings = append(out.Bindings, credentialref.StepBinding{OperationID: ingress.OperationID, AdapterID: ingress.AdapterID, TargetID: q.Change.ProfileID, ReferenceID: ref.ReferenceID, ConsumerID: ingress.AdapterID, PurposeID: purpose, MaterialVersion: ref.MaterialVersion, ResolverID: ref.ResolverID, StateRevision: q.ExpectedStateRevision + 3, RecoveryEpoch: q.RecoveryEpoch})
	}
	intent := discoveryIntent(a, "ingress.draft-staged", out.ID, ingress.Digest(q.IdempotencyKey), d)
	intent.Expected = &RevisionToken{StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch}
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(s string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, s, a...) }
		p, e := ingressGrant(ctx, row, q.Change.ProfileID, "author")
		if e != nil {
			return e
		}
		if p.ID != a.AuthenticatedPrincipalID {
			return ingressError(generated.ErrorCodeAuthorizationDenied)
		}
		if e = ingressOwner(row, q.Change); e != nil {
			return e
		}
		if e = ingressOwnership(row, q.Change, q.RecoveryEpoch); e != nil {
			return e
		}
		out.ActorID = p.ID
		out.ActorMethod = p.Method
		out.ActorDevice = p.DeviceID
		bindings, _ := json.Marshal(out.Bindings)
		_, e = tx.ExecContext(ctx, `INSERT INTO ingress_drafts VALUES(?,?,?,?,?,?,?,?)`, out.ID, d, raw, bindings, p.ID, p.Method, p.DeviceID, q.RecoveryEpoch)
		return e
	})
	return out, err
}
func ingressDraft(row discoveryRow, id string) (out ingress.Staged, err error) {
	var raw, bindings []byte
	err = row(`SELECT draft_id,digest,request_bytes,bindings_bytes,actor_id,actor_method,actor_device FROM ingress_drafts WHERE draft_id=?`, id).Scan(&out.ID, &out.Digest, &raw, &bindings, &out.ActorID, &out.ActorMethod, &out.ActorDevice)
	if err != nil {
		return
	}
	if json.Unmarshal(raw, &out.Request) != nil || json.Unmarshal(bindings, &out.Bindings) != nil || ingress.Digest(out.Request) != out.Digest || ingress.Validate(out.Request.Change) != nil {
		err = ingressError(generated.ErrorCodeIntegrityFailure)
	}
	return
}
func (r *IngressRepository) Resolve(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (out ingress.Staged, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		var raw, leaseRaw []byte
		if row(`SELECT p.canonical_bytes,l.canonical_bytes FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN target_execution_leases l ON l.run_id=r.run_id JOIN plan_run_steps s ON s.step_id=l.step_id AND s.run_id=r.run_id WHERE r.run_id=? AND l.lease_id=? AND s.step_id=? AND r.status='running' AND r.cancellation_requested=0 AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch AND s.status='running' AND s.effect_state IN ('intent-recorded','receipt-recorded') AND s.active_lease_id=l.lease_id AND l.status='active'`, b.RunID, b.LeaseID, b.StepID).Scan(&raw, &leaseRaw) != nil {
			return ingressError(generated.ErrorCodeApprovalRequired)
		}
		var p generated.Plan
		var l generated.ExecutorLease
		if json.Unmarshal(raw, &p) != nil || json.Unmarshal(leaseRaw, &l) != nil || p.PlanID != b.PlanID || p.PlanDigest != b.PlanDigest || p.Binding.StateRevision != b.StateRevision || p.Binding.RecoveryEpoch != b.RecoveryEpoch || p.ExecutorMode != "central" || p.AuthorizationBranch != "human" || len(p.Operations) != 1 || l.Status != "active" || l.LeaseID != b.LeaseID || l.RecoveryEpoch != b.RecoveryEpoch || l.OperationID != op.OperationID || l.TargetID != op.TargetID || l.PlanID != b.PlanID || l.PlanDigest != b.PlanDigest || l.RunID != b.RunID || l.StepID != b.StepID || l.ArtifactDigest != op.ArtifactDigest {
			return ingressError(generated.ErrorCodePlanStale)
		}
		deadline, e := time.Parse(time.RFC3339, l.MaximumExpiresAt)
		if e != nil || !r.store.config.Clock().Before(deadline) {
			return ingressError(generated.ErrorCodePlanStale)
		}
		po := p.Operations[0]
		if po.AdapterID != ingress.AdapterID || po.OperationID != op.OperationID || po.TargetID != op.TargetID || po.InputDigest != op.InputDigest || po.ArtifactDigest != op.ArtifactDigest {
			return ingressError(generated.ErrorCodeIntegrityFailure)
		}
		var payload string
		for _, x := range p.Extensions {
			if x.Name == ingress.Extension {
				payload = x.ValueDigest
			}
		}
		if payload == "" || payload != op.ArtifactDigest {
			return ingressError(generated.ErrorCodeIntegrityFailure)
		}
		out, e = ingressDraft(row, "ingress-"+payload[7:39])
		if e != nil {
			return e
		}
		q := out.Request
		c := q.Change
		if op.OperationType != "network.ingress."+c.Action || op.TargetID != c.ProfileID || op.InputDigest != credentialref.OperationManifestDigest(out.Bindings, op.OperationID) || !slices.Contains(r.allowed, ingress.ScopeDigest(c)) {
			return ingressError(generated.ErrorCodeIntegrityFailure)
		}
		actor := identity.Principal{ID: out.ActorID, Method: out.ActorMethod, DeviceID: out.ActorDevice}
		if _, e = ingressGrant(identity.WithVerifiedPrincipal(ctx, actor), row, c.ProfileID, "author"); e != nil {
			return e
		}
		if e = ingressOwner(row, c); e != nil {
			return e
		}
		if e = ingressOwnership(row, c, q.RecoveryEpoch); e != nil {
			return e
		}
		var epoch int64
		if row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&epoch) != nil || epoch != b.RecoveryEpoch {
			return ingressError(generated.ErrorCodeRecoveryEpochMismatch)
		}
		return nil
	})
	if err == nil {
		stored, e := NewPlanRepository(r.store).GetPlan(ctx, b.PlanID)
		if e != nil {
			return out, e
		}
		ordered, e := NewCredentialRepository(r.store).GetStepBindings(ctx, stored.Plan, op.OperationID)
		if e != nil {
			return out, e
		}
		out.Bindings = ordered
	}
	return
}
func (r *IngressRepository) Record(ctx context.Context, d ingress.Staged, b adapter.ExactExecutionBinding, s ingress.Snapshot, status string) error {
	a, e := r.store.HostAccessRunAttribution(ctx, b.RunID)
	if e != nil {
		return e
	}
	key := ingress.Digest([]string{b.RunID, b.StepID, status, s.Digest})
	in := discoveryIntent(a, "ingress.effect-observed", "ingress-result-"+key[7:39], key, ingress.Digest(s))
	_, e = r.store.executeAuditIntent(ctx, in, false, func(ctx context.Context, tx *sql.Tx) error {
		if d.Request.Change.Action == "token-rotate" && status == "partial" {
			version := ""
			for _, ref := range d.Bindings {
				if ref.PurposeID == ingress.PurposeReplacement {
					version = ref.MaterialVersion
				}
			}
			if version == "" {
				return ingressError(generated.ErrorCodeIntegrityFailure)
			}
			old, _ := json.Marshal(s.Connections)
			acknowledged := s.Reason == "connector-update-required"
			if _, e := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ingress_rotation_runs VALUES(?,?,?,?,?,?,?)`, b.RunID, d.Request.Change.ProfileID, d.ID, version, old, acknowledged, b.RecoveryEpoch); e != nil {
				return e
			}
		}
		if ingress.IsBootstrap(d.Request.Change) {
			return recordBootstrapReceipt(ctx, tx, d, b, s, status)
		}
		if status == "observed" {
			row := func(q string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, q, args...) }
			actor := identity.Principal{ID: d.ActorID, Method: d.ActorMethod, DeviceID: d.ActorDevice}
			if _, e := ingressGrant(identity.WithVerifiedPrincipal(ctx, actor), row, d.Request.Change.ProfileID, "author"); e != nil {
				return e
			}
			if e := ingressOwner(row, d.Request.Change); e != nil {
				return e
			}
			if e := ingressOwnership(row, d.Request.Change, b.RecoveryEpoch); e != nil {
				return e
			}
			var state, epoch int64
			if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch) != nil || state != b.StateRevision || epoch != b.RecoveryEpoch {
				return ingressError(generated.ErrorCodePlanStale)
			}
			var exact int
			if row(`SELECT COUNT(*) FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND s.step_id=? AND s.artifact_digest=? AND s.effect_state='receipt-recorded' AND l.lease_id=? AND l.status='active' AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=?`, b.RunID, b.PlanID, b.PlanDigest, b.StepID, d.Digest, b.LeaseID, b.RecoveryEpoch).Scan(&exact) != nil || exact != 1 {
				return ingressError(generated.ErrorCodeApprovalRequired)
			}
			_, e := tx.ExecContext(ctx, `INSERT INTO ingress_ownership VALUES(?,?,?,?,?,?,?)`, d.Request.Change.ProfileID, d.Request.Change.ExpectedOwnershipRevision+1, ingress.OwnershipDigest(d.Request.Change), ingress.ResourceKey(d.Request.Change), d.ID, b.RunID, b.RecoveryEpoch)
			if e != nil {
				return e
			}
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO ingress_observations VALUES(?,?,?,?,?,?,?,?,?)`, "ingress-result-"+key[7:39], d.Request.Change.ProfileID, d.ID, b.RunID, status, s.Reason, s.Digest, r.store.config.Clock().UTC().Format(time.RFC3339), b.RecoveryEpoch)
		return e
	})
	return e
}
func (r *IngressRepository) Status(ctx context.Context, id string) (out generated.IngressStatusData, err error) {
	out = generated.IngressStatusData{Schema: generated.SchemaIDIngressStatusData, SchemaVersion: "1.0.0", ProfileID: id, RotationStage: "not-requested", Connectivity: "unknown", OriginIsolation: "unknown", Status: "unknown", Reason: "no-provider-observation", ObservationDigest: ingress.Digest(nil)}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		if _, e := ingressGrant(ctx, row, id, "read"); e != nil {
			return e
		}
		if e := row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&out.StateRevision, &out.RecoveryEpoch); e != nil {
			return e
		}
		var rev sql.NullInt64
		if e := row(`SELECT MAX(revision) FROM ingress_ownership WHERE profile_id=? AND recovery_epoch=?`, id, out.RecoveryEpoch).Scan(&rev); e != nil {
			return e
		}
		out.OwnershipRevision = rev.Int64

		// Compare authoritative source revisions, not unrelated table row IDs or
		// clocks. A historical ordinary observation cannot overwrite a newer setup
		// receipt; a later ordinary plan may still become the current observation.
		bootstrap := out
		var bootstrapKind, bootstrapStatus, bootstrapResult string
		var bootstrapRevision, observationRevision int64
		bootstrapErr := row(`SELECT b.action,b.resource_id,b.run_id,b.status,b.result_digest,json_extract(d.request_bytes,'$.expectedStateRevision') FROM ingress_bootstrap_receipts b JOIN ingress_drafts d ON d.draft_id=b.draft_id WHERE b.profile_id=? AND b.recovery_epoch=? ORDER BY b.rowid DESC LIMIT 1`, id, out.RecoveryEpoch).Scan(&bootstrapKind, &bootstrap.ResourceID, &bootstrap.RunID, &bootstrapStatus, &bootstrapResult, &bootstrapRevision)
		if bootstrapErr == nil {
			bootstrap.ResourceKind = ingress.BootstrapKind(bootstrapKind)
			bootstrap.Status = "partial"
			bootstrap.Reason = "bootstrap-" + bootstrapStatus
			if bootstrapStatus == "observed" {
				bootstrap.Status = "observed"
			}
			if bootstrapResult != "" {
				bootstrap.ObservationDigest = bootstrapResult
			}
			out.ResourceKind, out.ResourceID, out.RunID = bootstrap.ResourceKind, bootstrap.ResourceID, bootstrap.RunID
		} else if !errors.Is(bootstrapErr, sql.ErrNoRows) {
			return bootstrapErr
		}
		e := row(`SELECT o.status,o.reason,o.observation_digest,o.observed_at,json_extract(d.request_bytes,'$.expectedStateRevision') FROM ingress_observations o JOIN ingress_drafts d ON d.draft_id=o.draft_id WHERE o.profile_id=? AND o.recovery_epoch=? ORDER BY o.rowid DESC LIMIT 1`, id, out.RecoveryEpoch).Scan(&out.Status, &out.Reason, &out.ObservationDigest, &out.ObservedAt, &observationRevision)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if bootstrapErr == nil && (errors.Is(e, sql.ErrNoRows) || bootstrapRevision >= observationRevision) {
			out = bootstrap
			return nil
		}
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		out.ResourceKind, out.ResourceID, out.RunID = "", "", ""
		rotationReason := out.Reason
		if e == nil {
			at, pe := time.Parse(time.RFC3339, out.ObservedAt)
			if pe != nil || r.store.config.Clock().Sub(at) > 5*time.Minute {
				out.Status = "unknown"
				out.Reason = "stale-provider-observation"
			}
		}
		if e == nil {
			switch rotationReason {
			case "connector-update-required":
				out.RotationStage = "connector-update-required"
			case "provider-effect-uncertain":
				out.RotationStage = "uncertain"
			case "provider-verification-incomplete", "provider-verification-pending":
				out.RotationStage = "verification-pending"
			}
		}
		return e
	})
	return
}

func (r *IngressRepository) GetStaged(ctx context.Context, id string) (out ingress.Staged, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var e error
		out, e = ingressDraft(func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }, id)
		return e
	})
	return
}
func (r *IngressRepository) CheckCurrent(ctx context.Context, d ingress.Staged) error {
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		q := d.Request
		c := q.Change
		if !slices.Contains(r.allowed, ingress.ScopeDigest(c)) {
			return ingressError(generated.ErrorCodeAuthorizationDenied)
		}
		actor := identity.Principal{ID: d.ActorID, Method: d.ActorMethod, DeviceID: d.ActorDevice}
		if _, e := ingressGrant(identity.WithVerifiedPrincipal(ctx, actor), row, c.ProfileID, "author"); e != nil {
			return e
		}
		if e := ingressOwner(row, c); e != nil {
			return e
		}
		return ingressOwnership(row, c, q.RecoveryEpoch)
	})
}

// Preview checks a read-only observation scope without writing desired state or ownership.
func (r *IngressRepository) Preview(ctx context.Context, q generated.IngressDraftRequest) (out ingress.Staged, err error) {
	return r.preview(ctx, q, true)
}

// PreviewPilotEvidence checks current authority and credential custody without
// requiring an ownership import which the evidence must precede.
func (r *IngressRepository) PreviewPilotEvidence(ctx context.Context, q generated.IngressDraftRequest) (ingress.Staged, error) {
	return r.preview(ctx, q, false)
}
func (r *IngressRepository) preview(ctx context.Context, q generated.IngressDraftRequest, ownership bool) (out ingress.Staged, err error) {
	if ingress.Validate(q.Change) != nil || !slices.Contains(r.allowed, ingress.ScopeDigest(q.Change)) {
		return out, ingressError(generated.ErrorCodeAuthorizationDenied)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		p, e := ingressGrant(ctx, row, q.Change.ProfileID, "read")
		if e != nil {
			return e
		}
		if e = ingressOwner(row, q.Change); e != nil {
			return e
		}
		if ownership {
			if e = ingressOwnership(row, q.Change, q.RecoveryEpoch); e != nil {
				return e
			}
		}
		var revision, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&revision, &epoch) != nil || epoch != q.RecoveryEpoch || revision != q.ExpectedStateRevision {
			return ingressError(generated.ErrorCodeStateConflict)
		}
		out = ingress.Staged{ID: "ingress-" + ingress.Digest(q)[7:39], Digest: ingress.Digest(q), Request: q, ActorID: p.ID, ActorMethod: p.Method, ActorDevice: p.DeviceID}
		return nil
	})
	if err != nil {
		return
	}
	ref, e := NewCredentialRepository(r.store).GetActiveVersion(ctx, q.Change.ObservationReferenceID, q.RecoveryEpoch)
	if e != nil || ref.ConsumerID != ingress.AdapterID || ref.TargetID != q.Change.ProfileID || ref.PurposeID != ingress.PurposeRead || ref.Status != "active" || ref.StateRevision > q.ExpectedStateRevision || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, ingress.AdapterID) {
		return out, ingressError(generated.ErrorCodePrerequisiteBlocked)
	}
	out.Bindings = []credentialref.StepBinding{{OperationID: "ingress-observe", AdapterID: ingress.AdapterID, TargetID: q.Change.ProfileID, ReferenceID: ref.ReferenceID, ConsumerID: ingress.AdapterID, PurposeID: ingress.PurposeRead, MaterialVersion: ref.MaterialVersion, ResolverID: ref.ResolverID, StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch}}
	return
}

func (r *IngressRepository) Rotation(ctx context.Context, q generated.IngressRolloutEvidenceRequest) (d ingress.Staged, state ingress.RotationState, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		if _, e := ingressGrant(ctx, row, q.ProfileID, "read"); e != nil {
			return e
		}
		var draft, version string
		var raw []byte
		var acknowledged bool
		var epoch int64
		if e := row(`SELECT draft_id,material_version,old_connections_bytes,provider_acknowledged,recovery_epoch FROM ingress_rotation_runs WHERE run_id=? AND profile_id=?`, q.RotationRunID, q.ProfileID).Scan(&draft, &version, &raw, &acknowledged, &epoch); e != nil {
			return ingressError(generated.ErrorCodeAuthorizationDenied)
		}
		if version != q.MaterialVersion || epoch != q.RecoveryEpoch {
			return ingressError(generated.ErrorCodeStateConflict)
		}
		var e error
		d, e = ingressDraft(row, draft)
		if e != nil {
			return e
		}
		if ingress.Digest(q.Connectors) != ingress.Digest(d.Request.Change.Connectors) {
			return ingressError(generated.ErrorCodeAuthorizationDenied)
		}
		if json.Unmarshal(raw, &state.OldConnections) != nil {
			return ingressError(generated.ErrorCodeIntegrityFailure)
		}
		state.ProviderAcknowledged = acknowledged
		state.MaterialVersion = version
		for _, x := range d.Request.Change.Connectors {
			state.DeclaredConnectorIDs = append(state.DeclaredConnectorIDs, x.ConnectorID)
		}
		return nil
	})
	return
}

// RecordRollout retains only the independently observed sanitized result. It cannot advance ownership or mark rotation complete.
func (r *IngressRepository) RecordRollout(ctx context.Context, q generated.IngressRolloutEvidenceRequest, result generated.IngressStatusData) error {
	a, e := hostdiscovery.Attribution(ctx, "ingress-rollout-"+ingress.Digest(q)[7:39])
	if e != nil {
		return e
	}
	in := discoveryIntent(a, "ingress.rollout-observed", q.ProfileID, ingress.Digest(q.IdempotencyKey), ingress.Digest(q))
	_, e = r.store.executeAuditIntent(ctx, in, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(s string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, s, a...) }
		if _, e := ingressGrant(ctx, row, q.ProfileID, "read"); e != nil {
			return e
		}
		var revision, epoch int64
		if e := row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&revision, &epoch); e != nil {
			return e
		}
		if revision != q.ExpectedStateRevision || epoch != q.RecoveryEpoch || result.ProfileID != q.ProfileID || result.Status != "partial" {
			return ingressError(generated.ErrorCodeStateConflict)
		}
		var n int
		if e := row(`SELECT COUNT(*) FROM ingress_rotation_runs WHERE run_id=? AND profile_id=? AND material_version=? AND recovery_epoch=?`, q.RotationRunID, q.ProfileID, q.MaterialVersion, q.RecoveryEpoch).Scan(&n); e != nil || n != 1 {
			return ingressError(generated.ErrorCodeStateConflict)
		}
		var prior string
		e := row(`SELECT request_digest FROM ingress_rollout_observations WHERE request_id=?`, q.IdempotencyKey).Scan(&prior)
		if e == nil {
			if prior != ingress.Digest(q) {
				return ingressError(generated.ErrorCodeStateConflict)
			}
			return nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO ingress_rollout_observations VALUES(?,?,?,?,?,?,?,?,?)`, q.IdempotencyKey, ingress.Digest(q), q.RotationRunID, q.ProfileID, result.RotationStage, result.Reason, result.ObservationDigest, result.ObservedAt, q.RecoveryEpoch)
		return e
	})
	return e
}
