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
	"github.com/vegastack/vegastack-labs/internal/identity"
	mesh "github.com/vegastack/vegastack-labs/internal/networkmesh"
	"slices"
	"time"
)

type MeshRepository struct {
	store   *Store
	allowed []string
}

func NewMeshRepository(s *Store, allowed []string) *MeshRepository {
	return &MeshRepository{s, slices.Clone(allowed)}
}
func meshError(code string) error { return newStoreError(code, "network-mesh", false, nil) }
func meshGrant(ctx context.Context, row discoveryRow, profile, action string) (identity.Principal, error) {
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok || !identity.ValidPrincipal(p) || p.DeviceID == "" {
		return p, meshError(generated.ErrorCodeAuthenticationRequired)
	}
	var n int
	err := row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision JOIN operator_devices d ON d.principal_id=p.principal_id AND d.device_id=? AND d.status='approved' WHERE p.principal_id=? AND p.status='active' AND g.status='active' AND g.action=? AND g.capability=? AND g.resource_kind='mesh-profile' AND g.resource_id=? AND g.role_id IN ('infrastructure-admin','control-plane-admin')`, p.DeviceID, p.ID, action, "network.mesh."+map[string]string{"author": "prepare", "read": "read"}[action], profile).Scan(&n)
	if err != nil || n == 0 {
		return p, meshError(generated.ErrorCodeAuthorizationDenied)
	}
	return p, nil
}
func meshOwner(row discoveryRow, c generated.MeshChange) error {
	var n int
	if row(`SELECT COUNT(*) FROM operator_devices d JOIN effective_authorization_principals p ON p.principal_id=d.principal_id WHERE d.device_id=? AND d.principal_id=? AND d.status='approved' AND p.status='active'`, c.DeviceID, c.OwnerID).Scan(&n) != nil || n != 1 {
		return meshError(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}
func meshOwnership(row discoveryRow, c generated.MeshChange, epoch int64) error {
	var rev int64
	var scope string
	var oldEpoch int64
	err := row(`SELECT revision,scope_digest,recovery_epoch FROM mesh_ownership WHERE profile_id=? ORDER BY revision DESC LIMIT 1`, c.ProfileID).Scan(&rev, &scope, &oldEpoch)
	if errors.Is(err, sql.ErrNoRows) && c.Action == "import" && c.ExpectedOwnershipRevision == 0 {
		return nil
	}
	if err != nil || oldEpoch != epoch || rev != c.ExpectedOwnershipRevision || scope != mesh.ScopeDigest(c) || c.Action == "import" {
		return meshError(generated.ErrorCodeStateConflict)
	}
	return nil
}
func (r *MeshRepository) Stage(ctx context.Context, q generated.MeshDraftRequest, a audit.Attribution) (mesh.Staged, error) {
	var out mesh.Staged
	raw, _ := json.Marshal(q)
	if generated.ValidateContractJSON(generated.SchemaIDMeshDraftRequest, raw, generated.ContractExact) != nil || mesh.Validate(q.Change) != nil || !slices.Contains(r.allowed, mesh.ScopeDigest(q.Change)) {
		return out, meshError(generated.ErrorCodeInputInvalid)
	}
	d := mesh.Digest(q)
	out = mesh.Staged{ID: "mesh-" + d[7:39], Digest: d, Request: q}
	refs := NewCredentialRepository(r.store)
	ids := []string{q.Change.ObservationReferenceID}
	if q.Change.Action != "import" {
		ids = append(ids, q.Change.MutationReferenceID)
	}
	for i, id := range ids {
		ref, e := refs.GetActiveVersion(ctx, id, q.RecoveryEpoch)
		purpose := mesh.PurposeRead
		if i == 1 {
			purpose = mesh.PurposeWrite
		}
		if e != nil || ref.ConsumerID != mesh.AdapterID || ref.PurposeID != purpose || ref.TargetID != q.Change.ProfileID || ref.Status != "active" || ref.StateRevision > q.ExpectedStateRevision || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, mesh.AdapterID) {
			return out, meshError(generated.ErrorCodePrerequisiteBlocked)
		}
		out.Bindings = append(out.Bindings, credentialref.StepBinding{OperationID: mesh.OperationID, AdapterID: mesh.AdapterID, TargetID: q.Change.ProfileID, ReferenceID: ref.ReferenceID, ConsumerID: mesh.AdapterID, PurposeID: purpose, MaterialVersion: ref.MaterialVersion, ResolverID: ref.ResolverID, StateRevision: q.ExpectedStateRevision + 3, RecoveryEpoch: q.RecoveryEpoch})
	}
	intent := discoveryIntent(a, "mesh.draft-staged", out.ID, mesh.Digest(q.IdempotencyKey), d)
	intent.Expected = &RevisionToken{StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch}
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(s string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, s, a...) }
		p, e := meshGrant(ctx, row, q.Change.ProfileID, "author")
		if e != nil {
			return e
		}
		if p.ID != a.AuthenticatedPrincipalID {
			return meshError(generated.ErrorCodeAuthorizationDenied)
		}
		if e = meshOwner(row, q.Change); e != nil {
			return e
		}
		if e = meshOwnership(row, q.Change, q.RecoveryEpoch); e != nil {
			return e
		}
		out.ActorID = p.ID
		out.ActorMethod = p.Method
		out.ActorDevice = p.DeviceID
		bindings, _ := json.Marshal(out.Bindings)
		_, e = tx.ExecContext(ctx, `INSERT INTO mesh_drafts VALUES(?,?,?,?,?,?,?,?)`, out.ID, d, raw, bindings, p.ID, p.Method, p.DeviceID, q.RecoveryEpoch)
		return e
	})
	return out, err
}
func meshDraft(row discoveryRow, id string) (out mesh.Staged, err error) {
	var raw, bindings []byte
	err = row(`SELECT draft_id,digest,request_bytes,bindings_bytes,actor_id,actor_method,actor_device FROM mesh_drafts WHERE draft_id=?`, id).Scan(&out.ID, &out.Digest, &raw, &bindings, &out.ActorID, &out.ActorMethod, &out.ActorDevice)
	if err != nil {
		return
	}
	if json.Unmarshal(raw, &out.Request) != nil || json.Unmarshal(bindings, &out.Bindings) != nil || mesh.Digest(out.Request) != out.Digest || mesh.Validate(out.Request.Change) != nil {
		err = meshError(generated.ErrorCodeIntegrityFailure)
	}
	return
}
func (r *MeshRepository) Resolve(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding) (out mesh.Staged, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		var raw, leaseRaw []byte
		if row(`SELECT p.canonical_bytes,l.canonical_bytes FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN target_execution_leases l ON l.run_id=r.run_id JOIN plan_run_steps s ON s.step_id=l.step_id AND s.run_id=r.run_id WHERE r.run_id=? AND l.lease_id=? AND s.step_id=? AND r.status='running' AND r.cancellation_requested=0 AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch AND s.status='running' AND s.effect_state IN ('intent-recorded','receipt-recorded') AND s.active_lease_id=l.lease_id AND l.status='active'`, b.RunID, b.LeaseID, b.StepID).Scan(&raw, &leaseRaw) != nil {
			return meshError(generated.ErrorCodeApprovalRequired)
		}
		var p generated.Plan
		var l generated.ExecutorLease
		if json.Unmarshal(raw, &p) != nil || json.Unmarshal(leaseRaw, &l) != nil || p.PlanID != b.PlanID || p.PlanDigest != b.PlanDigest || p.Binding.StateRevision != b.StateRevision || p.Binding.RecoveryEpoch != b.RecoveryEpoch || p.ExecutorMode != "central" || p.AuthorizationBranch != "human" || len(p.Operations) != 1 || l.Status != "active" || l.LeaseID != b.LeaseID || l.RecoveryEpoch != b.RecoveryEpoch || l.OperationID != op.OperationID || l.TargetID != op.TargetID || l.PlanID != b.PlanID || l.PlanDigest != b.PlanDigest || l.RunID != b.RunID || l.StepID != b.StepID || l.ArtifactDigest != op.ArtifactDigest {
			return meshError(generated.ErrorCodePlanStale)
		}
		deadline, e := time.Parse(time.RFC3339, l.MaximumExpiresAt)
		if e != nil || !r.store.config.Clock().Before(deadline) {
			return meshError(generated.ErrorCodePlanStale)
		}
		po := p.Operations[0]
		if po.AdapterID != mesh.AdapterID || po.OperationID != op.OperationID || po.TargetID != op.TargetID || po.InputDigest != op.InputDigest || po.ArtifactDigest != op.ArtifactDigest {
			return meshError(generated.ErrorCodeIntegrityFailure)
		}
		var payload string
		for _, x := range p.Extensions {
			if x.Name == mesh.Extension {
				payload = x.ValueDigest
			}
		}
		if payload == "" || payload != op.ArtifactDigest {
			return meshError(generated.ErrorCodeIntegrityFailure)
		}
		out, e = meshDraft(row, "mesh-"+payload[7:39])
		if e != nil {
			return e
		}
		q := out.Request
		c := q.Change
		if op.OperationType != "network.mesh."+c.Action || op.TargetID != c.ProfileID || op.InputDigest != credentialref.OperationManifestDigest(out.Bindings, op.OperationID) || !slices.Contains(r.allowed, mesh.ScopeDigest(c)) {
			return meshError(generated.ErrorCodeIntegrityFailure)
		}
		actor := identity.Principal{ID: out.ActorID, Method: out.ActorMethod, DeviceID: out.ActorDevice}
		if _, e = meshGrant(identity.WithVerifiedPrincipal(ctx, actor), row, c.ProfileID, "author"); e != nil {
			return e
		}
		if e = meshOwner(row, c); e != nil {
			return e
		}
		if e = meshOwnership(row, c, q.RecoveryEpoch); e != nil {
			return e
		}
		var epoch int64
		if row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&epoch) != nil || epoch != b.RecoveryEpoch {
			return meshError(generated.ErrorCodeRecoveryEpochMismatch)
		}
		return nil
	})
	return
}
func (r *MeshRepository) Record(ctx context.Context, d mesh.Staged, b adapter.ExactExecutionBinding, s mesh.Snapshot, status string) error {
	a, e := r.store.HostAccessRunAttribution(ctx, b.RunID)
	if e != nil {
		return e
	}
	key := mesh.Digest([]string{b.RunID, b.StepID, status, s.Digest})
	in := discoveryIntent(a, "mesh.effect-observed", "mesh-result-"+key[7:39], key, mesh.Digest(s))
	_, e = r.store.executeAuditIntent(ctx, in, false, func(ctx context.Context, tx *sql.Tx) error {
		if status == "observed" {
			_, e := tx.ExecContext(ctx, `INSERT INTO mesh_ownership VALUES(?,?,?,?,?,?)`, d.Request.Change.ProfileID, d.Request.Change.ExpectedOwnershipRevision+1, mesh.ScopeDigest(d.Request.Change), d.ID, b.RunID, b.RecoveryEpoch)
			if e != nil {
				return e
			}
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO mesh_observations VALUES(?,?,?,?,?,?,?,?,?)`, "mesh-result-"+key[7:39], d.Request.Change.ProfileID, d.ID, b.RunID, status, s.Reason, s.Digest, r.store.config.Clock().UTC().Format(time.RFC3339), b.RecoveryEpoch)
		return e
	})
	return e
}
func (r *MeshRepository) Status(ctx context.Context, id string) (out generated.MeshStatusData, err error) {
	out = generated.MeshStatusData{Schema: generated.SchemaIDMeshStatusData, SchemaVersion: "1.0.0", ProfileID: id, Status: "unknown", Reason: "no-provider-observation", ObservationDigest: mesh.Digest(nil)}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		if _, e := meshGrant(ctx, row, id, "read"); e != nil {
			return e
		}
		if e := row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&out.StateRevision, &out.RecoveryEpoch); e != nil {
			return e
		}
		var rev sql.NullInt64
		if e := row(`SELECT MAX(revision) FROM mesh_ownership WHERE profile_id=? AND recovery_epoch=?`, id, out.RecoveryEpoch).Scan(&rev); e != nil {
			return e
		}
		out.OwnershipRevision = rev.Int64
		e := row(`SELECT status,reason,observation_digest,observed_at FROM mesh_observations WHERE profile_id=? AND recovery_epoch=? ORDER BY rowid DESC LIMIT 1`, id, out.RecoveryEpoch).Scan(&out.Status, &out.Reason, &out.ObservationDigest, &out.ObservedAt)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e == nil {
			at, pe := time.Parse(time.RFC3339, out.ObservedAt)
			if pe != nil || r.store.config.Clock().Sub(at) > 5*time.Minute {
				out.Status = "unknown"
				out.Reason = "stale-provider-observation"
			}
		}
		return e
	})
	return
}

func (r *MeshRepository) GetStaged(ctx context.Context, id string) (out mesh.Staged, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var e error
		out, e = meshDraft(func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }, id)
		return e
	})
	return
}
func (r *MeshRepository) CheckCurrent(ctx context.Context, d mesh.Staged) error {
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		q := d.Request
		c := q.Change
		if !slices.Contains(r.allowed, mesh.ScopeDigest(c)) {
			return meshError(generated.ErrorCodeAuthorizationDenied)
		}
		actor := identity.Principal{ID: d.ActorID, Method: d.ActorMethod, DeviceID: d.ActorDevice}
		if _, e := meshGrant(identity.WithVerifiedPrincipal(ctx, actor), row, c.ProfileID, "author"); e != nil {
			return e
		}
		if e := meshOwner(row, c); e != nil {
			return e
		}
		return meshOwnership(row, c, q.RecoveryEpoch)
	})
}

// Preview checks a read-only observation scope without writing desired state or ownership.
func (r *MeshRepository) Preview(ctx context.Context, q generated.MeshDraftRequest) (out mesh.Staged, err error) {
	if mesh.Validate(q.Change) != nil || !slices.Contains(r.allowed, mesh.ScopeDigest(q.Change)) {
		return out, meshError(generated.ErrorCodeAuthorizationDenied)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		p, e := meshGrant(ctx, row, q.Change.ProfileID, "read")
		if e != nil {
			return e
		}
		if e = meshOwner(row, q.Change); e != nil {
			return e
		}
		if e = meshOwnership(row, q.Change, q.RecoveryEpoch); e != nil {
			return e
		}
		var revision, epoch int64
		if row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&revision, &epoch) != nil || epoch != q.RecoveryEpoch || revision != q.ExpectedStateRevision {
			return meshError(generated.ErrorCodeStateConflict)
		}
		out = mesh.Staged{ID: "mesh-" + mesh.Digest(q)[7:39], Digest: mesh.Digest(q), Request: q, ActorID: p.ID, ActorMethod: p.Method, ActorDevice: p.DeviceID}
		return nil
	})
	if err != nil {
		return
	}
	ref, e := NewCredentialRepository(r.store).GetActiveVersion(ctx, q.Change.ObservationReferenceID, q.RecoveryEpoch)
	if e != nil || ref.ConsumerID != mesh.AdapterID || ref.TargetID != q.Change.ProfileID || ref.PurposeID != mesh.PurposeRead || ref.Status != "active" || ref.StateRevision > q.ExpectedStateRevision || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, mesh.AdapterID) {
		return out, meshError(generated.ErrorCodePrerequisiteBlocked)
	}
	out.Bindings = []credentialref.StepBinding{{OperationID: "mesh-observe", AdapterID: mesh.AdapterID, TargetID: q.Change.ProfileID, ReferenceID: ref.ReferenceID, ConsumerID: mesh.AdapterID, PurposeID: mesh.PurposeRead, MaterialVersion: ref.MaterialVersion, ResolverID: ref.ResolverID, StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch}}
	return
}
