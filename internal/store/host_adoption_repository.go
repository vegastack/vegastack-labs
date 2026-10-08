package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"time"
)

type HostAdoptionRepository struct{ store *Store }

func NewHostAdoptionRepository(s *Store) *HostAdoptionRepository {
	return &HostAdoptionRepository{store: s}
}

type HostAdoptionDraft struct {
	ID, Digest string
	Request    generated.HostAdoptionRequest
}
type HostAdoptionApply struct {
	DraftID, PlanID, PlanDigest, RunID, StepID, LeaseID string
	Attribution                                         audit.Attribution
}

func adoptionError(code string) error { return newStoreError(code, "host-adoption", false, nil) }
func adoptionGrant(ctx context.Context, row discoveryRow, resource, kind, action, capability string, admin bool) (string, error) {
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok || !identity.ValidPrincipal(p) {
		return "", adoptionError(generated.ErrorCodeAuthenticationRequired)
	}
	var count int
	err := row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind=? AND p.status='active' AND g.status='active' AND g.action=? AND g.capability=? AND g.resource_kind=? AND g.resource_id=? AND (g.action!='execute' OR (g.branch='human' AND g.role_id='control-plane-admin')) AND (?=0 OR g.role_id IN ('infrastructure-admin','control-plane-admin'))`, p.ID, string(identity.EffectivePrincipalKind(p)), action, capability, kind, resource, admin).Scan(&count)
	if err != nil || count == 0 {
		return "", adoptionError(generated.ErrorCodeAuthorizationDenied)
	}
	return p.ID, nil
}
func (r *HostAdoptionRepository) validate(ctx context.Context, row discoveryRow, req generated.HostAdoptionRequest, a audit.Attribution) (generated.HostDiscoveryTarget, error) {
	obs, err := readDiscoveryObservation(row, req.ObservationID)
	if err != nil {
		return generated.HostDiscoveryTarget{}, adoptionError(generated.ErrorCodePrerequisiteBlocked)
	}
	p, err := adoptionGrant(ctx, row, obs.TargetID, "host-discovery-target", "author", "host.adoption.prepare", true)
	if err != nil {
		return generated.HostDiscoveryTarget{}, err
	}
	if p != a.AuthenticatedPrincipalID {
		return generated.HostDiscoveryTarget{}, adoptionError(generated.ErrorCodeAuthorizationDenied)
	}
	target, err := discoveryTarget(row, obs.TargetID)
	if err != nil {
		return generated.HostDiscoveryTarget{}, err
	}
	if target.Digest != obs.TargetDigest {
		return generated.HostDiscoveryTarget{}, adoptionError(generated.ErrorCodePlanStale)
	}
	if err := hostadoption.Validate(req, obs, target.Binding, r.store.config.Clock().UTC()); err != nil {
		return generated.HostDiscoveryTarget{}, err
	}
	// Later observations may reveal an identity conflict after this snapshot.
	for _, fact := range obs.Facts {
		if fact.Name != req.Confirmation.IdentityKind {
			continue
		}
		var duplicates int
		if err := row(`SELECT COUNT(*) FROM host_observation_identities WHERE kind=? AND value_digest=? AND target_id!=?`, fact.Name, hostdiscovery.Digest(fact.Value), obs.TargetID).Scan(&duplicates); err != nil {
			return generated.HostDiscoveryTarget{}, err
		}
		if duplicates != 0 {
			return generated.HostDiscoveryTarget{}, adoptionError(generated.ErrorCodeStateConflict)
		}
	}
	if err := discoveryInventoryRead(row, p, target.Binding); err != nil {
		return generated.HostDiscoveryTarget{}, err
	}
	var epoch int64
	if err := row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&epoch); err != nil {
		return generated.HostDiscoveryTarget{}, err
	}
	if epoch != req.RecoveryEpoch {
		return generated.HostDiscoveryTarget{}, adoptionError(generated.ErrorCodeRecoveryEpochMismatch)
	}
	return target.Binding, nil
}
func (r *HostAdoptionRepository) StageDraft(ctx context.Context, req generated.HostAdoptionRequest, a audit.Attribution) (HostAdoptionDraft, error) {
	if err := r.store.Read(ctx, func(tx ReadTx) error {
		_, err := r.validate(ctx, func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }, req, a)
		return err
	}); err != nil {
		return HostAdoptionDraft{}, err
	}
	digest := hostadoption.Digest(req)
	d := HostAdoptionDraft{ID: "host-adoption-" + digest[7:39], Digest: digest, Request: req}
	raw, _ := json.Marshal(req)
	intent := discoveryIntent(a, "host.adoption.drafted", d.ID, hostdiscovery.Digest([]string{a.AuthenticatedPrincipalID, req.IdempotencyKey}), digest)
	intent.Expected = &RevisionToken{StateRevision: req.ExpectedStateRevision, RecoveryEpoch: req.RecoveryEpoch}
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, q, args...) }
		if _, err := r.validate(ctx, row, req, a); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO host_adoption_drafts VALUES(?,?,?,?,?,?)`, d.ID, digest, raw, a.AuthenticatedPrincipalID, req.ExpectedStateRevision, req.RecoveryEpoch)
		return err
	})
	return d, err
}
func (r *HostAdoptionRepository) GetDraft(ctx context.Context, id string) (HostAdoptionDraft, error) {
	d := HostAdoptionDraft{ID: id}
	err := r.store.Read(ctx, func(tx ReadTx) error {
		var raw []byte
		if err := tx.queryRow(ctx, `SELECT canonical_bytes,digest FROM host_adoption_drafts WHERE draft_id=?`, id).Scan(&raw, &d.Digest); err != nil {
			return err
		}
		if json.Unmarshal(raw, &d.Request) != nil || hostadoption.Digest(d.Request) != d.Digest {
			return adoptionError(generated.ErrorCodeIntegrityFailure)
		}
		return nil
	})
	return d, err
}
func readManagedHost(row discoveryRow, id string) (generated.ManagedHost, error) {
	h := generated.ManagedHost{Schema: generated.SchemaIDManagedHost, SchemaVersion: "1.0.0", Status: "adopted-unadmitted"}
	err := row(`SELECT host_id,target_id,observation_id,profile_id,identity_class,state_revision,recovery_epoch FROM managed_hosts WHERE host_id=?`, id).Scan(&h.HostID, &h.TargetID, &h.ObservationID, &h.ProfileID, &h.IdentityClass, &h.StateRevision, &h.RecoveryEpoch)
	return h, err
}
func (r *HostAdoptionRepository) Get(ctx context.Context, id string) (generated.ManagedHost, error) {
	var h generated.ManagedHost
	err := r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }
		if _, err := adoptionGrant(ctx, row, id, "host", "read", "host.read", false); err != nil {
			return err
		}
		var err error
		h, err = readManagedHost(row, id)
		return err
	})
	return h, err
}
func (r *HostAdoptionRepository) Apply(ctx context.Context, req HostAdoptionApply) (generated.ManagedHost, error) {
	d, err := r.GetDraft(ctx, req.DraftID)
	if err != nil {
		return generated.ManagedHost{}, err
	}
	// Audit intent replays skip the callback; current authority is mandatory even then.
	if err := r.store.Read(ctx, func(tx ReadTx) error {
		_, _, _, _, err := r.applyBinding(ctx, func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }, d, req)
		return err
	}); err != nil {
		return generated.ManagedHost{}, err
	}
	intent := discoveryIntent(req.Attribution, "host.adoption.applied", d.ID, hostdiscovery.Digest([]string{req.PlanID, req.StepID}), d.Digest)
	intent.Context = audit.ContextIDs{PlanID: req.PlanID, RunID: req.RunID}
	_, err = r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, q, args...) }
		target, current, human, ack, err := r.applyBinding(ctx, row, d, req)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO managed_hosts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, d.Request.HostID, target.TargetID, d.Request.Confirmation.IdentityDigest, d.Request.Confirmation.IdentityKind, d.Request.Confirmation.IdentityClass, d.Request.ObservationID, target.ProfileID, d.ID, req.PlanID, human, ack, current.StateRevision, current.RecoveryEpoch)
		return err
	})
	if err != nil {
		return generated.ManagedHost{}, err
	}
	var h generated.ManagedHost
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var err error
		h, err = readManagedHost(func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }, d.Request.HostID)
		return err
	})
	return h, err
}
func (r *HostAdoptionRepository) Verify(ctx context.Context, draftID, planID, digest string) error {
	return r.store.Read(ctx, func(tx ReadTx) error {
		var n int
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM managed_hosts h JOIN host_adoption_drafts d ON d.draft_id=h.draft_id WHERE h.draft_id=? AND h.plan_id=? AND d.digest=?`, draftID, planID, digest).Scan(&n); err != nil || n != 1 {
			return adoptionError(generated.ErrorCodeStateConflict)
		}
		return nil
	})
}

func (r *HostAdoptionRepository) applyBinding(ctx context.Context, row discoveryRow, d HostAdoptionDraft, req HostAdoptionApply) (generated.HostDiscoveryTarget, RevisionToken, string, string, error) {
	// Background execution derives identity kind from current server-owned records,
	// and binds attribution to the durable run.created event, never a caller name.
	var kind string
	if err := row(`SELECT p.principal_kind FROM effective_authorization_principals p JOIN audit_events a ON a.principal_id=p.principal_id WHERE p.principal_id=? AND p.status='active' AND a.event_type='run.created' AND a.correlation_id=? AND a.principal_method=?`, req.Attribution.AuthenticatedPrincipalID, req.RunID, req.Attribution.AuthenticatedPrincipalMethod).Scan(&kind); err != nil {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", adoptionError(generated.ErrorCodeAuthorizationDenied)
	}
	principal := identity.Principal{ID: req.Attribution.AuthenticatedPrincipalID, Method: req.Attribution.AuthenticatedPrincipalMethod, Kind: identity.PrincipalKind(kind)}
	if !identity.ValidPrincipal(principal) || (principal.Kind == identity.PrincipalAgent && req.Attribution.Agent == nil) {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", adoptionError(generated.ErrorCodeAuthorizationDenied)
	}
	ctx = identity.WithVerifiedPrincipal(ctx, principal)

	target, err := r.validate(ctx, row, d.Request, req.Attribution)
	if err != nil {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", err
	}
	if _, err := adoptionGrant(ctx, row, d.ID, "execution-target", "execute", "host.adopt", true); err != nil {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", err
	}
	var raw []byte
	var revision, epoch int64
	if err := row(`SELECT canonical_bytes,state_revision,recovery_epoch FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, req.PlanID, req.PlanDigest).Scan(&raw, &revision, &epoch); err != nil {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", adoptionError(generated.ErrorCodeAuthorizationDenied)
	}
	var p generated.Plan
	if json.Unmarshal(raw, &p) != nil || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Risk != "control-plane" || len(p.Operations) != 1 {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", adoptionError(generated.ErrorCodeAuthorizationDenied)
	}
	op := p.Operations[0]
	if p.HostAdoption == nil || hostadoption.Digest(*p.HostAdoption) != d.Digest || op.OperationType != "host.adopt" || op.AdapterID != "core.host-adoption" || op.TargetID != d.ID || op.InputDigest != d.Digest || op.ArtifactDigest != d.Digest {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", adoptionError(generated.ErrorCodePlanStale)
	}
	var current RevisionToken
	if err := row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&current.StateRevision, &current.RecoveryEpoch); err != nil {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", err
	}
	if current.StateRevision != revision || current.RecoveryEpoch != epoch || epoch != d.Request.RecoveryEpoch {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", adoptionError(generated.ErrorCodePlanStale)
	}
	var human, ack string
	err = row(`SELECT a.human_id,a.acknowledgement_id FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.executor_mode='central' AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch AND s.step_id=? AND s.target_id=? AND s.operation_type='host.adopt' AND s.adapter_id='core.host-adoption' AND s.input_digest=? AND s.artifact_digest=? AND s.effect_state='intent-recorded' AND s.status='running' AND l.lease_id=? AND l.status='active' AND l.run_id=r.run_id AND l.step_id=s.step_id AND l.target_id=s.target_id AND l.recovery_epoch=a.recovery_epoch AND l.recovery_epoch=? AND l.expires_at>?`, req.RunID, req.PlanID, req.PlanDigest, req.StepID, d.ID, d.Digest, d.Digest, req.LeaseID, epoch, r.store.config.Clock().UTC().Format(time.RFC3339)).Scan(&human, &ack)
	if err != nil {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", adoptionError(generated.ErrorCodeApprovalRequired)
	}
	// A stored approval cannot outlive the human's effective control-plane grant.
	var count int
	if err := row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind='human' AND p.status='active' AND g.status='active' AND g.role_id='control-plane-admin' AND g.action='acknowledge' AND g.branch='human' AND g.capability='plan.acknowledge' AND g.resource_kind='plan-target' AND g.resource_id=?`, human, d.ID).Scan(&count); err != nil || count == 0 {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", adoptionError(generated.ErrorCodeAuthorizationDenied)
	}
	if req.Attribution.ResponsibleHumanPrincipalID == nil || *req.Attribution.ResponsibleHumanPrincipalID != human {
		return generated.HostDiscoveryTarget{}, RevisionToken{}, "", "", adoptionError(generated.ErrorCodeAuthorizationDenied)
	}
	return target, current, human, ack, nil
}
