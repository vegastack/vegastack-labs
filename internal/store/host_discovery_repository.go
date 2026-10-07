package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type HostDiscoveryRepository struct{ store *Store }

func NewHostDiscoveryRepository(s *Store) *HostDiscoveryRepository {
	return &HostDiscoveryRepository{store: s}
}
func discoveryError(code string) error { return newStoreError(code, "host-discovery", false, nil) }

type discoveryRow func(string, ...any) *sql.Row

// The data boundary checks actual active grants, not caller-authored scope claims.
func discoveryGrant(ctx context.Context, row discoveryRow, target, capability string, admin bool) (string, int64, error) {
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok || !identity.ValidPrincipal(p) {
		return "", 0, discoveryError(generated.ErrorCodeAuthenticationRequired)
	}
	var revision int64
	var kind string
	if err := row(`SELECT grant_revision,principal_kind FROM effective_authorization_principals WHERE principal_id=? AND status='active'`, p.ID).Scan(&revision, &kind); err != nil || kind != string(identity.EffectivePrincipalKind(p)) {
		return "", 0, discoveryError(generated.ErrorCodeAuthorizationDenied)
	}
	action := "read"
	if capability == "host.discovery.target.prepare" {
		action = "author"
	}
	var count int
	if err := row(`SELECT COUNT(*) FROM effective_authorization_grants WHERE principal_id=? AND grant_revision=? AND status='active' AND action=? AND capability=? AND resource_kind='host-discovery-target' AND resource_id=? AND (?=0 OR role_id IN ('infrastructure-admin','control-plane-admin'))`, p.ID, revision, action, capability, target, admin).Scan(&count); err != nil || count == 0 {
		return "", 0, discoveryError(generated.ErrorCodeAuthorizationDenied)
	}
	return p.ID, revision, nil
}
func discoveryEvent(a audit.Attribution, kind, id, digest string) audit.EventDraft {
	after := audit.Fingerprint(digest)
	return audit.EventDraft{Type: audit.EventType(kind), CorrelationID: id, Attribution: a, Target: audit.Target{Kind: "host-discovery", ID: id}, After: &after}
}
func discoveryIntent(a audit.Attribution, kind, id, key, digest string) intentRequest {
	return intentRequest{Idempotency: audit.IntentKey{Scope: kind, KeyDigest: audit.Fingerprint(key), RequestDigest: audit.Fingerprint(digest)}, Event: discoveryEvent(a, kind, id, digest)}
}
func discoveryTarget(row discoveryRow, id string) (hostdiscovery.Target, error) {
	var raw []byte
	var digest, status string
	err := row(`SELECT d.canonical_bytes,d.digest,t.status FROM host_discovery_targets t JOIN host_discovery_drafts d ON d.draft_id=t.draft_id WHERE t.target_id=? ORDER BY t.revision DESC LIMIT 1`, id).Scan(&raw, &digest, &status)
	if err != nil || status != "active" {
		return hostdiscovery.Target{}, discoveryError(generated.ErrorCodePrerequisiteBlocked)
	}
	var draft generated.HostDiscoveryTargetDraftRequest
	if json.Unmarshal(raw, &draft) != nil || hostdiscovery.Digest(draft) != digest || hostdiscovery.ValidateTarget(draft.Target) != nil {
		return hostdiscovery.Target{}, discoveryError(generated.ErrorCodeIntegrityFailure)
	}
	return hostdiscovery.Target{Binding: draft.Target, Digest: digest}, nil
}
func (r *HostDiscoveryRepository) Begin(ctx context.Context, req hostdiscovery.BeginRequest) (result hostdiscovery.Attempt, outcome error) {
	defer r.discoveryFailureAudit(ctx, "collect", req.Request.TargetID, &outcome)
	raw, _ := json.Marshal(req.Request)
	if generated.ValidateContractJSON(generated.SchemaIDHostDiscoveryRequest, raw, generated.ContractExact) != nil {
		return result, discoveryError(generated.ErrorCodeInputInvalid)
	}
	key := hostdiscovery.Digest(req.Request.IdempotencyKey)
	digest := hostdiscovery.Digest(req.Request)
	var found bool
	err := r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }
		principal, grant, err := discoveryGrant(ctx, row, req.Request.TargetID, "host.discovery.collect", true)
		if err != nil {
			return err
		}
		if req.Attribution.AuthenticatedPrincipalID != principal {
			return discoveryError(generated.ErrorCodeAuthorizationDenied)
		}
		target, err := discoveryTarget(row, req.Request.TargetID)
		if err != nil {
			return err
		}
		if err := discoveryInventoryRead(row, principal, target.Binding); err != nil {
			return err
		}
		if target.Binding.Revision != req.Request.TargetRevision || target.Binding.RecoveryEpoch != req.Request.RecoveryEpoch {
			return discoveryError(generated.ErrorCodeStateConflict)
		}
		var current RevisionToken
		if err := row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&current.StateRevision, &current.RecoveryEpoch); err != nil {
			return err
		}
		if current.RecoveryEpoch != req.Request.RecoveryEpoch {
			return discoveryError(generated.ErrorCodeRecoveryEpochMismatch)
		}
		var oldDigest string
		err = row(`SELECT attempt_id,request_digest FROM host_discovery_attempts WHERE principal_id=? AND key_digest=?`, principal, key).Scan(&result.ID, &oldDigest)
		if err == nil {
			found = true
			if oldDigest != digest {
				return discoveryError(generated.ErrorCodeStateConflict)
			}
			var terminal string
			err := row(`SELECT error_code FROM host_discovery_failures WHERE attempt_id=?`, result.ID).Scan(&terminal)
			if err == nil {
				return discoveryError(terminal)
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			observation, err := readDiscoveryObservation(row, result.ID)
			if errors.Is(err, sql.ErrNoRows) {
				var deadline string
				if err := row(`SELECT deadline FROM host_discovery_attempts WHERE attempt_id=?`, result.ID).Scan(&deadline); err != nil {
					return err
				}
				end, err := time.Parse(time.RFC3339Nano, deadline)
				if err != nil {
					return discoveryError(generated.ErrorCodeIntegrityFailure)
				}
				if !r.store.config.Clock().Before(end) {
					return discoveryError(generated.ErrorCodeInterrupted)
				}
				return discoveryError(generated.ErrorCodeStateConflict)
			}
			if err != nil {
				return err
			}
			if _, _, err := discoveryGrant(ctx, row, req.Request.TargetID, "host.discovery.read", false); err != nil {
				return err
			}
			result.Observation = &observation
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if current.StateRevision != req.Request.ExpectedStateRevision {
			return discoveryError(generated.ErrorCodeStateConflict)
		}
		result = hostdiscovery.Attempt{ID: "discovery-" + hostdiscovery.Digest([]string{principal, key})[7:39], Target: target, Request: req.Request, PrincipalID: principal, Deadline: r.store.config.Clock().UTC().Add(hostdiscovery.MaximumDuration)}
		result.Target.GrantRevision = grant
		result.Target.StateRevision = current.StateRevision + 1
		return nil
	})
	if err != nil || found {
		return result, err
	}
	intent := discoveryIntent(req.Attribution, "host.discovery.started", result.ID, key, digest)
	// Principal is part of the reservation key, preventing cross-user idempotency collisions.
	intent.Idempotency.KeyDigest = audit.Fingerprint(hostdiscovery.Digest([]string{result.PrincipalID, key}))
	intent.Expected = &RevisionToken{StateRevision: req.Request.ExpectedStateRevision, RecoveryEpoch: req.Request.RecoveryEpoch}
	committed, err := r.store.writeIntent(ctx, intent, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, q, args...) }
		principal, grant, err := discoveryGrant(ctx, row, req.Request.TargetID, "host.discovery.collect", true)
		if err != nil {
			return err
		}
		target, err := discoveryTarget(row, req.Request.TargetID)
		if err != nil {
			return err
		}
		if principal != result.PrincipalID || grant != result.Target.GrantRevision || target.Digest != result.Target.Digest {
			return discoveryError(generated.ErrorCodeStateConflict)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO host_discovery_attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, result.ID, principal, key, digest, req.Request.TargetID, req.Request.TargetRevision, target.Digest, grant, result.Target.StateRevision, req.Request.RecoveryEpoch, result.Deadline.Format(time.RFC3339Nano), raw)
		return err
	})
	if err != nil {
		return hostdiscovery.Attempt{}, err
	}
	if !committed.Created {
		return hostdiscovery.Attempt{}, discoveryError(generated.ErrorCodeStateConflict)
	}
	return result, nil
}
func readDiscoveryObservation(row discoveryRow, id string) (generated.HostObservation, error) {
	var raw []byte
	var digest string
	var result generated.HostObservation
	if err := row(`SELECT canonical_bytes,digest FROM host_observations WHERE observation_id=?`, id).Scan(&raw, &digest); err != nil {
		return result, err
	}
	if json.Unmarshal(raw, &result) != nil || hostdiscovery.Digest(result) != digest {
		return result, discoveryError(generated.ErrorCodeIntegrityFailure)
	}
	return result, nil
}
func (r *HostDiscoveryRepository) Get(ctx context.Context, id string) (result generated.HostObservation, outcome error) {
	defer r.discoveryFailureAudit(ctx, "read", id, &outcome)
	err := r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }
		var target string
		if err := row(`SELECT target_id FROM host_observations WHERE observation_id=?`, id).Scan(&target); err != nil {
			return discoveryError(generated.ErrorCodeAuthorizationDenied)
		}
		if _, _, err := discoveryGrant(ctx, row, target, "host.discovery.read", false); err != nil {
			return err
		}
		var epoch int64
		if err := row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&epoch); err != nil {
			return err
		}
		var err error
		result, err = readDiscoveryObservation(row, id)
		if err != nil {
			return err
		}
		if result.RecoveryEpoch != epoch {
			return discoveryError(generated.ErrorCodeRecoveryEpochMismatch)
		}
		return nil
	})
	if err != nil {
		return generated.HostObservation{}, err
	}
	expires, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil {
		return generated.HostObservation{}, discoveryError(generated.ErrorCodeIntegrityFailure)
	}
	if !r.store.config.Clock().Before(expires) {
		result.Blockers = append(result.Blockers, "stale-observation")
	}
	return result, nil
}

func (r *HostDiscoveryRepository) Complete(ctx context.Context, req hostdiscovery.CompleteRequest) (result generated.HostObservation, outcome error) {
	defer r.discoveryFailureAudit(ctx, "complete", req.Attempt.ID, &outcome)
	if hostdiscovery.ValidateCollection(req.Collection) != nil {
		return result, discoveryError(generated.ErrorCodeInputInvalid)
	}
	attempt := req.Attempt
	digest := hostdiscovery.Digest(req.Collection)
	intent := discoveryIntent(req.Attribution, "host.discovery.completed", attempt.ID, hostdiscovery.Digest(attempt.ID), digest)
	intent.Expected = &RevisionToken{StateRevision: attempt.Target.StateRevision, RecoveryEpoch: attempt.Request.RecoveryEpoch}
	_, err := r.store.writeIntent(ctx, intent, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, q, args...) }
		principal, grant, err := discoveryGrant(ctx, row, attempt.Request.TargetID, "host.discovery.collect", true)
		if err != nil {
			return err
		}
		if _, _, err := discoveryGrant(ctx, row, attempt.Request.TargetID, "host.discovery.read", false); err != nil {
			return err
		}
		if principal != attempt.PrincipalID || principal != req.Attribution.AuthenticatedPrincipalID || grant != attempt.Target.GrantRevision {
			return discoveryError(generated.ErrorCodeAuthorizationDenied)
		}
		var storedPrincipal, storedTarget, storedDigest, deadline, requestDigest string
		var revision, epoch, state, grantRevision int64
		if err := row(`SELECT principal_id,target_id,target_revision,target_digest,deadline,request_digest,recovery_epoch,state_revision,grant_revision FROM host_discovery_attempts WHERE attempt_id=?`, attempt.ID).Scan(&storedPrincipal, &storedTarget, &revision, &storedDigest, &deadline, &requestDigest, &epoch, &state, &grantRevision); err != nil {
			return err
		}
		if storedPrincipal != principal || storedTarget != attempt.Request.TargetID || revision != attempt.Request.TargetRevision || storedDigest != attempt.Target.Digest || requestDigest != hostdiscovery.Digest(attempt.Request) || epoch != attempt.Request.RecoveryEpoch || state != attempt.Target.StateRevision || grantRevision != grant {
			return discoveryError(generated.ErrorCodeStateConflict)
		}
		var failed int
		if err := row(`SELECT COUNT(*) FROM host_discovery_failures WHERE attempt_id=?`, attempt.ID).Scan(&failed); err != nil {
			return err
		}
		if failed != 0 {
			return discoveryError(generated.ErrorCodeInterrupted)
		}
		end, err := time.Parse(time.RFC3339Nano, deadline)
		if err != nil {
			return discoveryError(generated.ErrorCodeIntegrityFailure)
		}
		now := r.store.config.Clock().UTC()
		if !now.Before(end) {
			return discoveryError(generated.ErrorCodeInterrupted)
		}
		target, err := discoveryTarget(row, storedTarget)
		if err != nil {
			return err
		}
		if target.Digest != storedDigest || target.Binding.Revision != revision {
			return discoveryError(generated.ErrorCodeStateConflict)
		}
		result = generated.HostObservation{Schema: generated.SchemaIDHostObservation, SchemaVersion: "1.0.0", ObservationID: attempt.ID, TargetID: storedTarget, TargetRevision: revision, TargetDigest: storedDigest, Collector: hostdiscovery.CollectorID, CollectorVersion: hostdiscovery.CollectorVersion, ObservedAt: now.Truncate(time.Second).Format(time.RFC3339), ExpiresAt: now.Add(hostdiscovery.Freshness).Truncate(time.Second).Format(time.RFC3339), Status: "untrusted", Facts: req.Collection.Facts, Blockers: hostdiscovery.Findings(target.Binding, req.Collection), StateRevision: state + 1, RecoveryEpoch: epoch}
		if result.Facts == nil {
			result.Facts = []generated.HostDiscoveryFact{}
		}
		for _, code := range result.Blockers {
			if len(code) >= 8 && code[:8] == "missing-" {
				result.Status = "incomplete"
			}
		}
		for _, fact := range req.Collection.Facts {
			if fact.Name != "machine-id" && fact.Name != "product-uuid" && fact.Name != "product-serial" {
				continue
			}
			var count int
			if err := row(`SELECT COUNT(*) FROM host_observation_identities WHERE kind=? AND value_digest=? AND target_id!=?`, fact.Name, hostdiscovery.Digest(fact.Value), storedTarget).Scan(&count); err != nil {
				return err
			}
			if count > 0 {
				result.Blockers = append(result.Blockers, "identity-conflict")
				break
			}
		}
		if err := discoveryInventoryRead(row, principal, target.Binding); err != nil {
			return err
		}
		if target.Binding.InventoryDraftID != nil {
			for _, fact := range req.Collection.Facts {
				if fact.Name != "product-serial" {
					continue
				}
				// Inventory's hardware-serial has an explicit matching meaning;
				// its generic machine/installation IDs are not assumed to be DMI IDs.
				var mismatch, conflict int
				if err := row(`SELECT COUNT(*) FROM inventory_draft_identities i JOIN inventory_draft_assets a ON a.draft_id=i.draft_id AND a.draft_revision=i.draft_revision AND a.ordinal=i.asset_ordinal WHERE i.draft_id=? AND i.draft_revision=? AND a.local_id=? AND i.kind='hardware-serial' AND (i.value!=? OR i.quarantined=1)`, *target.Binding.InventoryDraftID, target.Binding.InventoryDraftRevision, *target.Binding.AssetID, fact.Value).Scan(&mismatch); err != nil {
					return err
				}
				if mismatch > 0 {
					result.Blockers = append(result.Blockers, "inventory-identity-mismatch")
				}
				if err := row(`SELECT COUNT(*) FROM inventory_draft_identities i JOIN inventory_draft_assets a ON a.draft_id=i.draft_id AND a.draft_revision=i.draft_revision AND a.ordinal=i.asset_ordinal WHERE i.draft_id=? AND i.draft_revision=? AND a.local_id!=? AND i.kind='hardware-serial' AND i.value=?`, *target.Binding.InventoryDraftID, target.Binding.InventoryDraftRevision, *target.Binding.AssetID, fact.Value).Scan(&conflict); err != nil {
					return err
				}
				if conflict > 0 && !slices.Contains(result.Blockers, "identity-conflict") {
					result.Blockers = append(result.Blockers, "identity-conflict")
				}
			}
		}
		// The digest covers the immutable observation, excluding its own digest field.
		result.ContentDigest = hostdiscovery.Digest(result)
		raw, _ := json.Marshal(result)
		if generated.ValidateContractJSON(generated.SchemaIDHostObservation, raw, generated.ContractExact) != nil {
			return discoveryError(generated.ErrorCodeIntegrityFailure)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO host_observations VALUES(?,?,?,?,?,?,?)`, attempt.ID, storedTarget, revision, raw, hostdiscovery.Digest(result), state+1, epoch); err != nil {
			return err
		}
		for _, fact := range req.Collection.Facts {
			if fact.Name == "machine-id" || fact.Name == "product-uuid" || fact.Name == "product-serial" {
				if _, err := tx.ExecContext(ctx, `INSERT INTO host_observation_identities VALUES(?,?,?,?)`, attempt.ID, storedTarget, fact.Name, hostdiscovery.Digest(fact.Value)); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return generated.HostObservation{}, err
	}
	return r.Get(ctx, attempt.ID)
}

var _ hostdiscovery.Repository = (*HostDiscoveryRepository)(nil)

func (r *HostDiscoveryRepository) CheckCollection(ctx context.Context, target hostdiscovery.Target) error {
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }
		_, grant, err := discoveryGrant(ctx, row, target.Binding.TargetID, "host.discovery.collect", true)
		if err != nil {
			return err
		}
		active, err := discoveryTarget(row, target.Binding.TargetID)
		if err != nil {
			return err
		}
		var state, epoch int64
		if err := row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&state, &epoch); err != nil {
			return err
		}
		if grant != target.GrantRevision || active.Digest != target.Digest || state != target.StateRevision || epoch != target.Binding.RecoveryEpoch {
			return discoveryError(generated.ErrorCodeStateConflict)
		}
		return nil
	})
}

// Fail records only a stable code. It cannot publish facts or grant authority.
func (r *HostDiscoveryRepository) Fail(ctx context.Context, attempt hostdiscovery.Attempt, code string, attribution audit.Attribution) error {
	if _, known := generated.ErrorExitCodes[code]; !known {
		return discoveryError(generated.ErrorCodeInputInvalid)
	}
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok || p.ID != attempt.PrincipalID || p.ID != attribution.AuthenticatedPrincipalID {
		return discoveryError(generated.ErrorCodeAuthorizationDenied)
	}
	intent := discoveryIntent(attribution, "host.discovery.failed", attempt.ID, hostdiscovery.Digest(attempt.ID), hostdiscovery.Digest([]string{attempt.ID, code}))
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		var principal, digest string
		if err := tx.QueryRowContext(ctx, `SELECT principal_id,request_digest FROM host_discovery_attempts WHERE attempt_id=?`, attempt.ID).Scan(&principal, &digest); err != nil {
			return err
		}
		if principal != p.ID || digest != hostdiscovery.Digest(attempt.Request) {
			return discoveryError(generated.ErrorCodeAuthorizationDenied)
		}
		var completed int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_observations WHERE observation_id=?`, attempt.ID).Scan(&completed); err != nil {
			return err
		}
		if completed != 0 {
			return discoveryError(generated.ErrorCodeStateConflict)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO host_discovery_failures VALUES(?,?)`, attempt.ID, code)
		return err
	})
	return err
}
