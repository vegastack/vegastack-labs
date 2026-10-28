package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"slices"
)

func bootstrapDependencies(row discoveryRow, c generated.IngressChange, epoch int64) error {
	ids := map[string]string{}
	for _, runID := range c.Bootstrap.SourceRunIDs {
		var action, id, scope, status string
		if row(`SELECT action,resource_id,scope_digest,status FROM ingress_bootstrap_receipts WHERE run_id=? AND profile_id=? AND recovery_epoch=? AND EXISTS(SELECT 1 FROM plan_runs r WHERE r.run_id=ingress_bootstrap_receipts.run_id AND r.status='succeeded')`, runID, c.ProfileID, epoch).Scan(&action, &id, &scope, &status) != nil || scope != ingress.BootstrapScopeDigest(c) || status != "observed" || id == "" || ids[action] != "" || !slices.Contains(ingress.BootstrapNeeds(c.Action), action) {
			return ingressError(generated.ErrorCodePrerequisiteBlocked)
		}
		ids[action] = id
	}
	for _, action := range ingress.BootstrapNeeds(c.Action) {
		if ids[action] == "" {
			return ingressError(generated.ErrorCodePrerequisiteBlocked)
		}
	}
	if c.TunnelID != ids["bootstrap-tunnel"] || c.AccessAppID != ids["bootstrap-app"] || c.AccessPolicyID != ids["bootstrap-policy"] {
		return ingressError(generated.ErrorCodeAuthorizationDenied)
	}
	if group := ids["bootstrap-group"]; group != "" {
		if len(c.AllowedGroupIDs) != 1 || c.AllowedGroupIDs[0] != group {
			return ingressError(generated.ErrorCodeAuthorizationDenied)
		}
	} else if len(c.AllowedGroupIDs) != 0 {
		return ingressError(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}

// ReserveBootstrap is durable before the single provider write. Unknown completion
// requires scoped reconciliation; a later plan cannot issue a second create.
func (r *IngressRepository) ReserveBootstrap(ctx context.Context, d ingress.Staged, b adapter.ExactExecutionBinding, before ingress.Snapshot) error {
	if !ingress.IsBootstrap(d.Request.Change) {
		return ingressError(generated.ErrorCodeInputInvalid)
	}
	if e := r.CheckCurrent(ctx, d); e != nil {
		return e
	}

	op := adapter.Operation{OperationID: ingress.OperationID, OperationType: "network.ingress." + d.Request.Change.Action, AdapterID: ingress.AdapterID, TargetID: d.Request.Change.ProfileID, InputDigest: credentialref.OperationManifestDigest(d.Bindings, ingress.OperationID), ArtifactDigest: d.Digest}
	current, e := r.Resolve(ctx, op, b)
	if e != nil || current.Digest != d.Digest {
		return ingressError(generated.ErrorCodeApprovalRequired)
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return ingressError(generated.ErrorCodeIntegrityFailure)
	}
	a, e := r.store.HostAccessRunAttribution(ctx, b.RunID)
	if e != nil {
		return e
	}
	key := ingress.Digest([]string{b.RunID, b.StepID, "bootstrap-reserve", hex.EncodeToString(nonce[:])})
	intent := discoveryIntent(a, "ingress.bootstrap-reserved", d.ID, key, d.Digest)
	_, e = r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(s string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, s, a...) }
		if e := bootstrapDependencies(row, d.Request.Change, b.RecoveryEpoch); e != nil {
			return e
		}
		c := d.Request.Change
		_, e := tx.ExecContext(ctx, `INSERT INTO ingress_bootstrap_receipts VALUES(?,?,?,?,?,?,'pending','','',?,?,?)`, c.ProfileID, c.Action, b.RecoveryEpoch, ingress.BootstrapScopeDigest(c), b.RunID, d.ID, c.BeforeDigest, before.DNSContent, before.DNSProxied)
		if e != nil {
			return ingressError(generated.ErrorCodeStateConflict)
		}
		return nil
	})
	return e
}
func recordBootstrapReceipt(ctx context.Context, tx *sql.Tx, d ingress.Staged, b adapter.ExactExecutionBinding, s ingress.Snapshot, status string) error {
	if status != "observed" {
		status = "partial"
	}
	c := d.Request.Change
	// Existing Resolve verifies this exact run/lease/ack at execution and verification.
	var exact int
	if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND s.step_id=? AND s.artifact_digest=? AND l.lease_id=? AND l.status='active' AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=?`, b.RunID, b.PlanID, b.PlanDigest, b.StepID, d.Digest, b.LeaseID, b.RecoveryEpoch).Scan(&exact) != nil || exact != 1 {
		return ingressError(generated.ErrorCodeApprovalRequired)
	}
	var currentState, currentEpoch int64
	if tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentState, &currentEpoch) != nil || currentEpoch != b.RecoveryEpoch || (status == "observed" && currentState != b.StateRevision) {
		return ingressError(generated.ErrorCodePlanStale)
	}

	res, e := tx.ExecContext(ctx, `UPDATE ingress_bootstrap_receipts SET status=?,resource_id=?,result_digest=? WHERE run_id=? AND draft_id=? AND scope_digest=? AND status='pending' AND recovery_epoch=?`, status, s.ResourceID, s.Digest, b.RunID, d.ID, ingress.BootstrapScopeDigest(c), b.RecoveryEpoch)
	if e != nil {
		return e
	}
	n, e := res.RowsAffected()
	if e != nil || n != 1 {
		return ingressError(generated.ErrorCodeStateConflict)
	}
	return nil
}
func (r *IngressRepository) CheckBootstrapUnattempted(ctx context.Context, c generated.IngressChange, epoch int64) error {
	return r.store.Read(ctx, func(tx ReadTx) error {
		var id string
		e := tx.queryRow(ctx, `SELECT run_id FROM ingress_bootstrap_receipts WHERE profile_id=? AND action=? AND recovery_epoch=?`, c.ProfileID, c.Action, epoch).Scan(&id)
		if errors.Is(e, sql.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		return ingressError(generated.ErrorCodeStateConflict)
	})
}

// BootstrapResource exposes only a successful exact-scope nonsecret ID. Host
// preparation uses this receipt rather than guessing a provider-created tunnel.
func (r *IngressRepository) BootstrapResource(ctx context.Context, profile, action string, epoch int64) (id string, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(s string, a ...any) *sql.Row { return tx.queryRow(ctx, s, a...) }
		if _, e := ingressGrant(ctx, row, profile, "read"); e != nil {
			return e
		}
		var scope string
		if e := row(`SELECT resource_id,scope_digest FROM ingress_bootstrap_receipts WHERE profile_id=? AND action=? AND recovery_epoch=? AND status='observed' AND EXISTS(SELECT 1 FROM plan_runs r WHERE r.run_id=ingress_bootstrap_receipts.run_id AND r.status='succeeded')`, profile, action, epoch).Scan(&id, &scope); e != nil || id == "" || !slices.Contains(r.allowed, scope) {
			return ingressError(generated.ErrorCodePrerequisiteBlocked)
		}
		var current int64
		if row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&current) != nil || current != epoch {
			return ingressError(generated.ErrorCodeRecoveryEpochMismatch)
		}
		return nil
	})
	return
}
