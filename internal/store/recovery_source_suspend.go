package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// SuspendRecoverySource makes the former authority read-only after an actual
// verified receive. It preserves its identity, epoch and complete database.
// It does not enable the successor or replace the ordinary former-writer fence.
func (s *Store) SuspendRecoverySource(ctx context.Context, b generated.HostActionBundle, d generated.ControlRecoveryReceiveInput, result generated.HostActionResult) error {
	deny := func() error {
		return newStoreError(generated.ErrorCodePrerequisiteBlocked, "recovery-source-suspension", false, nil)
	}
	raw, e := json.Marshal(d)
	if s == nil || e != nil || generated.ValidateContractJSON(generated.SchemaIDControlRecoveryReceiveInput, raw, generated.ContractExact) != nil || b.ActionID != "debian.control.recovery-receive" || b.ActionInput != string(raw) || b.ActionInputDigest != hostaction.BytesDigest(raw) || result.BundleDigest != hostaction.Digest(b) || hostaction.ValidateResult(result) != nil || result.ResultDigest != hostaction.ResultDigest(result) || result.Status != "succeeded" || !result.Changed || d.Binding.ReplacementContinuity == nil {
		return deny()
	}
	x, e := NewHostActionRepository(s).ExecutionForBundle(ctx, b)
	if e != nil {
		return e
	}
	if x.Draft.Request.ActionID != b.ActionID || x.Draft.Request.ActionVersion != b.ActionVersion || x.Draft.Request.HostID != b.HostID || x.Draft.Request.ConsoleConfirmation.HostIdentityDigest != b.HostIdentityDigest || x.Draft.Request.AutomationPrincipalID != b.AutomationPrincipalID || x.Draft.Request.CredentialReferenceID != b.CredentialReferenceID || x.Draft.Request.CredentialMaterialVersion != b.CredentialMaterialVersion || x.Draft.Request.ActionInput != b.ActionInput || x.Draft.Request.ActionInputDigest != b.ActionInputDigest || x.Draft.Request.HostID != d.Replacement.NewHostID {
		return deny()
	}
	attribution, e := s.HostAccessRunAttribution(ctx, b.RunID)
	if e != nil {
		return e
	}
	digest := audit.Fingerprint(hostaction.Digest(struct {
		Bundle     generated.HostActionBundle
		Descriptor generated.ControlRecoveryReceiveInput
		Result     generated.HostActionResult
	}{b, d, result}))
	expected := RevisionToken{StateRevision: b.StateRevision, RecoveryEpoch: b.RecoveryEpoch}
	request := intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "recovery-source-suspension", KeyDigest: digestParts("recovery-source-suspension", b.RunID, b.StepID, b.LeaseID), RequestDigest: digest}, Event: audit.EventDraft{Type: "recovery.source-suspended", CorrelationID: b.RunID, Attribution: attribution, Target: audit.Target{Kind: "run", ID: b.RunID}, After: &digest}}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e = s.readyForTransaction(ctx); e != nil {
		return e
	}
	tx, e := s.conn.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	committed, e := s.appendAuditInTx(ctx, tx, request, false, func(ctx context.Context, tx *sql.Tx) error {
		var instance, mode string
		var epoch, revision int64
		if tx.QueryRowContext(ctx, `SELECT instance_id,recovery_epoch,state_revision,authority_mode FROM system_meta WHERE id=1`).Scan(&instance, &epoch, &revision, &mode) != nil || instance != d.Binding.PriorInstanceID || epoch != d.Binding.PriorRecoveryEpoch || epoch != b.RecoveryEpoch || revision != b.StateRevision || mode != "ready" {
			return deny()
		}
		row := func(query string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, query, args...) }
		actorContext, err := hostRunReadContext(ctx, row, b.RunID)
		if err != nil {
			return err
		}
		if err = validateRecoveryReceiveContinuity(actorContext, ReadTx{handle: tx}, d.Binding); err != nil {
			return err
		}
		var pending []byte
		var database, journal, bundle string
		rows, e := tx.QueryContext(ctx, `SELECT s.binding_bytes,c.database_digest,c.journal_digest,c.bundle_digest FROM recovery_candidates c JOIN restore_sessions s ON s.plan_id=c.plan_id WHERE (SELECT t.to_status FROM restore_transitions t WHERE t.plan_id=c.plan_id ORDER BY t.transition_id DESC LIMIT 1)='verification-required' LIMIT 2`)
		if e != nil {
			return e
		}
		if !rows.Next() {
			rows.Close()
			return deny()
		}
		e = rows.Scan(&pending, &database, &journal, &bundle)
		extra := rows.Next()
		rows.Close()
		want, _ := json.Marshal(d.Binding)
		if e != nil || extra || !bytes.Equal(pending, want) || database != d.DatabaseDigest || journal != d.JournalDigest || bundle != d.BundleDigest {
			return deny()
		}
		var human string
		if tx.QueryRowContext(ctx, `SELECT a.human_id FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.plan_digest=r.plan_digest AND a.recovery_epoch=r.recovery_epoch AND s.step_id=? AND s.active_lease_id=? AND s.status='running' AND s.effect_state='intent-recorded' AND l.status='active' AND l.expires_at>?`, b.RunID, b.PlanID, b.PlanDigest, b.StepID, b.LeaseID, s.config.Clock().UTC().Format("2006-01-02T15:04:05Z")).Scan(&human) != nil {
			return deny()
		}
		for _, g := range []struct{ id, action, cap, kind string }{{human, "acknowledge", "plan.acknowledge", "plan-target"}, {attribution.AuthenticatedPrincipalID, "execute", "host.action.execute", "execution-target"}, {x.Draft.Request.AutomationPrincipalID, "execute", "host.action.execute", "execution-target"}} {
			var count int
			if tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.status='active' AND g.status='active' AND g.branch='human' AND g.action=? AND g.capability=? AND g.resource_kind=? AND g.resource_id=? AND (?!='acknowledge' OR (p.principal_kind='human' AND g.role_id IN ('infrastructure-admin','control-plane-admin')))`, g.id, g.action, g.cap, g.kind, b.HostID, g.action).Scan(&count) != nil || count == 0 {
				return deny()
			}
		}
		changed, e := tx.ExecContext(ctx, `UPDATE system_meta SET authority_mode='recovery-required' WHERE id=1 AND instance_id=? AND recovery_epoch=? AND state_revision=? AND authority_mode='ready'`, instance, epoch, revision)
		if e != nil {
			return e
		}
		n, _ := changed.RowsAffected()
		if n != 1 {
			return deny()
		}
		return nil
	})
	if e != nil {
		return e
	}
	if e = s.checkIdentity(ctx); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		s.enterSafeMode("recovery-source-suspension-uncertain")
		return e
	}
	s.health.RecoveryPending = true
	s.health.MutationEnabled = false
	if committed.Created {
		s.events.signal()
	}
	return nil
}
