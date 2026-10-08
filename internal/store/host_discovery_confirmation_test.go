package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"testing"
	"time"
)

// These repository tests deliberately seed persisted engine records to challenge
// the transaction boundary. Full API/engine acceptance uses no such seeding.
func TestConfirmedDiscoveryTransactionAuthorization(t *testing.T) {
	for _, mode := range []string{"valid", "missing-ack", "unconsumed-ack", "wrong-ack", "embedded-confirmation", "input-binding", "unknown-operation", "revoked-human", "revoked-executor", "malformed-expiry", "expired-plan"} {
		t.Run(mode, func(t *testing.T) {
			f := newRegistrationStoreFixture(t)
			target := discoveryFixtureTarget(t)
			target.TargetID = "confirmed-target"
			credentialMode, keyDigest := "preloaded-discovery", hostdiscovery.Digest("public")
			target.CredentialMode = &credentialMode
			target.CredentialPublicKeyDigest = &keyDigest
			req := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "confirmed", ConsoleConfirmation: &generated.HostDiscoveryConsoleConfirmation{Schema: generated.SchemaIDHostDiscoveryConsoleConfirmation, SchemaVersion: "1.0.0", TargetDigest: hostdiscovery.Digest(target), Method: "administrator-verified-console"}}
			d := DiscoveryDraft{ID: "confirmed-draft", Digest: hostdiscovery.Digest(req), Request: req}
			raw, _ := json.Marshal(req)
			if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO host_discovery_drafts VALUES(?,?,1,0,'activate',?,?,'operator-a',1,0)`, d.ID, target.TargetID, d.Digest, raw); err != nil {
				t.Fatal(err)
			}
			activation := bindConfirmedDiscovery(t, f, d, mode)
			if mode == "revoked-human" || mode == "revoked-executor" {
				action := "acknowledge"
				if mode == "revoked-executor" {
					action = "execute"
				}
				if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE action=?`, action); err != nil {
					t.Fatal(err)
				}
			}
			var before int64
			_ = f.s.conn.QueryRowContext(f.ctx, `SELECT state_revision FROM system_meta`).Scan(&before)
			_, err := NewHostDiscoveryRepository(f.s).ApplyTarget(f.ctx, activation)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("apply %s: %v", mode, err)
			}
			if (mode == "expired-plan" || mode == "malformed-expiry") && Code(err) != generated.ErrorCodePlanStale {
				t.Fatalf("expiry denial code=%v", err)
			}
			var count int
			if err := f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM host_discovery_targets WHERE target_id=?`, target.TargetID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if (count == 1) != (mode == "valid") {
				t.Fatalf("persisted targets=%d", count)
			}
			if mode == "revoked-human" || mode == "revoked-executor" {
				var after int64
				_ = f.s.conn.QueryRowContext(f.ctx, `SELECT state_revision FROM system_meta`).Scan(&after)
				if before != after || Code(err) != generated.ErrorCodeAuthorizationDenied {
					t.Fatalf("revocation masked by revision drift: %v %d/%d", err, before, after)
				}
			}
		})
	}
}
func bindConfirmedDiscovery(t *testing.T, f *registrationStoreFixture, d DiscoveryDraft, modes ...string) DiscoveryActivation {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.s.conn.ExecContext(f.ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	id := d.ID
	hash := hostdiscovery.Digest(id)
	planID := "plan-" + id
	runID := "run-" + id
	stepID := "step-" + id
	leaseID := "lease-" + id
	ackID := "ack-" + id
	p := generated.Plan{ExpiresAt: f.s.config.Clock().Add(time.Minute).UTC().Format(time.RFC3339), PlanID: planID, PlanDigest: hash, AuthorizationBranch: "human", ExecutorMode: "central", Risk: "control-plane", HostDiscoveryTarget: &d.Request, Operations: []generated.PlanOperation{{OperationType: "host.discovery-target.activate", AdapterID: "core.host-discovery-target", TargetID: id, InputDigest: d.Digest, ArtifactDigest: d.Digest}}}
	mode := ""
	if len(modes) > 0 {
		mode = modes[0]
	}
	consumed := any("now")
	runAck := any(ackID)
	ackDigest := hash
	switch mode {
	case "malformed-expiry":
		p.ExpiresAt = "invalid"
	case "expired-plan":
		p.ExpiresAt = f.s.config.Clock().UTC().Format(time.RFC3339)
	case "missing-ack":
		runAck = nil
	case "unconsumed-ack":
		consumed = nil
	case "wrong-ack":
		ackDigest = hostdiscovery.Digest("wrong-plan")
	case "embedded-confirmation":
		copy := d.Request
		confirmation := *copy.ConsoleConfirmation
		confirmation.TargetDigest = hostdiscovery.Digest("wrong-target")
		copy.ConsoleConfirmation = &confirmation
		p.HostDiscoveryTarget = &copy
	case "input-binding":
		p.Operations[0].InputDigest = hostdiscovery.Digest("wrong-input")
	case "unknown-operation":
		p.Operations[0].OperationType = "host.unknown"
	}
	raw, _ := json.Marshal(p)
	exec(`INSERT INTO immutable_plans VALUES(?,?,'fixture-declaration',1,1,0,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, planID, hash, hash, hash, hash, raw, "fixture", hash)
	exec(`INSERT INTO acknowledgement_requests VALUES(?,?,?,?,?,'operator-a','fixture-authority',?,0,0,'later','approved',?,?,'now','now',?)`, ackID, planID, ackDigest, hash, hash, hash, []byte(`{}`), []byte(`{}`), consumed)
	exec(`INSERT INTO plan_runs VALUES(?,?,?,'decision',?,'1.0.0','central','executor',?,'running',0,'not-requested','pending',NULL,0,0,0,?,?,?,'now','now')`, runID, planID, hash, runAck, hash, hash, hash, []byte(`{}`))
	exec(`INSERT INTO plan_run_steps VALUES(?,?,1,'adopt','host.discovery-target.activate','core.host-discovery-target','executor',?,?,?,1,'running','intent-recorded',?,NULL,'now',NULL)`, stepID, runID, id, d.Digest, d.Digest, leaseID)
	exec(`INSERT INTO target_execution_leases (lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES(?,?,?,?,?,?,0,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z',?,'later','active',?)`, leaseID, runID, stepID, id, hash, hash, f.s.config.Clock().Add(time.Hour).UTC().Format(time.RFC3339), []byte(`{}`))
	for _, v := range []struct{ action, cap, kind string }{{"acknowledge", "plan.acknowledge", "plan-target"}, {"execute", "host.discovery-target.activate", "execution-target"}} {
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,'human',1,'active','now','now')`, v.action+id, v.action, v.cap, v.kind, id)
	}
	_, err := f.s.executeAuditIntent(f.ctx, discoveryIntent(f.attr, "run.created", runID, hash, hash), false, func(context.Context, *sql.Tx) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return DiscoveryActivation{DraftID: id, PlanID: planID, PlanDigest: hash, RunID: runID, StepID: stepID, LeaseID: leaseID, Attribution: f.attr}
}
