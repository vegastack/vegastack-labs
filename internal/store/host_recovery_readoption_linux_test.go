//go:build linux

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
)

// This owning store fixture uses the real recovery authority transition. Only
// ordinary discovery/plan/run responses are seeded, as in registration tests.
func recoveredRegistration(t *testing.T) (*registrationStoreFixture, HostAdoptionDraft, HostAdoptionApply) {
	t.Helper()
	f := newRegistrationStoreFixture(t)
	original := f.Stage(t)
	applied := f.bind(t, original)
	if _, err := f.repo.Apply(f.ctx, applied); err != nil {
		t.Fatal(err)
	}
	promoteRecoveryArtifactStore(t, f.s)
	return f, original, applied
}

func recoveryAdoptionExec(t *testing.T, f *registrationStoreFixture, q string, args ...any) {
	t.Helper()
	if _, err := f.s.conn.ExecContext(f.ctx, q, args...); err != nil {
		t.Fatal(err)
	}
}

func freshRecoveryObservation(t *testing.T, f *registrationStoreFixture, change func(*generated.HostDiscoveryTarget, *generated.HostObservation)) {
	t.Helper()
	var raw []byte
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT canonical_bytes FROM host_discovery_drafts WHERE draft_id='fixture-target'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var draft generated.HostDiscoveryTargetDraftRequest
	if err := json.Unmarshal(raw, &draft); err != nil {
		t.Fatal(err)
	}
	authority, err := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	draft.Target.Revision = 2
	draft.Target.RecoveryEpoch = authority.RecoveryEpoch
	draft.ExpectedStateRevision = authority.StateRevision
	draft.ExpectedTargetRevision = 1
	draft.IdempotencyKey = "recovery-target"
	var obs generated.HostObservation
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT canonical_bytes FROM host_observations WHERE observation_id='fixture-observation'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &obs); err != nil {
		t.Fatal(err)
	}
	obs.ObservationID = "recovery-observation"
	obs.TargetRevision = 2
	obs.RecoveryEpoch = authority.RecoveryEpoch
	obs.StateRevision = authority.StateRevision
	if change != nil {
		change(&draft.Target, &obs)
	}
	raw, _ = json.Marshal(draft)
	td := hostdiscovery.Digest(draft)
	recoveryAdoptionExec(t, f, `INSERT INTO host_discovery_drafts VALUES('recovery-target',?,2,1,'activate',?,?,'operator-a',?,?)`, draft.Target.TargetID, td, raw, authority.StateRevision, authority.RecoveryEpoch)
	recoveryAdoptionExec(t, f, `INSERT INTO host_discovery_targets VALUES(?,2,'recovery-target','active','fixture-plan',?)`, draft.Target.TargetID, authority.RecoveryEpoch)
	obs.TargetID = draft.Target.TargetID
	obs.TargetDigest = td
	obs.ContentDigest = ""
	obs.ContentDigest = hostdiscovery.Digest(obs)
	raw, _ = json.Marshal(obs)
	recoveryAdoptionExec(t, f, `INSERT INTO host_discovery_attempts VALUES('recovery-observation','operator-a',?, ?,?,2,?,1,?,?,'later',?)`, td, td, obs.TargetID, td, authority.StateRevision, authority.RecoveryEpoch, []byte(`{}`))
	recoveryAdoptionExec(t, f, `INSERT INTO host_observations VALUES('recovery-observation',?,2,?,?,?,?)`, obs.TargetID, raw, hostdiscovery.Digest(obs), authority.StateRevision, authority.RecoveryEpoch)
	f.request.ObservationID = obs.ObservationID
	f.request.ObservationDigest = obs.ContentDigest
	f.request.Confirmation.TargetRevision = 2
	f.request.Confirmation.TargetDigest = td
	f.request.RecoveryEpoch = authority.RecoveryEpoch
	f.request.ExpectedStateRevision = authority.StateRevision
	f.request.IdempotencyKey = "recovery-adopt"
}

func bindRecoveryAdoption(t *testing.T, f *registrationStoreFixture, d HostAdoptionDraft) HostAdoptionApply {
	t.Helper()
	id := d.ID
	hash := hostdiscovery.Digest(id)
	planID := "plan-" + id
	runID := "run-" + id
	stepID := "step-" + id
	leaseID := "lease-" + id
	ackID := "ack-" + id
	a, err := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := generated.Plan{PlanID: planID, PlanDigest: hash, AuthorizationBranch: "human", ExecutorMode: "central", Risk: "control-plane", HostAdoption: &d.Request, Operations: []generated.PlanOperation{{OperationType: "host.adopt", AdapterID: "core.host-adoption", TargetID: id, InputDigest: d.Digest, ArtifactDigest: d.Digest}}}
	raw, _ := json.Marshal(p)
	recoveryAdoptionExec(t, f, `INSERT INTO immutable_plans VALUES(?,?,'fixture-declaration',1,?,?,?,?,?,?,?,?, '2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, planID, hash, a.StateRevision, a.RecoveryEpoch, hash, hash, hash, raw, "fixture", hash)
	recoveryAdoptionExec(t, f, `INSERT INTO acknowledgement_requests VALUES(?,?,?,?,?,'operator-a','fixture-authority',?, ?,?,'later','approved',?,?,'now','now','now')`, ackID, planID, hash, hash, hash, hash, a.StateRevision, a.RecoveryEpoch, []byte(`{}`), []byte(`{}`))
	recoveryAdoptionExec(t, f, `INSERT INTO plan_runs VALUES(?,?,?,'decision',?,'1.0.0','central','executor',?,'running',0,'not-requested','pending',NULL,0,?,?, ?,?,?,'now','now')`, runID, planID, hash, ackID, hash, a.StateRevision, a.RecoveryEpoch, hash, hash, []byte(`{}`))
	recoveryAdoptionExec(t, f, `INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,result_digest,started_at,finished_at) VALUES(?,?,1,'adopt','host.adopt','core.host-adoption','executor',?,?,?,1,'running','intent-recorded',?,NULL,'now',NULL)`, stepID, runID, id, d.Digest, d.Digest, leaseID)
	recoveryAdoptionExec(t, f, `INSERT INTO target_execution_leases (lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES(?,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z',?,'later','active',?)`, leaseID, runID, stepID, id, hash, hash, a.RecoveryEpoch, f.s.config.Clock().Add(time.Hour).UTC().Format(time.RFC3339), []byte(`{}`))
	_, err = f.s.executeAuditIntent(f.ctx, discoveryIntent(f.attr, "run.created", runID, hash, hash), false, func(context.Context, *sql.Tx) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return HostAdoptionApply{DraftID: id, PlanID: planID, PlanDigest: hash, RunID: runID, StepID: stepID, LeaseID: leaseID, Attribution: f.attr}
}

func TestHostRecoveryReadoptionRefreshesOnlyRegistration(t *testing.T) {
	f, original, oldApply := recoveredRegistration(t)
	oldDraft, err := f.repo.GetDraft(f.ctx, original.ID)
	if err != nil {
		t.Fatal(err)
	}
	freshRecoveryObservation(t, f, nil)
	d := f.Stage(t)
	b := bindRecoveryAdoption(t, f, d)
	h, err := f.repo.Apply(f.ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if h.HostID != original.Request.HostID || h.RecoveryEpoch != 1 || h.ObservationID != f.request.ObservationID || h.Status != "adopted-unadmitted" || f.CountHosts(t) != 1 {
		t.Fatalf("registration=%#v", h)
	}
	if err := f.repo.Verify(f.ctx, d.ID, b.PlanID, d.Digest); err != nil {
		t.Fatal(err)
	}
	again, err := f.repo.Apply(f.ctx, b)
	if err != nil || again != h {
		t.Fatal("exact replay differed", err)
	}
	retained, err := f.repo.GetDraft(f.ctx, original.ID)
	if err != nil || retained.Digest != oldDraft.Digest || retained.Request != oldDraft.Request {
		t.Fatal("prior draft changed", err)
	}
	var n int
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM audit_events WHERE event_type='host.adoption.applied'`).Scan(&n); err != nil || n != 2 {
		t.Fatal("missing immutable history", n, err)
	}
	if _, err := f.repo.Apply(f.ctx, oldApply); err == nil {
		t.Fatal("old epoch apply accepted")
	}
	admission, err := NewGateRepository(f.s).ResolveHostAdmission(f.ctx, h.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if len(admission.Measurements) != 0 || len(admission.Evidence) != 0 || len(admission.Blockers) == 0 {
		t.Fatal("registration carried admission evidence")
	}
	for _, q := range []string{`UPDATE managed_hosts SET profile_id='changed'`, `DELETE FROM managed_hosts`, `UPDATE host_adoption_drafts SET principal_id='changed'`, `DELETE FROM host_adoption_drafts`} {
		if _, err := f.s.conn.ExecContext(f.ctx, q); err == nil {
			t.Fatal("history/identity guard bypassed")
		}
	}
	f.request.IdempotencyKey = "duplicate-current-epoch"
	if _, err := f.repo.StageDraft(f.ctx, f.request, f.attr); err == nil {
		t.Fatal("same-epoch duplicate accepted")
	}
}

func TestHostRecoveryReadoptionDenials(t *testing.T) {
	for _, mode := range []string{"identity", "class", "address", "host-key", "credential", "profile", "unverified", "frozen-stage", "frozen-apply", "ack", "lease", "audit"} {
		t.Run(mode, func(t *testing.T) {
			f, original, _ := recoveredRegistration(t)
			freshRecoveryObservation(t, f, func(target *generated.HostDiscoveryTarget, obs *generated.HostObservation) {
				switch mode {
				case "address":
					target.Address = "192.0.2.99"
				case "host-key":
					target.HostKey = target.HostKey + " changed-comment"
				case "credential":
					target.MaterialVersion = "different"
				case "profile":
					target.ProfileID = "other-profile"
				}
			})
			switch mode {
			case "identity":
				f.request.Confirmation.IdentityDigest = hostdiscovery.Digest("changed")
			case "class":
				f.request.Confirmation.IdentityClass = "qualified-virtual"
			case "unverified":
				recoveryAdoptionExec(t, f, `UPDATE system_meta SET instance_id='instance-uninitialized' WHERE id=1`)
			case "frozen-stage":
				freezeRecoveryHost(t, f)
			}
			if mode == "identity" || mode == "class" || mode == "address" || mode == "host-key" || mode == "credential" || mode == "profile" || mode == "unverified" || mode == "frozen-stage" {
				if _, err := f.repo.StageDraft(f.ctx, f.request, f.attr); err == nil {
					t.Fatal("invalid recovered draft accepted")
				}
			} else {
				d := f.Stage(t)
				b := bindRecoveryAdoption(t, f, d)
				switch mode {
				case "frozen-apply":
					freezeRecoveryHost(t, f)
				case "ack":
					recoveryAdoptionExec(t, f, `UPDATE effective_authorization_grants SET status='revoked' WHERE action='acknowledge'`)
				case "lease":
					b.LeaseID = "wrong"
				case "audit":
					recoveryAdoptionExec(t, f, `CREATE TRIGGER recovered_adoption_audit_fail BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fixture audit fault'); END`)
				}
				if _, err := f.repo.Apply(f.ctx, b); err == nil {
					t.Fatal("invalid recovered apply accepted")
				}
			}
			var epoch int64
			var draft string
			if err := f.s.conn.QueryRowContext(f.ctx, `SELECT recovery_epoch,draft_id FROM managed_hosts WHERE host_id=?`, original.Request.HostID).Scan(&epoch, &draft); err != nil || epoch != 0 || draft != original.ID {
				t.Fatal("denial changed prior registration", err)
			}
		})
	}
}

func freezeRecoveryHost(t *testing.T, f *registrationStoreFixture) {
	t.Helper()
	d := hostdiscovery.Digest("freeze")
	recoveryAdoptionExec(t, f, `INSERT INTO host_replacement_events VALUES('fixture-freeze',1,'frozen','synthetic-host',?,'replacement-host',?,?,?,?,1)`, f.request.Confirmation.IdentityDigest, d, d, []byte(`{}`), f.request.ExpectedStateRevision)
}
