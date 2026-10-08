package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
	"time"
)

type registrationStoreFixture struct {
	s       *Store
	repo    *HostAdoptionRepository
	ctx     context.Context
	request generated.HostAdoptionRequest
	attr    audit.Attribution
}

func newRegistrationStoreFixture(t *testing.T) *registrationStoreFixture {
	t.Helper()
	s := portableDiscoveryStore(t)
	ctx := discoveryPrincipalContext()
	discoveryFixtureGrant(t, s)
	p, _ := identity.PrincipalFromContext(ctx)
	a, _ := audit.NewAttribution(p, &p, nil)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.conn.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	target := discoveryFixtureTarget(t)
	target.ProfileID = "debian-13-amd64"
	dr := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "fixture-target"}
	raw, _ := json.Marshal(dr)
	digest := hostdiscovery.Digest(dr)
	exec(`INSERT INTO host_discovery_drafts VALUES('fixture-target','candidate-a',1,0,'activate',?,?,'operator-a',0,0)`, digest, raw)
	hash := hostdiscovery.Digest("fixture")
	exec(`INSERT INTO declaration_revisions VALUES('fixture-declaration',1,'host.discovery-target',0,0,?,?,'draft',?,'now','operator-a','session-a')`, hash, hash, []byte(`{}`))
	exec(`INSERT INTO immutable_plans VALUES('fixture-plan',?,'fixture-declaration',1,1,0,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, hash, hash, hash, hash, []byte(`{}`), "fixture", hash)
	exec(`INSERT INTO host_discovery_targets VALUES('candidate-a',1,'fixture-target','active','fixture-plan',0)`)
	now := s.config.Clock().UTC().Truncate(time.Second)
	facts := []generated.HostDiscoveryFact{}
	for _, v := range []struct{ n, v, o string }{{"os.id", "debian", "os-release"}, {"os.version", "13", "os-release"}, {"architecture", "amd64", "architecture"}, {"product-serial", "synthetic-serial", "product-serial"}, {"product-uuid", "synthetic-uuid", "product-uuid"}, {"machine-id", "synthetic-machine", "machine-id"}} {
		f := hostdiscovery.Fact(v.n, v.v, v.o)
		f.CapturedAt = now.Format(time.RFC3339)
		facts = append(facts, f)
	}
	obs := generated.HostObservation{Schema: generated.SchemaIDHostObservation, SchemaVersion: "1.0.0", ObservationID: "fixture-observation", TargetID: target.TargetID, TargetRevision: 1, TargetDigest: digest, Collector: hostdiscovery.CollectorID, CollectorVersion: "1.0.0", ObservedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(15 * time.Minute).Format(time.RFC3339), Status: "incomplete", Facts: facts, Blockers: []string{"hardening-unverified", "role-admission-unverified", "identity-class-unverified"}}
	obs.ContentDigest = hostdiscovery.Digest(obs)
	raw, _ = json.Marshal(obs)
	exec(`INSERT INTO host_discovery_attempts VALUES('fixture-observation','operator-a',?,?,'candidate-a',1,?,1,0,0,'later',?)`, hash, hash, digest, []byte(`{}`))
	exec(`INSERT INTO host_observations VALUES('fixture-observation','candidate-a',1,?,?,0,0)`, raw, hostdiscovery.Digest(obs))
	exec(`INSERT INTO effective_authorization_grants VALUES('adoption-grant','operator-a','control-plane-admin','author','host.adoption.prepare','host-discovery-target','candidate-a',NULL,1,'active','now','now')`)
	exec(`INSERT INTO effective_authorization_grants VALUES('host-read','operator-a','control-plane-admin','read','host.read','host','synthetic-host',NULL,1,'active','now','now')`)
	req := generated.HostAdoptionRequest{Schema: generated.SchemaIDHostAdoptionRequest, SchemaVersion: "1.0.0", HostID: "synthetic-host", ObservationID: obs.ObservationID, ObservationDigest: obs.ContentDigest, IdempotencyKey: "adopt-one", Confirmation: generated.HostIdentityConfirmation{Schema: generated.SchemaIDHostIdentityConfirmation, SchemaVersion: "1.0.0", TargetRevision: 1, TargetDigest: digest, IdentityClass: "physical", IdentityKind: "product-serial", IdentityDigest: hostadoption.IdentityDigest("product-serial", "synthetic-serial"), ConfirmedAt: now.Format(time.RFC3339)}}
	exec(`UPDATE system_meta SET state_revision=1 WHERE id=1`)
	req.ExpectedStateRevision = 1
	return &registrationStoreFixture{s: s, repo: NewHostAdoptionRepository(s), ctx: ctx, request: req, attr: a}
}
func (f *registrationStoreFixture) Stage(t *testing.T) HostAdoptionDraft {
	t.Helper()
	d, err := f.repo.StageDraft(f.ctx, f.request, f.attr)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func (f *registrationStoreFixture) CountHosts(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM managed_hosts`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func (f *registrationStoreFixture) bind(t *testing.T, d HostAdoptionDraft, modes ...string) HostAdoptionApply {
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
	p := generated.Plan{PlanID: planID, PlanDigest: hash, AuthorizationBranch: "human", ExecutorMode: "central", Risk: "control-plane", HostAdoption: &d.Request, Operations: []generated.PlanOperation{{OperationType: "host.adopt", AdapterID: "core.host-adoption", TargetID: id, InputDigest: d.Digest, ArtifactDigest: d.Digest}}}
	mode := ""
	if len(modes) > 0 {
		mode = modes[0]
	}
	consumed := any("now")
	runAck := any(ackID)
	ackDigest := hash
	switch mode {
	case "missing-ack":
		runAck = nil
	case "unconsumed-ack":
		consumed = nil
	case "wrong-ack":
		ackDigest = hostdiscovery.Digest("wrong-plan")
	case "embedded-confirmation":
		copy := d.Request
		copy.Confirmation.IdentityDigest = hostdiscovery.Digest("wrong-identity")
		p.HostAdoption = &copy
	case "input-binding":
		p.Operations[0].InputDigest = hostdiscovery.Digest("wrong-input")
	case "unknown-operation":
		p.Operations[0].OperationType = "host.unknown"
	}
	raw, _ := json.Marshal(p)
	exec(`INSERT INTO immutable_plans VALUES(?,?,'fixture-declaration',1,1,0,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, planID, hash, hash, hash, hash, raw, "fixture", hash)
	exec(`INSERT INTO acknowledgement_requests VALUES(?,?,?,?,?,'operator-a','fixture-authority',?,0,0,'later','approved',?,?,'now','now',?)`, ackID, planID, ackDigest, hash, hash, hash, []byte(`{}`), []byte(`{}`), consumed)
	exec(`INSERT INTO plan_runs VALUES(?,?,?,'decision',?,'1.0.0','central','executor',?,'running',0,'not-requested','pending',NULL,0,0,0,?,?,?,'now','now')`, runID, planID, hash, runAck, hash, hash, hash, []byte(`{}`))
	exec(`INSERT INTO plan_run_steps VALUES(?,?,1,'adopt','host.adopt','core.host-adoption','executor',?,?,?,1,'running','intent-recorded',?,NULL,'now',NULL)`, stepID, runID, id, d.Digest, d.Digest, leaseID)
	exec(`INSERT INTO target_execution_leases (lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES(?,?,?,?,?,?,0,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z',?,'later','active',?)`, leaseID, runID, stepID, id, hash, hash, f.s.config.Clock().Add(time.Hour).UTC().Format(time.RFC3339), []byte(`{}`))
	for _, v := range []struct{ action, cap, kind string }{{"acknowledge", "plan.acknowledge", "plan-target"}, {"execute", "host.adopt", "execution-target"}} {
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,'human',1,'active','now','now')`, v.action+id, v.action, v.cap, v.kind, id)
	}
	_, err := f.s.executeAuditIntent(f.ctx, discoveryIntent(f.attr, "run.created", runID, hash, hash), false, func(context.Context, *sql.Tx) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return HostAdoptionApply{DraftID: id, PlanID: planID, PlanDigest: hash, RunID: runID, StepID: stepID, LeaseID: leaseID, Attribution: f.attr}
}
func TestHostAdoptionDraftDoesNotRegister(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	d := f.Stage(t)
	if f.CountHosts(t) != 0 {
		t.Fatal("draft registered host")
	}
	b := f.bind(t, d)
	h, err := f.repo.Apply(f.ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if h.Status != "adopted-unadmitted" || f.CountHosts(t) != 1 {
		t.Fatal("incorrect host")
	}
	again, err := f.repo.Apply(f.ctx, b)
	if err != nil || again != h {
		t.Fatalf("replay: %v", err)
	}
	got, err := f.repo.Get(f.ctx, h.HostID)
	if err != nil || got != h {
		t.Fatal("read mismatch", err)
	}
	if err := f.repo.Verify(f.ctx, d.ID, b.PlanID, d.Digest); err != nil {
		t.Fatal(err)
	}
}
func TestHostAdoptionDenials(t *testing.T) {
	for _, mode := range []string{"grant", "human", "lease", "epoch", "revision", "expired", "audit", "target", "principal"} {
		t.Run(mode, func(t *testing.T) {
			f := newRegistrationStoreFixture(t)
			d := f.Stage(t)
			b := f.bind(t, d)
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := f.s.conn.ExecContext(f.ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "grant":
				exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.adoption.prepare'`)
			case "human":
				exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE action='acknowledge'`)
			case "lease":
				b.LeaseID = "wrong"
			case "epoch":
				exec(`UPDATE system_meta SET recovery_epoch=1 WHERE id=1`)
			case "revision":
				exec(`UPDATE system_meta SET state_revision=2 WHERE id=1`)
			case "expired":
				now := f.s.config.Clock()
				f.s.config.Clock = func() time.Time { return now.Add(time.Hour) }
			case "audit":
				exec(`CREATE TRIGGER adoption_audit_fail BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fixture audit fault'); END`)
			case "target":
				exec(`INSERT INTO host_discovery_targets VALUES('candidate-a',2,'fixture-target','revoked','fixture-plan',0)`)
			case "principal":
				b.Attribution.AuthenticatedPrincipalID = "other"
			}
			if _, err := f.repo.Apply(f.ctx, b); err == nil {
				t.Fatal("invalid apply accepted")
			}
			if f.CountHosts(t) != 0 {
				t.Fatal("failed apply committed host")
			}
		})
	}
}
func TestHostAdoptionReplayRechecksAuthority(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	d := f.Stage(t)
	b := f.bind(t, d)
	if _, err := f.repo.Apply(f.ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE action='acknowledge'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.Apply(f.ctx, b); err == nil {
		t.Fatal("replay skipped revoked human")
	}
}
func TestHostAdoptionDuplicateIdentity(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	d := f.Stage(t)
	b := f.bind(t, d)
	if _, err := f.repo.Apply(f.ctx, b); err != nil {
		t.Fatal(err)
	}
	f.request.HostID = "second-host"
	f.request.IdempotencyKey = "second-key"
	d2 := f.Stage(t)
	b2 := f.bind(t, d2)
	if _, err := f.repo.Apply(f.ctx, b2); err == nil {
		t.Fatal("duplicate target/identity allowed")
	}
	if f.CountHosts(t) != 1 {
		t.Fatal("duplicate persisted")
	}
}
func TestHostAdoptionStageReplayAndChangedKey(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	d := f.Stage(t)
	again := f.Stage(t)
	if fmt.Sprint(d) != fmt.Sprint(again) {
		t.Fatal("replay differed")
	}
	f.request.HostID = "different-host"
	if _, err := f.repo.StageDraft(f.ctx, f.request, f.attr); err == nil {
		t.Fatal("changed request reused key")
	}
}

func TestHostAdoptionConcurrentRegistrations(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	d1 := f.Stage(t)
	b1 := f.bind(t, d1)
	f.request.HostID = "second-host"
	f.request.IdempotencyKey = "second-key"
	d2 := f.Stage(t)
	b2 := f.bind(t, d2)
	results := make(chan error, 2)
	for _, b := range []HostAdoptionApply{b1, b2} {
		go func(b HostAdoptionApply) { _, err := f.repo.Apply(f.ctx, b); results <- err }(b)
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			successes++
		}
	}
	if successes != 1 || f.CountHosts(t) != 1 {
		t.Fatal("competing drafts did not select exactly one identity")
	}
}
func TestHostAdoptionReadGrantAndAppendOnly(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	d := f.Stage(t)
	b := f.bind(t, d)
	if _, err := f.repo.Apply(f.ctx, b); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE managed_hosts SET profile_id='other'`, `DELETE FROM managed_hosts`, `UPDATE host_adoption_drafts SET principal_id='other'`, `DELETE FROM host_adoption_drafts`} {
		if _, err := f.s.conn.ExecContext(f.ctx, q); err == nil {
			t.Fatal("immutable records changed")
		}
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.read'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.Get(f.ctx, "synthetic-host"); err == nil {
		t.Fatal("revoked read permitted")
	}
}

// Persist a second synthetic target/observation, keeping the original immutable.
func (f *registrationStoreFixture) otherObservation(t *testing.T, sharedKind string, index bool) generated.HostObservation {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.s.conn.ExecContext(f.ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	var raw []byte
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT canonical_bytes FROM host_discovery_drafts WHERE draft_id='fixture-target'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var target generated.HostDiscoveryTargetDraftRequest
	if err := json.Unmarshal(raw, &target); err != nil {
		t.Fatal(err)
	}
	target.Target.TargetID = "candidate-b"
	raw, _ = json.Marshal(target)
	digest := hostdiscovery.Digest(target)
	exec(`INSERT INTO host_discovery_drafts VALUES('second-target','candidate-b',1,0,'activate',?,?,'operator-a',1,0)`, digest, raw)
	exec(`INSERT INTO host_discovery_targets VALUES('candidate-b',1,'second-target','active','fixture-plan',0)`)
	var obs generated.HostObservation
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT canonical_bytes FROM host_observations WHERE observation_id='fixture-observation'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &obs); err != nil {
		t.Fatal(err)
	}
	obs.ObservationID = "second-observation"
	obs.TargetID = "candidate-b"
	obs.TargetDigest = digest
	for i := range obs.Facts {
		fact := &obs.Facts[i]
		if fact.Name == "machine-id" || fact.Name == "product-uuid" || fact.Name == "product-serial" {
			if fact.Name != sharedKind {
				fact.Value = "different-" + fact.Value
			}
		}
	}
	obs.ContentDigest = ""
	obs.ContentDigest = hostdiscovery.Digest(obs)
	raw, _ = json.Marshal(obs)
	hash := hostdiscovery.Digest("second-observation")
	exec(`INSERT INTO host_discovery_attempts VALUES('second-observation','operator-a',?,?,'candidate-b',1,?,1,1,0,'later',?)`, hash, hash, digest, []byte(`{}`))
	exec(`INSERT INTO host_observations VALUES('second-observation','candidate-b',1,?,?,1,0)`, raw, hostdiscovery.Digest(obs))
	if index {
		for _, fact := range obs.Facts {
			if fact.Name == "machine-id" || fact.Name == "product-uuid" || fact.Name == "product-serial" {
				exec(`INSERT INTO host_observation_identities VALUES('second-observation','candidate-b',?,?)`, fact.Name, hostdiscovery.Digest(fact.Value))
			}
		}
	}
	exec(`INSERT INTO effective_authorization_grants VALUES('second-prepare','operator-a','control-plane-admin','author','host.adoption.prepare','host-discovery-target','candidate-b',NULL,1,'active','now','now')`)
	return obs
}
func TestHostAdoptionLaterNonselectedIdentityConflict(t *testing.T) {
	for _, kind := range []string{"machine-id", "product-uuid", "product-serial"} {
		for _, phase := range []string{"stage", "apply"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				f := newRegistrationStoreFixture(t)
				if kind == "product-serial" {
					f.request.Confirmation.IdentityClass = "qualified-virtual"
					f.request.Confirmation.IdentityKind = "product-uuid"
					f.request.Confirmation.IdentityDigest = hostadoption.IdentityDigest("product-uuid", "synthetic-uuid")
				}
				var draft HostAdoptionDraft
				if phase == "apply" {
					draft = f.Stage(t)
				}
				f.otherObservation(t, kind, true)
				if phase == "stage" {
					if _, err := f.repo.StageDraft(f.ctx, f.request, f.attr); err == nil {
						t.Fatal("older observation ignored later identity conflict")
					}
				} else {
					b := f.bind(t, draft)
					if _, err := f.repo.Apply(f.ctx, b); err == nil {
						t.Fatal("apply ignored later identity conflict")
					}
				}
				if f.CountHosts(t) != 0 {
					t.Fatal("conflict committed host")
				}
			})
		}
	}
}
func TestHostAdoptionDifferentTargetsSameConfirmedIdentity(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	d1 := f.Stage(t)
	b1 := f.bind(t, d1)
	other := f.otherObservation(t, "product-serial", false)
	f.request.HostID = "different-host"
	f.request.IdempotencyKey = "different-key"
	f.request.ObservationID = other.ObservationID
	f.request.ObservationDigest = other.ContentDigest
	f.request.Confirmation.TargetDigest = other.TargetDigest
	d2 := f.Stage(t)
	b2 := f.bind(t, d2)
	if _, err := f.repo.Apply(f.ctx, b1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.Apply(f.ctx, b2); err == nil {
		t.Fatal("same identity registered on distinct targets")
	}
	if f.CountHosts(t) != 1 {
		t.Fatal("duplicate identity persisted")
	}
}

func TestHostAdoptionPersistedApprovalAndPlanDenials(t *testing.T) {
	for _, mode := range []string{"missing-ack", "unconsumed-ack", "wrong-ack", "embedded-confirmation", "input-binding", "unknown-operation"} {
		t.Run(mode, func(t *testing.T) {
			f := newRegistrationStoreFixture(t)
			d := f.Stage(t)
			b := f.bind(t, d, mode)
			_, err := f.repo.Apply(f.ctx, b)
			want := generated.ErrorCodePlanStale
			if mode == "missing-ack" || mode == "unconsumed-ack" || mode == "wrong-ack" {
				want = generated.ErrorCodeApprovalRequired
			}
			if Code(err) != want {
				t.Fatalf("denial %s want %s: %v", Code(err), want, err)
			}
			if f.CountHosts(t) != 0 {
				t.Fatal("denied binding committed host")
			}
		})
	}
}

func TestHostAdoptionDeniedPreparationAuditFailure(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.adoption.prepare'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `CREATE TRIGGER failure_audit_block BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.repo.StageDraft(f.ctx, f.request, f.attr); Code(err) != generated.ErrorCodeIntegrityFailure {
		t.Fatalf("missing denial audit did not fail closed: %v", err)
	}
	var n int
	if err := f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM host_adoption_drafts`).Scan(&n); err != nil || n != 0 {
		t.Fatal("denied draft persisted", err)
	}
}
