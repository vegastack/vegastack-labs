//go:build linux

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostinglifecycle"
	"testing"
	"time"
)

func newHostingLifecycleFixture(t *testing.T) (*registrationStoreFixture, *HostingLifecycleRepository, generated.HostingLifecycleRequest) {
	t.Helper()
	f, _ := newServiceCatalogFixture(t)
	in := generated.HostingLifecycleRequest{Schema: generated.SchemaIDHostingLifecycleRequest, SchemaVersion: "1.0.0", TargetID: "hosting-a", BindingID: "binding-a", ConfigurationDigest: serviceTestDigest, ObservedDigest: serviceTestDigest, Action: "resources.apply", IdempotencyKey: "hosting-a", ReasonDigest: serviceTestDigest}
	f.s.config.HostingLifecycleProfiles = []hostinglifecycle.Profile{{Binding: generated.HostingLifecycleProfile{Schema: generated.SchemaIDHostingLifecycleProfile, SchemaVersion: "1.0.0", TargetID: in.TargetID, BindingID: in.BindingID, ConfigurationDigest: in.ConfigurationDigest, ConfigurationPath: "/private/hosting.json", MutationReferenceID: "coolify-admin", PlatformReferenceID: "host-admin"}}}
	if _, e := f.s.conn.ExecContext(f.ctx, `INSERT INTO effective_authorization_grants VALUES('hosting-author','operator-a','infrastructure-admin','author','hosting.lifecycle.prepare','hosting','hosting-a',NULL,1,'active','now','now'),('hosting-read','operator-a','infrastructure-admin','read','hosting.read','hosting','hosting-a',NULL,1,'active','now','now'),('hosting-ack','operator-a','control-plane-admin','acknowledge','plan.acknowledge','plan-target','hosting-a','human',1,'active','now','now'),('hosting-execute','operator-a','control-plane-admin','execute','hosting.lifecycle.apply','execution-target','hosting-a','human',1,'active','now','now')`); e != nil {
		t.Fatal(e)
	}
	revision, e := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	in.ExpectedStateRevision = revision.StateRevision
	in.RecoveryEpoch = revision.RecoveryEpoch
	return f, NewHostingLifecycleRepository(f.s), in
}
func seedHostingLifecycleExecution(t *testing.T, f *registrationStoreFixture, in generated.HostingLifecycleRequest) HostingLifecycleApply {
	t.Helper()
	exec := func(q string, a ...any) {
		t.Helper()
		if _, e := f.s.conn.ExecContext(f.ctx, q, a...); e != nil {
			t.Fatal(e)
		}
	}
	r := NewHostingLifecycleRepository(f.s)
	stage, err := r.Stage(f.ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	now := f.s.config.Clock().UTC().Truncate(time.Second)
	digest := hostinglifecycle.Digest(in)
	document := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: stage.DeclarationID, DeclarationType: stage.DeclarationType, HostingLifecycle: &in, Revision: 1, StateRevision: in.ExpectedStateRevision + 1, RecoveryEpoch: in.RecoveryEpoch, Status: "draft", Operations: stage.Operations, CreatedAt: now.Format(time.RFC3339), CreatedBy: "operator-a", AgentSessionID: "session-a", Extensions: []generated.ContractExtension{}}
	for _, status := range []string{"draft", "committed"} {
		if status == "committed" {
			document.Revision = 2
			document.StateRevision++
			document.Status = status
		}
		document.ContentDigest = declarationContentDigest(document, in.ReasonDigest)
		raw, _ := json.Marshal(document)
		exec(`INSERT INTO declaration_revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, document.DeclarationID, document.Revision, document.DeclarationType, document.StateRevision, document.RecoveryEpoch, document.ContentDigest, in.ReasonDigest, document.Status, raw, document.CreatedAt, document.CreatedBy, document.AgentSessionID)
	}
	p, _ := credentialLifecyclePlan(stage.DeclarationID, in.TargetID, digest, hostinglifecycle.Operation, 2, in.ExpectedStateRevision+2)
	p.HostingLifecycle = &in
	p.Risk = "control-plane"
	p.CreatedAt = now.Format(time.RFC3339)
	p.ExpiresAt = now.Add(time.Duration(generated.PlanValiditySeconds) * time.Second).Format(time.RFC3339)
	p.Operations[0].OperationID = hostinglifecycle.OperationID
	p.Operations[0].AdapterID = hostinglifecycle.AdapterID
	p.Operations[0].Idempotent = false
	p.PlanID = ""
	p.PlanDigest = ""
	p.PlanDigest = hostinglifecycle.Digest(p)
	p.PlanID = "plan-" + p.PlanDigest[7:39]
	raw, _ := json.Marshal(p)
	var checked generated.Plan
	if !decodeStoredPlan(raw, "readable\n", &checked) {
		t.Fatal("fixture plan invalid")
	}
	exec(`INSERT INTO immutable_plans VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.PlanID, p.PlanDigest, p.DeclarationID, 2, p.Binding.StateRevision, p.Binding.RecoveryEpoch, p.Binding.ObservationFingerprint, hostinglifecycle.Digest("deploy-key"), digest, raw, "readable\n", p.ReadableDigest, p.CreatedAt, p.ExpiresAt)
	const runID = "hosting-run"
	const stepID = "hosting-step"
	const leaseID = "hosting-lease"
	const ackID = "hosting-ack"
	exec(`INSERT INTO acknowledgement_requests VALUES(?,?,?,?,?,'operator-a','fixture-authority',?,0,0,'later','approved',?,?,'now','now','now')`, ackID, p.PlanID, p.PlanDigest, digest, digest, digest, []byte(`{}`), []byte(`{}`))
	exec(`INSERT INTO plan_runs VALUES(?,?,?,'decision',?,'1.0.0','central','executor-central',?,'running',0,'not-requested','pending',NULL,0,?,0,?,?,?,'now','now')`, runID, p.PlanID, p.PlanDigest, ackID, digest, p.Binding.StateRevision, digest, digest, []byte(`{}`))
	exec(`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,result_digest,started_at,finished_at) VALUES(?,?,1,?,?,?,'executor-central',?,?,?,0,'running','intent-recorded',?,NULL,'now',NULL)`, stepID, runID, hostinglifecycle.OperationID, hostinglifecycle.Operation, hostinglifecycle.AdapterID, in.TargetID, digest, digest, leaseID)
	exec(`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES(?,?,?,?,?,?,0,?,?,?,?,'active',?)`, leaseID, runID, stepID, in.TargetID, digest, digest, p.CreatedAt, p.CreatedAt, now.Add(time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339), []byte(`{}`))
	exec(`INSERT INTO service_import_run_actors VALUES(?,'operator-a','local-os-peer','')`, runID)
	exec(`UPDATE system_meta SET state_revision=? WHERE id=1`, p.Binding.StateRevision)
	_, err = f.s.executeAuditIntent(f.ctx, discoveryIntent(f.attr, "run.created", runID, digest, digest), false, func(context.Context, *sql.Tx) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return HostingLifecycleApply{PlanID: p.PlanID, PlanDigest: p.PlanDigest, RunID: runID, StepID: stepID, LeaseID: leaseID, Attribution: f.attr}
}

func TestHostingLifecycleUnknownEffectCannotReplay(t *testing.T) {
	f, r, in := newHostingLifecycleFixture(t)
	defer f.s.Close()
	apply := seedHostingLifecycleExecution(t, f, in)
	if e := r.Begin(f.ctx, apply); e != nil {
		t.Fatal(e)
	}
	if e := NewHostingLifecycleRepository(f.s).Begin(f.ctx, apply); e == nil {
		t.Fatal("unknown attempt replayed")
	}
	if _, e := r.Get(f.ctx, in.TargetID); Code(e) != generated.ErrorCodeRecoveryRequired {
		t.Fatal("pending hidden", e)
	}
	digest, e := r.Complete(f.ctx, apply, hostinglifecycle.Outcome{Status: "partial"})
	if e != nil {
		t.Fatal(e)
	}
	if r.Verify(f.ctx, apply.PlanID, apply.RunID, digest) == nil {
		t.Fatal("partial verified")
	}
}
func TestHostingLifecycleVerifiedOwnershipAndRevocation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "revoked"}[revoke], func(t *testing.T) {
			f, r, in := newHostingLifecycleFixture(t)
			defer f.s.Close()
			apply := seedHostingLifecycleExecution(t, f, in)
			if e := r.Begin(f.ctx, apply); e != nil {
				t.Fatal(e)
			}
			if revoke {
				if _, e := f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='hosting-execute'`); e != nil {
					t.Fatal(e)
				}
			}
			owned := []generated.HostingOwnedResource{{Schema: generated.SchemaIDHostingOwnedResource, SchemaVersion: "1.0.0", Kind: "coolify-project", ExternalID: "project-a", ParentID: "team-a"}}
			digest, e := r.Complete(f.ctx, apply, hostinglifecycle.Outcome{Status: "succeeded", ResultDigest: serviceTestDigest, OwnedResources: owned})
			if e != nil {
				t.Fatal(e)
			}
			if e = r.Verify(f.ctx, apply.PlanID, apply.RunID, digest); (e != nil) != revoke {
				t.Fatal("incorrect verify after authority", e)
			}
			record, e := r.Get(f.ctx, in.TargetID)
			if e != nil || len(record.OwnedResources) != 1 || record.OwnedResources[0].ExternalID != "project-a" {
				t.Fatal(record, e)
			}
		})
	}
}
func TestHostingLifecyclePreparationInert(t *testing.T) {
	f, r, in := newHostingLifecycleFixture(t)
	defer f.s.Close()
	if _, e := r.Stage(f.ctx, in); e != nil {
		t.Fatal(e)
	}
	var n int
	if e := f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM hosting_lifecycle_attempts`).Scan(&n); e != nil || n != 0 {
		t.Fatal("draft mutated", n, e)
	}
	in.ConfigurationDigest = hostinglifecycle.Digest("different")
	if _, e := r.Stage(f.ctx, in); e == nil {
		t.Fatal("different profile accepted")
	}
}
