//go:build linux

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"testing"
	"time"
)

func newDeploymentFixture(t *testing.T) (*registrationStoreFixture, *DeploymentRepository, generated.ServiceDeploymentRequest) {
	t.Helper()
	f, _ := newServiceCatalogFixture(t)
	exec := func(q string, a ...any) {
		t.Helper()
		if _, e := f.s.conn.ExecContext(f.ctx, q, a...); e != nil {
			t.Fatal(e)
		}
	}
	var planID, runID string
	if e := f.s.conn.QueryRowContext(f.ctx, `SELECT plan_id,run_id FROM plan_runs LIMIT 1`).Scan(&planID, &runID); e != nil {
		t.Fatal(e)
	}
	p := f.s.config.ServiceImportPolicies[0]
	record := generated.ServiceRecord{Schema: generated.SchemaIDServiceRecord, SchemaVersion: "1.0.0", Definition: p.Definition, Revision: 1, RegistrationStatus: "registered", HostAdmission: "not-verified", RegisteredAt: "2026-10-26T00:00:00Z"}
	raw, _ := json.Marshal(record)
	exec(`INSERT INTO service_catalog VALUES(?,?,?,?,?,?,?)`, record.Definition.ServiceID, p.ResourceKeyDigest, raw, servicecatalog.Digest(record), serviceTestDigest, planID, runID)
	in := deploymentRequestFixture()
	in.Definition = p.Definition
	f.s.config.ServiceDeploymentPolicies = []servicecatalog.DeploymentPolicy{{Binding: in.Binding, Artifacts: []generated.ServiceDeploymentArtifact{in.Artifact}}}
	exec(`INSERT INTO effective_authorization_grants VALUES('deploy-author','operator-a','maintainer','author','service.deploy.prepare','service','service-a',NULL,1,'active','now','now'),('deploy-ack','operator-a','maintainer','acknowledge','plan.acknowledge','plan-target','service-a','human',1,'active','now','now'),('deploy-execute','operator-a','maintainer','execute','service.deploy','execution-target','service-a','human',1,'active','now','now')`)
	revision, err := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	in.ExpectedStateRevision = revision.StateRevision
	in.RecoveryEpoch = revision.RecoveryEpoch
	return f, NewDeploymentRepository(f.s), in
}
func seedDeploymentExecution(t *testing.T, f *registrationStoreFixture, in generated.ServiceDeploymentRequest) ServiceDeploymentApply {
	t.Helper()
	exec := func(q string, a ...any) {
		t.Helper()
		if _, e := f.s.conn.ExecContext(f.ctx, q, a...); e != nil {
			t.Fatal(e)
		}
	}
	r := NewDeploymentRepository(f.s)
	stage, err := r.Stage(f.ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	now := f.s.config.Clock().UTC().Truncate(time.Second)
	digest := servicecatalog.Digest(in)
	document := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: stage.DeclarationID, DeclarationType: stage.DeclarationType, ServiceDeployment: &in, Revision: 1, StateRevision: in.ExpectedStateRevision + 1, RecoveryEpoch: in.RecoveryEpoch, Status: "draft", Operations: stage.Operations, CreatedAt: now.Format(time.RFC3339), CreatedBy: "operator-a", AgentSessionID: "session-a", Extensions: []generated.ContractExtension{}}
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
	p, _ := credentialLifecyclePlan(stage.DeclarationID, in.Definition.ServiceID, digest, servicecatalog.DeploymentOperation, 2, in.ExpectedStateRevision+2)
	p.ServiceDeployment = &in
	p.Risk = "production-like"
	p.CreatedAt = now.Format(time.RFC3339)
	p.ExpiresAt = now.Add(time.Duration(generated.PlanValiditySeconds) * time.Second).Format(time.RFC3339)
	p.Operations[0].OperationID = servicecatalog.DeploymentOperationID
	p.Operations[0].AdapterID = servicecatalog.DeploymentAdapterID
	p.Operations[0].Idempotent = false
	p.PlanID = ""
	p.PlanDigest = ""
	p.PlanDigest = servicecatalog.Digest(p)
	p.PlanID = "plan-" + p.PlanDigest[7:39]
	raw, _ := json.Marshal(p)
	var checked generated.Plan
	if !decodeStoredPlan(raw, "readable\n", &checked) {
		t.Fatal("fixture plan invalid")
	}
	exec(`INSERT INTO immutable_plans VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, p.PlanID, p.PlanDigest, p.DeclarationID, 2, p.Binding.StateRevision, p.Binding.RecoveryEpoch, p.Binding.ObservationFingerprint, servicecatalog.Digest("deploy-key"), digest, raw, "readable\n", p.ReadableDigest, p.CreatedAt, p.ExpiresAt)
	const runID = "deployment-run"
	const stepID = "deployment-step"
	const leaseID = "deployment-lease"
	const ackID = "deployment-ack"
	exec(`INSERT INTO acknowledgement_requests VALUES(?,?,?,?,?,'operator-a','fixture-authority',?,0,0,'later','approved',?,?,'now','now','now')`, ackID, p.PlanID, p.PlanDigest, digest, digest, digest, []byte(`{}`), []byte(`{}`))
	exec(`INSERT INTO plan_runs VALUES(?,?,?,'decision',?,'1.0.0','central','executor-central',?,'running',0,'not-requested','pending',NULL,0,?,0,?,?,?,'now','now')`, runID, p.PlanID, p.PlanDigest, ackID, digest, p.Binding.StateRevision, digest, digest, []byte(`{}`))
	exec(`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,result_digest,started_at,finished_at) VALUES(?,?,1,?,?,?,'executor-central',?,?,?,0,'running','intent-recorded',?,NULL,'now',NULL)`, stepID, runID, servicecatalog.DeploymentOperationID, servicecatalog.DeploymentOperation, servicecatalog.DeploymentAdapterID, in.Definition.ServiceID, digest, digest, leaseID)
	exec(`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES(?,?,?,?,?,?,0,?,?,?,?,'active',?)`, leaseID, runID, stepID, in.Definition.ServiceID, digest, digest, p.CreatedAt, p.CreatedAt, now.Add(time.Minute).Format(time.RFC3339), now.Add(time.Minute).Format(time.RFC3339), []byte(`{}`))
	exec(`INSERT INTO service_import_run_actors VALUES(?,'operator-a','local-os-peer','')`, runID)
	exec(`UPDATE system_meta SET state_revision=? WHERE id=1`, p.Binding.StateRevision)
	_, err = f.s.executeAuditIntent(f.ctx, discoveryIntent(f.attr, "run.created", runID, digest, digest), false, func(context.Context, *sql.Tx) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return ServiceDeploymentApply{PlanID: p.PlanID, PlanDigest: p.PlanDigest, RunID: runID, StepID: stepID, LeaseID: leaseID, Attribution: f.attr}
}
func TestDeploymentPreparationIsInertAndRollbackFailClosed(t *testing.T) {
	f, r, in := newDeploymentFixture(t)
	defer f.s.Close()
	draft := generated.ServiceDeploymentDraftRequest{Schema: generated.SchemaIDServiceDeploymentDraftRequest, SchemaVersion: "1.0.0", ServiceID: in.Definition.ServiceID, ArtifactID: in.Artifact.ArtifactID, Action: "deploy", ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, IdempotencyKey: in.IdempotencyKey, ReasonDigest: in.ReasonDigest}
	prepared, err := r.Prepare(f.ctx, draft)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.ArtifactProofDigest != "" {
		t.Fatal("fabricated proof")
	}
	if _, err = r.Stage(f.ctx, prepared); err == nil {
		t.Fatal("unverified proof staged")
	}
	if _, err = r.Stage(f.ctx, in); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM service_deployment_attempts`).Scan(&n); err != nil || n != 0 {
		t.Fatal("inert stage attempted deployment", n, err)
	}
	in.Action = "rollback"
	if _, err = r.Stage(f.ctx, in); err == nil {
		t.Fatal("rollback without prior verified image accepted")
	}
}
func TestDeploymentAttemptCannotReplayAfterUnknownEffect(t *testing.T) {
	f, r, in := newDeploymentFixture(t)
	defer f.s.Close()
	apply := seedDeploymentExecution(t, f, in)
	actor, err := r.ExecutionActor(f.ctx, apply)
	if err != nil || actor.ID != "operator-a" {
		t.Fatal(actor, err)
	}
	if err = r.Begin(f.ctx, apply); err != nil {
		t.Fatal(err)
	}
	if _, e := r.Get(f.ctx, in.Definition.ServiceID); Code(e) != generated.ErrorCodeRecoveryRequired {
		t.Fatal("unfinished deployment presented as completed", e)
	}
	// A replacement repository represents a restarted execution path. The durable
	// attempt must deny another provider callback before any network operation.
	if err = NewDeploymentRepository(f.s).Begin(f.ctx, apply); err == nil {
		t.Fatal("unknown effect replayed")
	}
	digest, err := r.Complete(f.ctx, apply, servicecatalog.DeploymentOutcome{Status: "partial", ProviderReceiptID: "receipt-a", ProviderStage: "deploy_attempted"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verify(f.ctx, apply.PlanID, apply.RunID, digest) == nil {
		t.Fatal("partial effect verified")
	}
	record, err := r.Get(f.ctx, in.Definition.ServiceID)
	if err != nil || record.Status != "partial" || record.ProviderReceiptID != "receipt-a" {
		t.Fatal(record, err)
	}
}
func TestDeploymentExactRuntimeAndRevocation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy", true: "revoked-after-attempt"}[revoke], func(t *testing.T) {
			f, r, in := newDeploymentFixture(t)
			defer f.s.Close()
			apply := seedDeploymentExecution(t, f, in)
			if err := r.Begin(f.ctx, apply); err != nil {
				t.Fatal(err)
			}
			if revoke {
				if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='deploy-execute'`); err != nil {
					t.Fatal(err)
				}
			}
			digest, err := r.Complete(f.ctx, apply, servicecatalog.DeploymentOutcome{Status: "succeeded", ProviderReceiptID: "receipt-a", ProviderStage: "queued", ReceiptDigest: serviceTestDigest, RuntimeDigest: serviceTestDigest, RunningDigest: in.Artifact.Digest, Running: true, Healthy: true})
			if err != nil {
				t.Fatal(err)
			}
			err = r.Verify(f.ctx, apply.PlanID, apply.RunID, digest)
			if (err != nil) != revoke {
				t.Fatal("verification did not follow current authority", err)
			}
			if !revoke {
				revision, e := NewPlanRepository(f.s).CurrentRevision(f.ctx)
				if e != nil {
					t.Fatal(e)
				}
				rollback := in
				rollback.Action = "rollback"
				rollback.ExpectedDeploymentRevision = 1
				rollback.ExpectedStateRevision = revision.StateRevision
				rollback.IdempotencyKey = "rollback-a"
				if _, e = r.Stage(f.ctx, rollback); e != nil {
					t.Fatal("previous verified compatible image rollback denied", e)
				}
				rollback.Binding.DataPolicy = "unknown"
				f.s.config.ServiceDeploymentPolicies[0].Binding = rollback.Binding
				if _, e = r.Stage(f.ctx, rollback); e == nil {
					t.Fatal("unknown data rollback accepted")
				}
			}

		})
	}
}

func TestDeploymentAuthorityDeniesBeforeAttempt(t *testing.T) {
	for _, mode := range []string{"author", "executor", "acknowledger", "owner", "epoch", "state", "excluded", "binding", "actor"} {
		t.Run(mode, func(t *testing.T) {
			f, r, in := newDeploymentFixture(t)
			defer f.s.Close()
			apply := seedDeploymentExecution(t, f, in)
			exec := func(q string, a ...any) {
				t.Helper()
				if _, e := f.s.conn.ExecContext(f.ctx, q, a...); e != nil {
					t.Fatal(e)
				}
			}
			switch mode {
			case "author":
				exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='deploy-author'`)
			case "executor":
				exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='deploy-execute'`)
			case "acknowledger":
				exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='deploy-ack'`)
			case "owner":
				exec(`UPDATE effective_authorization_principals SET status='revoked' WHERE principal_id='operator-a'`)
			case "epoch":
				exec(`UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`)
			case "state":
				exec(`UPDATE system_meta SET state_revision=state_revision+1 WHERE id=1`)
			case "excluded":
				f.s.config.NetworkConnectExcludedHostIDs = []string{"synthetic-host"}
			case "binding":
				f.s.config.ServiceDeploymentPolicies[0].Binding.ConfigurationDigest = servicecatalog.Digest("changed")
			case "actor":
				apply.Attribution.AuthenticatedPrincipalID = "another-actor"
			}
			if err := r.Begin(f.ctx, apply); err == nil {
				t.Fatal("invalid authority began provider attempt")
			}
			var n int
			if err := f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM service_deployment_attempts`).Scan(&n); err != nil || n != 0 {
				t.Fatal("denied preflight persisted mutation attempt", n, err)
			}
		})
	}
}
func TestDeploymentBoundariesRecheckAcknowledgement(t *testing.T) {
	f, r, in := newDeploymentFixture(t)
	defer f.s.Close()
	apply := seedDeploymentExecution(t, f, in)
	if err := r.Begin(f.ctx, apply); err != nil {
		t.Fatal(err)
	}
	if err := r.Authorize(f.ctx, in); err != nil {
		t.Fatal("current approved boundary denied", err)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='deploy-ack'`); err != nil {
		t.Fatal(err)
	}
	if err := r.Authorize(f.ctx, in); err == nil {
		t.Fatal("revoked human acknowledgement authority crossed provider boundary")
	}
}
