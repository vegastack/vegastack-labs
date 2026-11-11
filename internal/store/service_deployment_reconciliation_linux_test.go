//go:build linux

package store

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"testing"
)

func recoveryFixture(t *testing.T) (*registrationStoreFixture, *DeploymentRepository, generated.ServiceDeploymentRequest, ServiceDeploymentApply) {
	t.Helper()
	f, r, q := newDeploymentFixture(t)
	a := seedDeploymentExecution(t, f, q)
	if e := r.Begin(f.ctx, a); e != nil {
		t.Fatal(e)
	}
	for _, sql := range []string{
		`UPDATE plan_runs SET status='partial',changed=1,verification_status='incomplete' WHERE run_id='deployment-run'`,
		`UPDATE plan_run_steps SET status='partial',effect_state='effect-unknown',started_at='2026-11-10T16:42:29Z',finished_at='2026-11-10T16:49:29Z' WHERE step_id='deployment-step'`,
		`UPDATE target_execution_leases SET status='expired' WHERE lease_id='deployment-lease'`,
	} {
		if _, e := f.s.conn.ExecContext(f.ctx, sql); e != nil {
			t.Fatal(e)
		}
	}
	q.Action = "reconcile"
	q.IdempotencyKey = "reconcile-a"
	q.ExpectedStateRevision += 2
	q.Recovery = &generated.ServiceDeploymentRecovery{Schema: generated.SchemaIDServiceDeploymentRecovery, SchemaVersion: "1.0.0", PriorPlanID: a.PlanID, PriorRunID: a.RunID, PriorStepID: a.StepID, PriorRequestDigest: servicecatalog.Digest(*mustDeploymentPlan(t, f, a.PlanID).ServiceDeployment), ProviderReceiptID: "receipt-a"}
	return f, r, q, a
}
func mustDeploymentPlan(t *testing.T, f *registrationStoreFixture, id string) generated.Plan {
	t.Helper()
	p, e := NewPlanRepository(f.s).GetPlan(f.ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	return p.Plan
}
func TestDeploymentRecoveryExactUncompletedAttempt(t *testing.T) {
	f, r, q, _ := recoveryFixture(t)
	defer f.s.Close()
	out, e := r.RecoveryAttempt(f.ctx, q)
	if e != nil || out.Request.Action != "deploy" || out.StartedAt.IsZero() || out.FinishedAt.IsZero() {
		t.Fatal(out, e)
	}
	if _, e = r.Stage(f.ctx, q); e != nil {
		t.Fatal(e)
	}
	var n int
	if e = f.s.conn.QueryRowContext(f.ctx, `SELECT COUNT(*) FROM service_deployments`).Scan(&n); e != nil || n != 0 {
		t.Fatal("observation created deployment record", n, e)
	}
	for name, change := range map[string]func(*generated.ServiceDeploymentRequest){
		"run":  func(x *generated.ServiceDeploymentRequest) { x.Recovery.PriorRunID = "other-run" },
		"plan": func(x *generated.ServiceDeploymentRequest) { x.Recovery.PriorPlanID = "other-plan" },
		"step": func(x *generated.ServiceDeploymentRequest) { x.Recovery.PriorStepID = "other-step" },
		"request": func(x *generated.ServiceDeploymentRequest) {
			x.Recovery.PriorRequestDigest = servicecatalog.Digest("wrong")
		},
		"target":   func(x *generated.ServiceDeploymentRequest) { x.Definition.ServiceID = "other-service" },
		"artifact": func(x *generated.ServiceDeploymentRequest) { x.Artifact.Digest = servicecatalog.Digest("wrong") },
		"epoch":    func(x *generated.ServiceDeploymentRequest) { x.RecoveryEpoch++ },
		"revision": func(x *generated.ServiceDeploymentRequest) { x.ExpectedDeploymentRevision++ },
		"configuration": func(x *generated.ServiceDeploymentRequest) {
			x.Binding.ConfigurationDigest = servicecatalog.Digest("wrong")
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := q
			s := *q.Recovery
			copy.Recovery = &s
			change(&copy)
			if _, e := r.RecoveryAttempt(f.ctx, copy); e == nil {
				t.Fatal("accepted mismatched selector")
			}
		})
	}
}
func TestDeploymentRecoverySelectedLatestPartialRecord(t *testing.T) {
	f, r, q, old := recoveryFixture(t)
	defer f.s.Close()
	prior := mustDeploymentPlan(t, f, old.PlanID).ServiceDeployment
	record, e := deploymentRecord(*prior, old, servicecatalog.DeploymentOutcome{Status: "partial", ProviderReceiptID: "receipt-a", ProviderStage: "queued"}, f.s.config.Clock())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(record)
	if _, e = f.s.conn.ExecContext(f.ctx, `INSERT INTO service_deployments VALUES(?,?,?,?,?,?,?,?,?)`, q.Definition.ServiceID, record.Revision, old.PlanID, old.RunID, q.Artifact.Digest, q.RecoveryEpoch, "partial", raw, servicecatalog.Digest(record)); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.conn.ExecContext(f.ctx, `UPDATE service_deployment_attempts SET status='partial' WHERE plan_id=?`, old.PlanID); e != nil {
		t.Fatal(e)
	}
	q.ExpectedDeploymentRevision = 1
	if _, e = r.RecoveryAttempt(f.ctx, q); e != nil {
		t.Fatal("exact latest partial rejected", e)
	}
	mismatch := q
	s := *q.Recovery
	s.ProviderReceiptID = "other-receipt"
	mismatch.Recovery = &s
	if _, e = r.RecoveryAttempt(f.ctx, mismatch); e == nil {
		t.Fatal("partial record accepted different selected receipt")
	}
	current := seedDeploymentExecution(t, f, q, "-partial-reconcile")
	if e = r.Begin(f.ctx, current); e != nil {
		t.Fatal(e)
	}
	out := servicecatalog.DeploymentOutcome{Status: "succeeded", ProviderReceiptID: "receipt-a", ProviderStage: "queued", ReceiptDigest: serviceTestDigest, RuntimeDigest: serviceTestDigest, RunningDigest: q.Artifact.Digest, Running: true, Healthy: true}
	if _, e = r.Complete(f.ctx, current, out); e != nil {
		t.Fatal(e)
	}
	q.ExpectedDeploymentRevision = 2
	if _, e = r.RecoveryAttempt(f.ctx, q); e == nil {
		t.Fatal("already reconciled historical partial reused")
	}
}

func TestDeploymentRecoveryCompletionPreservesHistoricalUnknownRun(t *testing.T) {
	f, r, q, old := recoveryFixture(t)
	defer f.s.Close()
	current := seedDeploymentExecution(t, f, q, "-reconcile")
	if e := r.Begin(f.ctx, current); e != nil {
		t.Fatal(e)
	}
	// A second ordinary deployment cannot pass the selected recovery exception.
	if e := r.Begin(f.ctx, current); e == nil {
		t.Fatal("reconciliation replayed")
	}
	out := servicecatalog.DeploymentOutcome{Status: "succeeded", ProviderReceiptID: q.Recovery.ProviderReceiptID, ProviderStage: "queued", ReceiptDigest: serviceTestDigest, RuntimeDigest: serviceTestDigest, RunningDigest: q.Artifact.Digest, Running: true, Healthy: true}
	digest, e := r.Complete(f.ctx, current, out)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Verify(f.ctx, current.PlanID, current.RunID, digest); e != nil {
		t.Fatal(e)
	}
	var status, effect string
	if e = f.s.conn.QueryRowContext(f.ctx, `SELECT r.status,s.effect_state FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id WHERE r.run_id=?`, old.RunID).Scan(&status, &effect); e != nil || status != "partial" || effect != "effect-unknown" {
		t.Fatal("rewrote historical result", status, effect, e)
	}
	if e = f.s.conn.QueryRowContext(f.ctx, `SELECT status FROM service_deployment_attempts WHERE plan_id=?`, old.PlanID).Scan(&status); e != nil || status != "partial" {
		t.Fatal("old attempt not settled", status, e)
	}
	record, e := r.Get(f.ctx, q.Definition.ServiceID)
	if e != nil || record.Status != "succeeded" || record.Request.Recovery.PriorRunID != old.RunID {
		t.Fatal(record, e)
	}
	if _, e = r.RecoveryAttempt(f.ctx, q); e == nil {
		t.Fatal("settled old attempt eligible again")
	}
}
func TestDeploymentRecoveryFailedReadCanRetryWithoutSettlingOldAttempt(t *testing.T) {
	f, r, q, old := recoveryFixture(t)
	defer f.s.Close()
	current := seedDeploymentExecution(t, f, q, "-failed")
	if e := r.Begin(f.ctx, current); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Complete(f.ctx, current, servicecatalog.DeploymentOutcome{Status: "partial"}); e != nil {
		t.Fatal(e)
	}
	// A new normally acknowledged plan can observe the same original operation.
	rev, e := NewPlanRepository(f.s).CurrentRevision(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	q.ExpectedStateRevision = rev.StateRevision
	q.ExpectedDeploymentRevision = 1
	q.IdempotencyKey = "reconcile-second"
	if _, e = r.RecoveryAttempt(f.ctx, q); e != nil {
		t.Fatal("failed read blocked fresh precise recovery", e)
	}
	var status string
	if e = f.s.conn.QueryRowContext(f.ctx, `SELECT status FROM service_deployment_attempts WHERE plan_id=?`, old.PlanID).Scan(&status); e != nil || status != "attempted" {
		t.Fatal("failed observation settled original", status, e)
	}
	if _, e = f.s.conn.ExecContext(f.ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='deploy-author'`); e != nil {
		t.Fatal(e)
	}
	if _, e = r.RecoveryAttempt(f.ctx, q); e == nil {
		t.Fatal("revoked current author accepted")
	}
}
