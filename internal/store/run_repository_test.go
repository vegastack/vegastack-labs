//go:build linux

package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

//go:embed pending-migrations/0009_runs.sql
var pendingRunMigration string

func TestRunStateAndRetentionNeverEraseRequiredSummary(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	repository := openRunRepository(t, now)
	run := testRun("run-retention", "submit-retention", now.Add(-179*24*time.Hour))
	created, err := repository.Create(context.Background(), RunCreateRequest{
		Run: run, SubmitKeyDigest: digestForText("submit-retention"), RequestDigest: digestForText("request-retention"), Attribution: runAttribution(t),
	})
	if err != nil || !created.Created {
		t.Fatalf("create = %#v, %v", created, err)
	}
	if _, err := repository.TransitionRun(context.Background(), RunTransitionRequest{RunID: run.RunID, From: "queued", To: "running", At: now.Add(-178 * 24 * time.Hour), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.TransitionRun(context.Background(), RunTransitionRequest{RunID: run.RunID, From: "running", To: "succeeded", At: now.Add(-177 * 24 * time.Hour), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.TransitionRun(context.Background(), RunTransitionRequest{RunID: run.RunID, From: "succeeded", To: "running", At: now, Attribution: runAttribution(t)}); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("illegal transition code = %q", Code(err))
	}
	if err := repository.AppendRunEvent(context.Background(), RunEventRequest{RunID: run.RunID, EventType: "run.detail", EventDigest: digestForText("detail"), OccurredAt: now.Add(-31 * 24 * time.Hour), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	result, err := repository.PruneRunHistory(context.Background(), now)
	if err != nil || result.DetailedEventsDeleted < 1 || result.SummariesDeleted != 0 {
		t.Fatalf("prune = %#v, %v", result, err)
	}
	if _, err := repository.Get(context.Background(), run.RunID); err != nil {
		t.Fatalf("179-day summary missing: %v", err)
	}

	veryOld := testRun("run-expired", "submit-expired", now.Add(-181*24*time.Hour))
	if _, err := repository.Create(context.Background(), RunCreateRequest{Run: veryOld, SubmitKeyDigest: digestForText("submit-expired"), RequestDigest: digestForText("request-expired"), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.TransitionRun(context.Background(), RunTransitionRequest{RunID: veryOld.RunID, From: "queued", To: "running", At: now.Add(-181 * 24 * time.Hour), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.TransitionRun(context.Background(), RunTransitionRequest{RunID: veryOld.RunID, From: "running", To: "succeeded", At: now.Add(-181 * 24 * time.Hour), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	result, err = repository.PruneRunHistory(context.Background(), now)
	if err != nil || result.SummariesDeleted != 1 {
		t.Fatalf("old summary prune = %#v, %v", result, err)
	}
	if _, err := repository.Get(context.Background(), veryOld.RunID); Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("181-day summary code = %q", Code(err))
	}
}

func TestRunSubmitLeaseAndReceiptAreDurableIdempotentAndExclusive(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	repository := openRunRepository(t, now)
	run := testRun("run-one", "submit-one", now)
	request := RunCreateRequest{Run: run, SubmitKeyDigest: digestForText("submit-one"), RequestDigest: digestForText("request-one"), Attribution: runAttribution(t)}
	first, err := repository.Create(context.Background(), request)
	if err != nil || !first.Created {
		t.Fatalf("first create = %#v, %v", first, err)
	}
	replay, err := repository.Create(context.Background(), request)
	if err != nil || replay.Created || replay.Run.RunID != run.RunID {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	changed := request
	changed.RequestDigest = digestForText("changed-request")
	if _, err := repository.Create(context.Background(), changed); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("changed replay code = %q", Code(err))
	}
	if _, err := repository.TransitionRun(context.Background(), RunTransitionRequest{RunID: run.RunID, From: "queued", To: "running", At: now, Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}

	lease := testLease(run, run.Steps[0], now)
	if err := repository.AcquireTargetLease(context.Background(), lease, runAttribution(t)); err != nil {
		t.Fatal(err)
	}
	conflict := lease
	conflict.LeaseID = "lease-two"
	if err := repository.AcquireTargetLease(context.Background(), conflict, runAttribution(t)); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("conflicting lease code = %q", Code(err))
	}
	if _, err := repository.BeginStep(context.Background(), StepBeginRequest{RunID: run.RunID, StepID: run.Steps[0].StepID, LeaseID: lease.LeaseID, At: now, Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	receipt := testReceipt(lease, now)
	if _, err := repository.RecordReceipt(context.Background(), ReceiptRecordRequest{RunID: run.RunID, StepID: run.Steps[0].StepID, LeaseID: lease.LeaseID, Receipt: receipt, At: now.Add(time.Second), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	finished, err := repository.FinishStep(context.Background(), StepFinishRequest{RunID: run.RunID, StepID: run.Steps[0].StepID, LeaseID: lease.LeaseID, Receipt: receipt, Status: "succeeded", EffectState: "verified", VerificationDigest: string(digestForText("verified")), Changed: true, At: now.Add(time.Second), Attribution: runAttribution(t)})
	if err != nil || finished.Steps[0].EffectState != "verified" || !finished.Changed {
		t.Fatalf("finish = %#v, %v", finished, err)
	}
	if _, err := repository.FinishStep(context.Background(), StepFinishRequest{RunID: run.RunID, StepID: run.Steps[0].StepID, LeaseID: lease.LeaseID, Receipt: receipt, Status: "succeeded", EffectState: "verified", VerificationDigest: string(digestForText("verified")), Changed: true, At: now.Add(time.Second), Attribution: runAttribution(t)}); err != nil {
		t.Fatalf("receipt replay failed: %v", err)
	}
	var eventCount int
	if err := repository.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_events WHERE correlation_id=? AND target_kind='run'`, run.RunID).Scan(&eventCount); err != nil || eventCount < 6 {
		t.Fatalf("durable run audit events = %d, %v", eventCount, err)
	}
}

func TestConcurrentTargetLeaseClaimsHaveOneAuthoritativeWinner(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	repository := openRunRepository(t, now)
	run := testRun("run-race", "submit-race", now)
	if _, err := repository.Create(context.Background(), RunCreateRequest{Run: run, SubmitKeyDigest: digestForText("submit-race"), RequestDigest: digestForText("request-race"), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.TransitionRun(context.Background(), RunTransitionRequest{RunID: run.RunID, From: "queued", To: "running", At: now, Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	attribution := runAttribution(t)
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})
	for _, leaseID := range []string{"lease-race-one", "lease-race-two"} {
		lease := testLease(run, run.Steps[0], now)
		lease.LeaseID = leaseID
		go func() {
			ready.Done()
			<-start
			results <- repository.AcquireTargetLease(context.Background(), lease, attribution)
		}()
	}
	ready.Wait()
	close(start)
	succeeded, conflicted := 0, 0
	for range 2 {
		err := <-results
		switch Code(err) {
		case "":
			succeeded++
		case generated.ErrorCodeStateConflict:
			conflicted++
		default:
			t.Fatalf("unexpected claim error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("lease winners/conflicts = %d/%d", succeeded, conflicted)
	}
}

func runAttribution(t *testing.T) audit.Attribution {
	t.Helper()
	value, err := audit.NewAttribution(identity.Principal{ID: "principal-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func openRunRepository(t *testing.T, now time.Time) *RunRepository {
	t.Helper()
	config := testConfig(t)
	config.Clock = func() time.Time { return now }
	authority, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	if _, err := authority.conn.ExecContext(context.Background(), pendingRunMigration); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(context.Background(), `UPDATE system_meta SET state_revision=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedRunPlan(t, authority, now)
	return NewRunRepository(authority)
}

func seedRunPlan(t *testing.T, authority *Store, now time.Time) {
	t.Helper()
	digest := digestForText("plan")
	declaration := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: "declaration-run-test", DeclarationType: "application", Revision: 1, StateRevision: 1, RecoveryEpoch: 0, ContentDigest: string(digestForText("content")), Status: "committed", Operations: []generated.DeclarationOperation{}, CreatedAt: now.Format(time.RFC3339), CreatedBy: "principal-run-test", AgentSessionID: "session-run-test", Extensions: []generated.ContractExtension{}}
	declarationBytes, _ := json.Marshal(declaration)
	if _, err := authority.conn.ExecContext(context.Background(), `INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, declaration.DeclarationID, declaration.Revision, declaration.DeclarationType, declaration.StateRevision, declaration.RecoveryEpoch, declaration.ContentDigest, digestForText("reason"), declaration.Status, declarationBytes, declaration.CreatedAt, declaration.CreatedBy, declaration.AgentSessionID); err != nil {
		t.Fatal(err)
	}
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-run-test", PlanDigest: string(digest), DeclarationID: declaration.DeclarationID, Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 0, StateRevision: 1, DeclarationRevision: 1, ObservationFingerprint: string(digestForText("observation")), TargetDigest: string(digestForText("target")), ReasonDigest: string(digestForText("reason")), PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-run-test", OperationType: "application.deploy.low-risk", AdapterID: "adapter-test", ExecutorID: "executor-central", TargetID: "target-run-test", InputDigest: string(digestForText("input")), ArtifactDigest: string(digestForText("artifact")), Idempotent: true}}, Status: "planned", Risk: "routine", AuthorizationBranch: "preauthorized", ExecutorMode: "central", ExecutorID: nil, CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339), ReadableDigest: string(digestForText("readable")), Extensions: []generated.ContractExtension{}}
	planBytes, _ := json.Marshal(plan)
	if _, err := authority.conn.ExecContext(context.Background(), `INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, plan.PlanID, plan.PlanDigest, plan.DeclarationID, plan.Binding.DeclarationRevision, plan.Binding.StateRevision, plan.Binding.RecoveryEpoch, plan.Binding.ObservationFingerprint, digestForText("plan-key"), digestForText("plan-request"), planBytes, "test plan", plan.ReadableDigest, plan.CreatedAt, plan.ExpiresAt); err != nil {
		t.Fatal(err)
	}
}

func testRun(runID, submit string, at time.Time) generated.Run {
	return generated.Run{Schema: generated.SchemaIDRun, SchemaVersion: "1.0.0", RunID: runID, PlanID: "plan-run-test", PlanDigest: string(digestForText("plan")), AuthorizationDecisionID: "decision-run-test", AcknowledgementID: nil, PolicyVersion: "1.0.0", ExecutorMode: "central", ExecutorID: "executor-central", ExecutorBindingDigest: string(digestForText("executor-binding")), Status: "queued", Steps: []generated.RunStep{{Sequence: 1, OperationID: "operation-run-test", OperationType: "application.deploy.low-risk", AdapterID: "adapter-test", ExecutorID: "executor-central", TargetID: "target-run-test", InputDigest: string(digestForText("input")), ArtifactDigest: string(digestForText("artifact")), Idempotent: true, StepID: "step-" + runID, Status: "queued", EffectState: "not-started"}}, CancellationRequested: false, RollbackStatus: "not-requested", VerificationStatus: "pending", VerificationDigest: nil, Changed: false, StateRevision: 1, RecoveryEpoch: 0, CreatedAt: at.Format(time.RFC3339), UpdatedAt: at.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
}

func testLease(run generated.Run, step generated.RunStep, at time.Time) generated.ExecutorLease {
	return generated.ExecutorLease{Schema: generated.SchemaIDExecutorLease, SchemaVersion: "1.0.0", LeaseID: "lease-" + run.RunID, PlanID: run.PlanID, PlanDigest: run.PlanDigest, RunID: run.RunID, StepID: step.StepID, OperationID: step.OperationID, ExecutorID: run.ExecutorID, AdapterID: step.AdapterID, TargetID: step.TargetID, ArtifactDigest: step.ArtifactDigest, BindingDigest: run.ExecutorBindingDigest, NonceDigest: string(digestForText("nonce")), RecoveryEpoch: run.RecoveryEpoch, ClaimedAt: at.Format(time.RFC3339), RenewAfter: at.Add(20 * time.Second).Format(time.RFC3339), LeaseExpiresAt: at.Add(60 * time.Second).Format(time.RFC3339), MaximumExpiresAt: at.Add(60 * time.Second).Format(time.RFC3339), Status: "active", Extensions: []generated.ContractExtension{}}
}

func testReceipt(lease generated.ExecutorLease, at time.Time) generated.ExecutionReceipt {
	return generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, OperationID: lease.OperationID, ExecutorID: lease.ExecutorID, AdapterID: lease.AdapterID, TargetID: lease.TargetID, ArtifactDigest: lease.ArtifactDigest, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch, ReceiptID: "receipt-" + lease.RunID, Status: "succeeded", ResultDigest: string(digestForText("result")), RecordedAt: at.Add(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
}
