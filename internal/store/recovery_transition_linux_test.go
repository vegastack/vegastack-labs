//go:build linux

package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestRecoveryRequiredReopenRemainsReadOnlyAndRetainsDistinctInstances(t *testing.T) {
	cfg := testConfig(t)
	authority, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var former string
	if err := authority.conn.QueryRowContext(context.Background(), `SELECT instance_id FROM system_meta WHERE id=1`).Scan(&former); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(context.Background(), `INSERT INTO audit_instances(instance_id,created_at) VALUES('instance-replacement-a','2026-09-24T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(context.Background(), `UPDATE system_meta SET instance_id='instance-replacement-a',recovery_epoch=1,authority_mode='recovery-required' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Mode = OpenExisting
	reopened, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	health, err := reopened.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !health.RecoveryPending || health.MutationEnabled || health.SafeModeReason != "recovery-required" || health.Revision.RecoveryEpoch != 1 {
		t.Fatalf("health=%#v", health)
	}
	if _, err := reopened.WriteIntent(context.Background(), nil, func(IntentTx) error { return nil }); Code(err) != "PREREQUISITE_BLOCKED" {
		t.Fatalf("write code=%s", Code(err))
	}
	prior := RevisionToken{StateRevision: health.Revision.StateRevision, RecoveryEpoch: 0}
	if _, err := reopened.WriteIntent(context.Background(), &prior, func(IntentTx) error { return nil }); Code(err) != "RECOVERY_EPOCH_MISMATCH" {
		t.Fatalf("old epoch write code=%s", Code(err))
	}
	request := publicIntentRequest(t, "9", nil)
	request.Expected = &prior
	if _, err := reopened.writeIntent(context.Background(), request, func(context.Context, *sql.Tx) error { return nil }); Code(err) != "RECOVERY_EPOCH_MISMATCH" {
		t.Fatalf("old epoch audited write code=%s", Code(err))
	}
	var count int
	if err := reopened.conn.QueryRowContext(context.Background(), `SELECT COUNT(1) FROM audit_instances WHERE instance_id IN (?,?)`, former, "instance-replacement-a").Scan(&count); err != nil || count != 2 {
		t.Fatalf("instances=%d err=%v", count, err)
	}
}

// TestRecoveryEpochFencesEveryOldAuthorityArtifact exercises the public store
// boundary for every authority-bearing artifact named by the recovery brief.
// Each artifact is created in epoch zero, the real recovery transition advances
// the database to epoch one, and the old artifact is then presented to the same
// repository method that would otherwise consume it.
func TestRecoveryEpochFencesEveryOldAuthorityArtifact(t *testing.T) {
	type boundary struct {
		name string
		run  func(*testing.T) string
		want string
	}
	boundaries := []boundary{
		{name: "plan", want: generated.ErrorCodeRecoveryEpochMismatch, run: func(t *testing.T) string {
			s := openRecoveryArtifactStore(t)
			plan := seedAcknowledgementPlan(t, s)
			promoteRecoveryArtifactStore(t, s)
			now := time.Date(2026, 9, 12, 18, 35, 0, 0, time.UTC)
			run := runForRecoveryArtifact(plan, "run-old-plan", now)
			_, err := NewRunRepository(s).Create(context.Background(), RunCreateRequest{Run: run, SubmitKeyDigest: digestForText("old-plan-submit"), RequestDigest: digestForText("old-plan-request"), Attribution: runAttribution(t)})
			return Code(err)
		}},
		{name: "acknowledgement", want: generated.ErrorCodeRecoveryEpochMismatch, run: func(t *testing.T) string {
			s := openRecoveryArtifactStore(t)
			plan := seedAcknowledgementPlan(t, s)
			repository := NewAcknowledgementRepository(s)
			create := acknowledgementTestCreate(plan)
			stored, _, err := repository.Create(context.Background(), create)
			if err != nil {
				t.Fatal(err)
			}
			approved := stored.Acknowledgement
			approved.Status = "approved"
			approved.ReceivedAt = create.CreatedAt.Format(time.RFC3339)
			approved.ProofDigest = string(digestForText("old-ack-proof"))
			attribution := audit.Attribution{AuthenticatedPrincipalID: create.Request.HumanID, AuthenticatedPrincipalMethod: identity.SlackSocketModeMethod}
			if _, _, err := repository.Decide(context.Background(), acknowledgement.DecisionRecord{Expected: create.Request, Outcome: approved, DecidedAt: create.CreatedAt, Attribution: attribution}); err != nil {
				t.Fatal(err)
			}
			promoteRecoveryArtifactStore(t, s)
			_, _, err = repository.Consume(context.Background(), plan.PlanID, create.CreatedAt.Add(time.Minute))
			return Code(err)
		}},
		{name: "browser session", want: generated.ErrorCodeAuthenticationRequired, run: func(t *testing.T) string {
			s, clock := newSessionStore(t)
			principal, binding := seedRemoteBinding(t, s, "principal-recovery-old")
			_, raw, err := s.CreateBrowserSession(context.Background(), BrowserSessionCreate{Principal: principal, BindingDigest: binding, ExternalExpiresAt: clock.Now().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			promoteRecoveryArtifactStore(t, s)
			_, err = s.ValidateAndTouchBrowserSession(context.Background(), raw, binding, clock.Now().Add(time.Hour))
			return Code(err)
		}},
		{name: "executor lease", want: generated.ErrorCodeRecoveryEpochMismatch, run: func(t *testing.T) string {
			now := time.Date(2026, 9, 13, 0, 3, 0, 0, time.UTC)
			fixture := openExecutorLeaseFixture(t, now)
			lease := fixture.mustClaim(t, now)
			promoteRecoveryArtifactStore(t, fixture.store)
			_, err := fixture.leases.Renew(context.Background(), fixture.renewal(lease, now.Add(20*time.Second)))
			return Code(err)
		}},
		{name: "credential", want: generated.ErrorCodeRecoveryEpochMismatch, run: func(t *testing.T) string {
			repository := openCredentialStore(t)
			binding := stageBinding()
			stage := seedCredentialLifecycleStep(t, repository, credentialref.ActionStage, stagedReference(2), 2, ackConsumed, binding)
			promoteRecoveryArtifactStore(t, repository.store)
			_, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: binding, Stage: stage})
			return Code(err)
		}},
		{name: "receipt", want: generated.ErrorCodeRecoveryEpochMismatch, run: func(t *testing.T) string {
			now := time.Date(2026, 9, 13, 0, 4, 0, 0, time.UTC)
			fixture := openExecutorLeaseFixture(t, now)
			lease := fixture.mustClaim(t, now)
			receipt := fixture.receipt(lease, now.Add(time.Second))
			promoteRecoveryArtifactStore(t, fixture.store)
			_, err := fixture.leases.RecordReceipt(context.Background(), ExecutorReceiptPersistenceRequest{Request: receipt, At: now.Add(time.Second), Attribution: fixture.attribution})
			return Code(err)
		}},
	}
	for _, boundary := range boundaries {
		t.Run(boundary.name, func(t *testing.T) {
			if got := boundary.run(t); got != boundary.want {
				t.Fatalf("old %s authority code = %q, want %q", boundary.name, got, boundary.want)
			}
		})
	}
}

func openRecoveryArtifactStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func promoteRecoveryArtifactStore(t *testing.T, s *Store) {
	t.Helper()
	prior, err := s.CurrentAuthority(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan := generated.Plan{PlanID: "plan-recovery-artifact", PlanDigest: testDigest, Binding: generated.PlanBinding{TargetDigest: testDigest}}
	binding := testRestoreBinding(plan, prior.InstanceID, "ack-recovery-artifact")
	if err := s.PrepareRecoveredAuthority(context.Background(), binding, digestForText("recovery-artifact-checkpoint")); err != nil {
		t.Fatal(err)
	}
	health, err := s.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableRecoveredAuthority(context.Background(), binding.NewInstanceID, binding.NextRecoveryEpoch, health.Revision.StateRevision, string(digestForText("recovery-artifact-canary"))); err != nil {
		t.Fatal(err)
	}
}

func runForRecoveryArtifact(plan generated.Plan, runID string, at time.Time) generated.Run {
	steps := make([]generated.RunStep, len(plan.Operations))
	for index, operation := range plan.Operations {
		steps[index] = generated.RunStep{Sequence: operation.Sequence, OperationID: operation.OperationID, OperationType: operation.OperationType, AdapterID: operation.AdapterID, ExecutorID: operation.ExecutorID, TargetID: operation.TargetID, InputDigest: operation.InputDigest, ArtifactDigest: operation.ArtifactDigest, Idempotent: operation.Idempotent, StepID: "step-" + runID, Status: "queued", EffectState: "not-started"}
	}
	return generated.Run{Schema: generated.SchemaIDRun, SchemaVersion: "1.0.0", RunID: runID, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, AuthorizationDecisionID: "decision-old-plan", PolicyVersion: plan.Binding.PolicyVersion, ExecutorMode: plan.ExecutorMode, ExecutorID: "executor-central", ExecutorBindingDigest: string(digestForText("old-plan-executor-binding")), Status: "queued", Steps: steps, CancellationRequested: false, RollbackStatus: "not-requested", VerificationStatus: "pending", Changed: false, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, CreatedAt: at.Format(time.RFC3339), UpdatedAt: at.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
}
