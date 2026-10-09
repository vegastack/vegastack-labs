//go:build linux

package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func nativePendingFixture(t *testing.T) (*RunRepository, credentialref.NativeRestartPending, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)
	r := openRunRepository(t, now)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := r.store.conn.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	fp := string(digestForText("native ciphertext"))
	b := credentialref.LifecycleBinding{OperationID: "activate-native", Action: credentialref.ActionActivate, ReferenceID: "action-key", MaterialVersion: "material-one", ResolverID: "native-systemd", TargetID: "host-one", CiphertextFingerprint: fp, StateRevision: 1, ConsumerIDs: []string{"host-action"}, RequiredDeniedConsumerIDs: []string{"denied-reader"}, NativeArtifactConsumerID: "host-action", HostActionConsole: &credentialref.HostActionConsoleBinding{Method: "administrator-verified-console", TargetDigest: fp, HostIdentityDigest: fp, TargetRevision: 1, NativeConsumerMachineID: strings.Repeat("a", 32)}}
	b.NativeConsumers = []credentialref.NativeConsumerBinding{{ConsumerID: "host-action", TargetID: b.TargetID, HostMachineID: strings.Repeat("a", 32), UnitName: "vsk-labs.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-one", RoleID: "control", LoadedName: credentialref.LoadedNameForVersion("host-action", b.ReferenceID, b.MaterialVersion)}}
	b.NativeDeniedReaders = []credentialref.NativeDeniedReaderBinding{{ConsumerID: "denied-reader", TargetID: b.TargetID, HostMachineID: strings.Repeat("a", 32), ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-one", RoleID: "denied"}}
	if !credentialref.ValidLifecycleBinding(b) {
		t.Fatal("invalid lifecycle fixture")
	}
	var plan generated.Plan
	var raw []byte
	if err := r.store.conn.QueryRowContext(ctx, `SELECT canonical_bytes FROM immutable_plans WHERE plan_id='plan-run-test'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	plan.PlanID, plan.PlanDigest, plan.AuthorizationBranch, plan.Risk = "native-plan", string(digestForText("native plan")), "human", "control-plane"
	plan.Binding.DeclarationRevision = 2
	exec(`INSERT INTO declaration_revisions SELECT declaration_id,2,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,'committed',canonical_bytes,created_at,created_by,agent_session_id FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=1`, plan.DeclarationID)
	plan.Operations = []generated.PlanOperation{{Sequence: 1, OperationID: b.OperationID, OperationType: string(b.Action), AdapterID: "core.credential", ExecutorID: "executor-central", TargetID: b.TargetID, InputDigest: fp, ArtifactDigest: fp, Idempotent: false}}
	raw, _ = json.Marshal(plan)
	exec(`INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, plan.PlanID, plan.PlanDigest, plan.DeclarationID, 2, 1, 0, plan.Binding.ObservationFingerprint, digestForText("native plan key"), digestForText("native plan request"), raw, "synthetic native activation plan", plan.ReadableDigest, now.Format(time.RFC3339), now.Add(30*time.Minute).Format(time.RFC3339))
	raw, _ = json.Marshal(b)
	exec(`INSERT INTO credential_lifecycle_bindings VALUES('native-binding',?,1,?,?,?,?,?,0,?)`, plan.DeclarationID, b.OperationID, string(b.Action), b.ReferenceID, b.Digest(), raw, now.Format(time.RFC3339))
	exec(`INSERT INTO effective_authorization_principals VALUES('principal-run-test','human','active',1,'now','now')`)
	exec(`INSERT INTO authorization_decisions VALUES('decision-native','principal-run-test','execute','credential.activate','execution-target',?,1,'human','allowed',1,1,0,?,?,'now','native-auth')`, b.TargetID, plan.PlanDigest, fp)
	exec(`INSERT INTO acknowledgement_requests VALUES('ack-native',?,?,?,?, 'principal-run-test','slack-fixture',?,1,0,?,'approved',?,?,'now','now','now')`, plan.PlanID, plan.PlanDigest, plan.Binding.TargetDigest, plan.Binding.ReasonDigest, digestForText("native ack nonce"), plan.ExpiresAt, []byte(`{}`), []byte(`{}`))
	run := testRun("run-native", "submit-native", now)
	run.PlanID, run.PlanDigest, run.AuthorizationDecisionID = plan.PlanID, plan.PlanDigest, "decision-native"
	ack := "ack-native"
	run.AcknowledgementID = &ack
	op := plan.Operations[0]
	run.Steps[0].OperationID, run.Steps[0].OperationType, run.Steps[0].AdapterID, run.Steps[0].TargetID = op.OperationID, op.OperationType, op.AdapterID, op.TargetID
	run.Steps[0].InputDigest, run.Steps[0].ArtifactDigest, run.Steps[0].Idempotent = fp, fp, false
	if _, err := r.Create(ctx, RunCreateRequest{Run: run, SubmitKeyDigest: digestForText("submit-native"), RequestDigest: digestForText("request-native"), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.TransitionRun(ctx, RunTransitionRequest{RunID: run.RunID, From: "queued", To: "running", At: now, Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	lease := testLease(run, run.Steps[0], now)
	if err := r.AcquireTargetLease(ctx, lease, runAttribution(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.BeginStep(ctx, StepBeginRequest{RunID: run.RunID, StepID: run.Steps[0].StepID, LeaseID: lease.LeaseID, At: now, Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	p := credentialref.NativeRestartPending{Version: 1, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: run.RunID, StepID: run.Steps[0].StepID, LeaseID: lease.LeaseID, Binding: b, Before: credentialref.NativeRestartBefore{ConsumerID: "host-action", MachineID: strings.Repeat("a", 32), BootID: "00000000-0000-0000-0000-000000000001", InvocationID: strings.Repeat("b", 32), MainPID: 42, ProcessStartTicks: 10, SourceDevice: 12, SourceInode: 13, SourceFingerprint: fp, RequestMonotonicNanos: 100000000}}
	return r, p, now
}

func TestNativeRestartPendingRequiresCurrentExecution(t *testing.T) {
	for _, mutation := range []string{"expired-lease", "revoked-principal", "changed-grant-revision", "changed-epoch", "wrong-target", "wrong-lease"} {
		t.Run(mutation, func(t *testing.T) {
			r, p, now := nativePendingFixture(t)
			ctx := context.Background()
			var err error
			switch mutation {
			case "expired-lease":
				r.store.config.Clock = func() time.Time { return now.Add(2 * time.Minute) }
			case "revoked-principal":
				_, err = r.store.conn.ExecContext(ctx, `UPDATE effective_authorization_principals SET status='revoked',grant_revision=2 WHERE principal_id='principal-run-test'`)
			case "changed-grant-revision":
				_, err = r.store.conn.ExecContext(ctx, `UPDATE effective_authorization_principals SET grant_revision=2 WHERE principal_id='principal-run-test'`)
			case "changed-epoch":
				_, err = r.store.conn.ExecContext(ctx, `UPDATE system_meta SET recovery_epoch=1 WHERE id=1`)
			case "wrong-target":
				p.Binding.TargetID = "other-host"
				p.Binding.NativeConsumers[0].TargetID = "other-host"
				p.Binding.NativeDeniedReaders[0].TargetID = "other-host"
			case "wrong-lease":
				p.LeaseID = "other-lease"
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := r.RecordNativeRestartPending(ctx, p, runAttribution(t)); err == nil {
				t.Fatal("unsafe restart intent accepted")
			}
			var count int
			if err := r.store.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM plan_run_steps WHERE native_restart_pending_bytes IS NOT NULL`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("denial persisted pending proof: %d, %v", count, err)
			}
		})
	}
}

func TestNativeRestartPendingPreservesPartialAndRejectsReplay(t *testing.T) {
	r, p, now := nativePendingFixture(t)
	ctx := context.Background()
	if err := r.RecordNativeRestartPending(ctx, p, runAttribution(t)); err != nil {
		t.Fatal(err)
	}
	if err := r.RecordNativeRestartPending(ctx, p, runAttribution(t)); err == nil {
		t.Fatal("duplicate pending intent accepted")
	}
	if _, err := r.ReadNativeRestartPending(ctx, p.RunID, p.StepID); err == nil {
		t.Fatal("running attempt eligible for completion")
	}
	if _, err := r.MarkStepUnknown(ctx, p.RunID, p.StepID, now.Add(time.Second), runAttribution(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.TransitionRun(ctx, RunTransitionRequest{RunID: p.RunID, From: "running", To: "partial", At: now.Add(time.Second), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	if err := r.ReleaseTargetLease(ctx, p.LeaseID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := NewRunRepository(r.store).ReadNativeRestartPending(ctx, p.RunID, p.StepID)
	if err != nil || got.Before.SourceInode != 13 || got.Before.MainPID != 42 {
		t.Fatalf("pending observation not durable: %+v, %v", got.Before, err)
	}
	if _, err := r.ReadNativeRestartPending(ctx, "different-run", p.StepID); err == nil {
		t.Fatal("wrong original run accepted")
	}
	if _, err := r.store.conn.ExecContext(ctx, `UPDATE plan_run_steps SET native_restart_consumed_run_id='completion-run',native_restart_consumed_step_id='completion-step' WHERE step_id=?`, p.StepID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadNativeRestartPending(ctx, p.RunID, p.StepID); err == nil {
		t.Fatal("consumed attempt accepted again")
	}
	old, err := r.Get(ctx, p.RunID)
	if err != nil || old.Status != "partial" || old.Steps[0].EffectState != "effect-unknown" {
		t.Fatalf("old interrupted run relabelled: %+v, %v", old, err)
	}
}

// This tests the store transaction boundary only. Invocation observations are
// synthetic; native systemd delivery is qualified separately.
func TestNativeRestartConsumptionRollsBackAndCannotReplay(t *testing.T) {
	r, p, now := nativePendingFixture(t)
	ctx := context.Background()
	if err := r.RecordNativeRestartPending(ctx, p, runAttribution(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.MarkStepUnknown(ctx, p.RunID, p.StepID, now.Add(time.Second), runAttribution(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.TransitionRun(ctx, RunTransitionRequest{RunID: p.RunID, From: "running", To: "partial", At: now.Add(time.Second), Attribution: runAttribution(t)}); err != nil {
		t.Fatal(err)
	}
	proof := credentialref.NativeInvocationMetadata{BootID: p.Before.BootID, InvocationID: strings.Repeat("c", 32), MainPID: 84, ProcessStartTicks: 20, NamespaceDevice: 1, NamespaceInode: 2, CredentialDevice: 3, CredentialInode: 4, CredentialUID: 1001, CredentialGID: 1001, CredentialMode: 0100400, SourceDevice: 12, SourceInode: 13, SourceFingerprint: p.Binding.CiphertextFingerprint}
	b := p.Binding
	b.OperationID = "complete-native"
	b.NativeRestartContinuation = &credentialref.NativeRestartContinuation{PriorRunID: p.RunID, PriorStepID: p.StepID, PendingDigest: credentialref.NativeRestartPendingDigest(p), Expected: proof}
	v, err := credentialref.NewConsumerVerification(b, "host-action", "profile-one", "control", string(digestForText("actual observed transition")), "native-systemd-delivery", "verified", true)
	if err != nil {
		t.Fatal(err)
	}
	v.NativeReceipt = &credentialref.NativeLoadedReceipt{Version: 1, Binding: b, ConsumerID: "host-action", PlanDigest: string(digestForText("completion plan")), RunID: "run-completion", StepID: "step-completion", Proof: proof}
	request := CredentialLifecycleApplyRequest{Binding: b, Stage: CredentialStageRequest{RunID: "run-completion", StepID: "step-completion", PlanDigest: v.NativeReceipt.PlanDigest}, Verifications: []credentialref.ConsumerVerification{v}}
	if !credentialref.ValidConsumerVerification(b, v) {
		t.Fatal("invalid synthetic verification fixture")
	}
	// A failed activation transaction must not consume its prior attempt.
	tx, err := r.store.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = consumeNativeRestartPending(ctx, tx, request); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ReadNativeRestartPending(ctx, p.RunID, p.StepID); err != nil {
		t.Fatalf("rollback lost continuation: %v", err)
	}
	// A receipt originating in another completion run cannot consume it.
	wrong := request
	wrong.Stage.RunID = "unrelated-completion"
	tx, err = r.store.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = consumeNativeRestartPending(ctx, tx, wrong)
	_ = tx.Rollback()
	if err == nil {
		t.Fatal("foreign completion receipt consumed original attempt")
	}
	tx, err = r.store.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = consumeNativeRestartPending(ctx, tx, request); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ReadNativeRestartPending(ctx, p.RunID, p.StepID); err == nil {
		t.Fatal("committed completion remained available")
	}
	tx, err = r.store.conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = consumeNativeRestartPending(ctx, tx, request)
	_ = tx.Rollback()
	if err == nil {
		t.Fatal("same completion replayed")
	}
	old, err := r.Get(ctx, p.RunID)
	if err != nil || old.Status != "partial" {
		t.Fatalf("completion rewrote original outcome: %s %v", old.Status, err)
	}
}
