//go:build linux

package store

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestExecutorLeaseIsSixtySecondsAndCannotBeWidenedOnRenewal(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	fixture := openExecutorLeaseFixture(t, now)

	lease, err := fixture.leases.Claim(context.Background(), ExecutorLeaseClaimRequest{
		Request:     fixture.claim,
		Lease:       fixture.lease,
		At:          now,
		Attribution: fixture.attribution,
	})
	if err != nil {
		t.Fatal(err)
	}
	if lease.LeaseExpiresAt != now.Add(60*time.Second).Format(time.RFC3339) {
		t.Fatalf("lease expiry = %q", lease.LeaseExpiresAt)
	}
	if lease.RenewAfter != now.Add(20*time.Second).Format(time.RFC3339) {
		t.Fatalf("renew after = %q", lease.RenewAfter)
	}

	widened := fixture.renewal(lease, now.Add(20*time.Second))
	widened.Request.BindingDigest = string(digestForText("different-binding"))
	if _, err := fixture.leases.Renew(context.Background(), widened); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("widened renewal code = %q", Code(err))
	}
}

func TestExecutorLeaseClaimIntentRecordsExactlyOneConcurrentWinner(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 1, 0, 0, time.UTC)
	fixture := openExecutorLeaseFixture(t, now)
	requests := []ExecutorLeaseClaimRequest{
		fixture.claimRequest(now),
		fixture.claimRequest(now),
	}
	requests[1].Lease.LeaseID = "lease-external-second"
	requests[1].Lease.NonceDigest = string(digestForText("external-nonce-second"))
	requests[1].Request.NonceDigest = requests[1].Lease.NonceDigest

	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, request := range requests {
		request := request
		go func() {
			ready.Done()
			<-start
			_, err := fixture.leases.Claim(context.Background(), request)
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	succeeded, denied := 0, 0
	for range 2 {
		switch Code(<-results) {
		case "":
			succeeded++
		case generated.ErrorCodeStateConflict, generated.ErrorCodeRecoveryRequired:
			denied++
		default:
			t.Fatal("unexpected concurrent claim result")
		}
	}
	if succeeded != 1 || denied != 1 {
		t.Fatalf("claim winners/denials = %d/%d", succeeded, denied)
	}
	storedRun, err := fixture.runs.Get(context.Background(), fixture.run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if storedRun.Steps[0].Status != "running" || storedRun.Steps[0].EffectState != "intent-recorded" {
		t.Fatalf("claimed step = %#v", storedRun.Steps[0])
	}
	var leases int
	if err := fixture.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM target_execution_leases WHERE step_id=?`, fixture.run.Steps[0].StepID).Scan(&leases); err != nil || leases != 1 {
		t.Fatalf("stored leases = %d, %v", leases, err)
	}
}

func TestExecutorLeaseRenewalRotatesNonceAtBoundariesWithoutExtendingAuthority(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 2, 0, 0, time.UTC)
	fixture := openExecutorLeaseFixture(t, now)
	lease := fixture.mustClaim(t, now)

	if _, err := fixture.leases.Renew(context.Background(), fixture.renewal(lease, now.Add(19*time.Second))); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("early renewal code = %q", Code(err))
	}
	renewal := fixture.renewal(lease, now.Add(20*time.Second))
	renewed, err := fixture.leases.Renew(context.Background(), renewal)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.NonceDigest != renewal.NextNonceDigest || renewed.RenewAfter != now.Add(40*time.Second).Format(time.RFC3339) {
		t.Fatalf("renewed lease = %#v", renewed)
	}
	if renewed.LeaseExpiresAt != lease.LeaseExpiresAt || renewed.MaximumExpiresAt != lease.MaximumExpiresAt || renewed.BindingDigest != lease.BindingDigest {
		t.Fatal("renewal widened immutable authority")
	}
	if _, err := fixture.leases.Renew(context.Background(), renewal); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("nonce replay code = %q", Code(err))
	}
	late := fixture.renewal(renewed, now.Add(60*time.Second))
	if _, err := fixture.leases.Renew(context.Background(), late); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("expiry-boundary renewal code = %q", Code(err))
	}
	var history int
	if err := fixture.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM executor_lease_nonce_history WHERE lease_id=?`, lease.LeaseID).Scan(&history); err != nil || history != 2 {
		t.Fatalf("nonce history = %d, %v", history, err)
	}
	rotatedBack := fixture.renewal(renewed, now.Add(40*time.Second))
	rotatedBack.NextNonceDigest = lease.NonceDigest
	if _, err := fixture.leases.Renew(context.Background(), rotatedBack); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("prior nonce rotation code = %q", Code(err))
	}
}

func TestExecutorLeaseRejectsWrongClaimBindingsAndChangedEpoch(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 3, 0, 0, time.UTC)
	cases := map[string]func(*ExecutorLeaseClaimRequest){
		"executor": func(request *ExecutorLeaseClaimRequest) { request.Request.ExecutorID = "executor-wrong" },
		"adapter":  func(request *ExecutorLeaseClaimRequest) { request.Request.AdapterID = "adapter-wrong" },
		"nonce": func(request *ExecutorLeaseClaimRequest) {
			request.Request.NonceDigest = string(digestForText("nonce-wrong"))
		},
		"target": func(request *ExecutorLeaseClaimRequest) { request.Lease.TargetID = "target-wrong" },
		"artifact": func(request *ExecutorLeaseClaimRequest) {
			request.Lease.ArtifactDigest = string(digestForText("artifact-wrong"))
		},
		"plan": func(request *ExecutorLeaseClaimRequest) {
			request.Lease.PlanDigest = string(digestForText("plan-wrong"))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := openExecutorLeaseFixture(t, now)
			request := fixture.claimRequest(now)
			mutate(&request)
			if _, err := fixture.leases.Claim(context.Background(), request); Code(err) != generated.ErrorCodeAuthorizationDenied {
				t.Fatalf("wrong %s code = %q", name, Code(err))
			}
		})
	}
	epoch := openExecutorLeaseFixture(t, now)
	request := epoch.claimRequest(now)
	request.Request.RecoveryEpoch++
	if _, err := epoch.leases.Claim(context.Background(), request); Code(err) != generated.ErrorCodeRecoveryEpochMismatch {
		t.Fatalf("wrong claim epoch code = %q", Code(err))
	}

	changed := openExecutorLeaseFixture(t, now)
	lease := changed.mustClaim(t, now)
	if _, err := changed.store.conn.ExecContext(context.Background(), `UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := changed.leases.Renew(context.Background(), changed.renewal(lease, now.Add(20*time.Second))); Code(err) != generated.ErrorCodeRecoveryEpochMismatch {
		t.Fatalf("changed recovery epoch renewal code = %q", Code(err))
	}
}

func TestExecutorLeaseClaimFencesCurrentRecoveryEpochInsideTransaction(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 3, 30, 0, time.UTC)
	fixture := openExecutorLeaseFixture(t, now)
	if _, err := fixture.store.conn.ExecContext(context.Background(), `UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.leases.Claim(context.Background(), fixture.claimRequest(now)); Code(err) != generated.ErrorCodeRecoveryEpochMismatch {
		t.Fatalf("claim after epoch advance code = %q", Code(err))
	}
	var leases int
	if err := fixture.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM target_execution_leases WHERE step_id=?`, fixture.run.Steps[0].StepID).Scan(&leases); err != nil || leases != 0 {
		t.Fatalf("epoch-fenced leases = %d, %v", leases, err)
	}
	stored, err := fixture.runs.Get(context.Background(), fixture.run.RunID)
	if err != nil || stored.Steps[0].Status != "queued" || stored.Steps[0].EffectState != "not-started" {
		t.Fatalf("epoch-fenced step = %#v, %v", stored.Steps, err)
	}
}

func TestExpiredExecutorReceiptIsUntrustedDurableAndCannotReclaim(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 4, 0, 0, time.UTC)
	fixture := openExecutorLeaseFixture(t, now)
	lease := fixture.mustClaim(t, now)
	expired, err := fixture.leases.Expire(context.Background(), ExecutorLeaseExpiryRequest{At: now.Add(60 * time.Second), Attribution: fixture.attribution})
	if err != nil || len(expired) != 1 || expired[0].Status != "expired" {
		t.Fatalf("expire = %#v, %v", expired, err)
	}
	stored, err := fixture.leases.Get(context.Background(), lease.LeaseID)
	if err != nil || stored.Status != "expired" {
		t.Fatalf("stored expired lease = %#v, %v", stored, err)
	}

	progress := fixture.receipt(stored, now.Add(61*time.Second))
	progress.Receipt.ReceiptID = "receipt-external-progress"
	progress.Receipt.Status = "running"
	progress.Receipt.ResultDigest = string(digestForText("external-progress"))
	if _, err := fixture.leases.RecordReceipt(context.Background(), ExecutorReceiptPersistenceRequest{Request: progress, At: now.Add(61 * time.Second), Attribution: fixture.attribution}); err != nil {
		t.Fatalf("record expired progress = %v", err)
	}
	progressRun, err := fixture.runs.Get(context.Background(), fixture.run.RunID)
	if err != nil || progressRun.Steps[0].EffectState != "intent-recorded" || progressRun.Steps[0].Status != "running" {
		t.Fatalf("progress changed durable intent = %#v, %v", progressRun.Steps, err)
	}
	receipt := fixture.receipt(stored, now.Add(62*time.Second))
	got, err := fixture.leases.RecordReceipt(context.Background(), ExecutorReceiptPersistenceRequest{Request: receipt, At: now.Add(62 * time.Second), Attribution: fixture.attribution})
	if err != nil || got.ReceiptID != receipt.Receipt.ReceiptID {
		t.Fatalf("record expired receipt = %#v, %v", got, err)
	}
	storedRun, err := fixture.runs.Get(context.Background(), fixture.run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if storedRun.Steps[0].EffectState != "receipt-recorded" || storedRun.Steps[0].Status != "running" {
		t.Fatalf("terminal observation did not stop at receipt-recorded = %#v", storedRun.Steps[0])
	}
	if _, err := fixture.leases.RecordReceipt(context.Background(), ExecutorReceiptPersistenceRequest{Request: receipt, At: now.Add(62 * time.Second), Attribution: fixture.attribution}); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("receipt replay code = %q", Code(err))
	}
	var observations int
	if err := fixture.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM external_execution_observations WHERE lease_id=?`, stored.LeaseID).Scan(&observations); err != nil || observations != 2 {
		t.Fatalf("progress and terminal observations = %d, %v", observations, err)
	}

	reclaim := fixture.claimRequest(now.Add(63 * time.Second))
	reclaim.Lease.LeaseID = "lease-external-reclaim"
	reclaim.Lease.NonceDigest = string(digestForText("external-reclaim-nonce"))
	reclaim.Request.NonceDigest = reclaim.Lease.NonceDigest
	if _, err := fixture.leases.Claim(context.Background(), reclaim); Code(err) != generated.ErrorCodeStateConflict && Code(err) != generated.ErrorCodeRecoveryRequired {
		t.Fatalf("blind reclaim code = %q", Code(err))
	}
}

func TestExpiredExecutorLeaseRecoveryDiscoverySurvivesRetryAndRestart(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 4, 30, 0, time.UTC)
	fixture := openExecutorLeaseFixture(t, now)
	lease := fixture.mustClaim(t, now)
	request := ExecutorLeaseExpiryRequest{At: now.Add(60 * time.Second), Attribution: fixture.attribution}
	first, err := fixture.leases.Expire(context.Background(), request)
	if err != nil || len(first) != 1 || first[0].LeaseID != lease.LeaseID {
		t.Fatalf("first expiry discovery = %#v, %v", first, err)
	}
	retry, err := fixture.leases.Expire(context.Background(), request)
	if err != nil || len(retry) != 1 || retry[0].LeaseID != lease.LeaseID {
		t.Fatalf("same-request expiry recovery = %#v, %v", retry, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.closed = true
	fixture.config.Mode = OpenExisting
	reopened, err := Open(context.Background(), fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	repository := NewExecutorLeaseRepository(reopened)
	afterRestart, err := repository.Expire(context.Background(), ExecutorLeaseExpiryRequest{At: now.Add(61 * time.Second), Attribution: fixture.attribution})
	if err != nil || len(afterRestart) != 1 || afterRestart[0].LeaseID != lease.LeaseID {
		t.Fatalf("restart expiry recovery = %#v, %v", afterRestart, err)
	}

	stored, err := repository.Get(context.Background(), lease.LeaseID)
	if err != nil {
		t.Fatal(err)
	}
	receipt := fixture.receipt(stored, now.Add(62*time.Second))
	if _, err := repository.RecordReceipt(context.Background(), ExecutorReceiptPersistenceRequest{Request: receipt, At: now.Add(62 * time.Second), Attribution: fixture.attribution}); err != nil {
		t.Fatal(err)
	}
	receiptPending, err := repository.Expire(context.Background(), ExecutorLeaseExpiryRequest{At: now.Add(63 * time.Second), Attribution: fixture.attribution})
	if err != nil || len(receiptPending) != 1 || receiptPending[0].LeaseID != lease.LeaseID {
		t.Fatalf("receipt-recorded expiry recovery = %#v, %v", receiptPending, err)
	}

	runs := NewRunRepository(reopened)
	if _, err := runs.MarkStepUnknown(context.Background(), fixture.run.RunID, fixture.run.Steps[0].StepID, now.Add(64*time.Second), fixture.attribution); err != nil {
		t.Fatal(err)
	}
	unknown, err := repository.Expire(context.Background(), ExecutorLeaseExpiryRequest{At: now.Add(65 * time.Second), Attribution: fixture.attribution})
	if err != nil || len(unknown) != 1 || unknown[0].LeaseID != lease.LeaseID {
		t.Fatalf("effect-unknown expiry recovery = %#v, %v", unknown, err)
	}
}

func TestExecutorAuthorizationDenialAuditStoresOnlyFingerprints(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 4, 45, 0, time.UTC)
	fixture := openExecutorLeaseFixture(t, now)
	reasonCanary := "raw-denial-reason-must-not-persist"
	targetCanary := "raw-denial-target-must-not-persist"
	request := ExecutorAuthorizationDenialRequest{
		ReasonFingerprint: digestForText(reasonCanary),
		TargetFingerprint: digestForText(targetCanary),
		At:                now,
		Attribution:       fixture.attribution,
	}
	if err := fixture.leases.RecordAuthorizationDenial(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := fixture.leases.RecordAuthorizationDenial(context.Background(), request); err != nil {
		t.Fatalf("idempotent denial replay = %v", err)
	}
	var targetID, after string
	var canonical []byte
	var count int
	if err := fixture.store.conn.QueryRowContext(context.Background(), `SELECT target_id,after_fingerprint,canonical_payload FROM audit_events WHERE event_type='run.external-authorization-denied'`).Scan(&targetID, &after, &canonical); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_events WHERE event_type='run.external-authorization-denied'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if targetID != string(request.TargetFingerprint) || after != string(request.ReasonFingerprint) || count != 1 {
		t.Fatalf("denial audit target/reason/count = %q/%q/%d", targetID, after, count)
	}
	payload := string(canonical)
	if strings.Contains(payload, reasonCanary) || strings.Contains(payload, targetCanary) {
		t.Fatalf("denial audit leaked caller plaintext: %s", payload)
	}
}

func TestExecutorReceiptRejectsTampering(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 5, 0, 0, time.UTC)
	fixture := openExecutorLeaseFixture(t, now)
	lease := fixture.mustClaim(t, now)
	receipt := fixture.receipt(lease, now.Add(time.Second))
	receipt.Receipt.TargetID = "target-wrong"
	if _, err := fixture.leases.RecordReceipt(context.Background(), ExecutorReceiptPersistenceRequest{Request: receipt, At: now.Add(time.Second), Attribution: fixture.attribution}); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("tampered receipt code = %q", Code(err))
	}
}

func TestVerifiedExternalReceiptCanFinishDurableStep(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 5, 30, 0, time.UTC)
	fixture := openExecutorLeaseFixture(t, now)
	lease := fixture.mustClaim(t, now)
	request := fixture.receipt(lease, now.Add(time.Second))
	if _, err := fixture.leases.RecordReceipt(context.Background(), ExecutorReceiptPersistenceRequest{Request: request, At: now.Add(time.Second), Attribution: fixture.attribution}); err != nil {
		t.Fatal(err)
	}
	finished, err := fixture.runs.FinishStep(context.Background(), StepFinishRequest{
		RunID: fixture.run.RunID, StepID: fixture.run.Steps[0].StepID, LeaseID: lease.LeaseID,
		Receipt: request.Receipt, Status: "succeeded", EffectState: "verified",
		VerificationDigest: string(digestForText("external-verification")), Changed: true,
		At: now.Add(2 * time.Second), Attribution: fixture.attribution,
	})
	if err != nil || finished.Steps[0].EffectState != "verified" || finished.Steps[0].Status != "succeeded" {
		t.Fatalf("finish external step = %#v, %v", finished, err)
	}
}

func TestExecutorLeasePersistsAcrossRestart(t *testing.T) {
	now := time.Date(2026, 9, 13, 0, 6, 0, 0, time.UTC)
	fixture := openExecutorLeaseFixture(t, now)
	lease := fixture.mustClaim(t, now)
	renewed, err := fixture.leases.Renew(context.Background(), fixture.renewal(lease, now.Add(20*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.closed = true
	fixture.config.Mode = OpenExisting
	reopened, err := Open(context.Background(), fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	got, err := NewExecutorLeaseRepository(reopened).Get(context.Background(), renewed.LeaseID)
	if err != nil || got.NonceDigest != renewed.NonceDigest || got.RenewAfter != renewed.RenewAfter || got.LeaseExpiresAt != renewed.LeaseExpiresAt {
		t.Fatalf("restarted lease = %#v, %v", got, err)
	}
}

type executorLeaseFixture struct {
	store       *Store
	leases      *ExecutorLeaseRepository
	runs        *RunRepository
	run         generated.Run
	claim       generated.ExecutorClaimRequest
	lease       generated.ExecutorLease
	attribution audit.Attribution
	config      Config
	closed      bool
}

func openExecutorLeaseFixture(t *testing.T, now time.Time) *executorLeaseFixture {
	t.Helper()
	config := testConfig(t)
	config.Clock = func() time.Time { return now }
	authority, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &executorLeaseFixture{store: authority, leases: NewExecutorLeaseRepository(authority), runs: NewRunRepository(authority), config: config, attribution: runAttribution(t)}
	t.Cleanup(func() {
		if !fixture.closed {
			_ = authority.Close()
		}
	})
	if _, err := authority.conn.ExecContext(context.Background(), `UPDATE system_meta SET state_revision=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedExternalRunPlan(t, authority, now)
	fixture.run = externalTestRun(now)
	if _, err := fixture.runs.Create(context.Background(), RunCreateRequest{Run: fixture.run, SubmitKeyDigest: digestForText("external-submit"), RequestDigest: digestForText("external-request"), Attribution: fixture.attribution}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runs.TransitionRun(context.Background(), RunTransitionRequest{RunID: fixture.run.RunID, From: "queued", To: "running", At: now, Attribution: fixture.attribution}); err != nil {
		t.Fatal(err)
	}
	fixture.run, err = fixture.runs.Get(context.Background(), fixture.run.RunID)
	if err != nil {
		t.Fatal(err)
	}
	fixture.lease = externalTestLease(fixture.run, now)
	fixture.claim = generated.ExecutorClaimRequest{Schema: generated.SchemaIDExecutorClaimRequest, SchemaVersion: "1.0.0", ExecutorID: fixture.lease.ExecutorID, PrincipalID: fixture.attribution.AuthenticatedPrincipalID, AdapterID: fixture.lease.AdapterID, RecoveryEpoch: fixture.lease.RecoveryEpoch, NonceDigest: fixture.lease.NonceDigest, Extensions: []generated.ContractExtension{}}
	return fixture
}

func (fixture *executorLeaseFixture) claimRequest(at time.Time) ExecutorLeaseClaimRequest {
	lease := fixture.lease
	lease.ClaimedAt = at.Format(time.RFC3339)
	lease.RenewAfter = at.Add(20 * time.Second).Format(time.RFC3339)
	lease.LeaseExpiresAt = at.Add(60 * time.Second).Format(time.RFC3339)
	lease.MaximumExpiresAt = lease.LeaseExpiresAt
	return ExecutorLeaseClaimRequest{Request: fixture.claim, Lease: lease, At: at, Attribution: fixture.attribution}
}

func (fixture *executorLeaseFixture) mustClaim(t *testing.T, at time.Time) generated.ExecutorLease {
	t.Helper()
	lease, err := fixture.leases.Claim(context.Background(), fixture.claimRequest(at))
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func (fixture *executorLeaseFixture) renewal(lease generated.ExecutorLease, at time.Time) ExecutorLeaseRenewalRequest {
	return ExecutorLeaseRenewalRequest{
		Request:         generated.ExecutorRenewRequest{Schema: generated.SchemaIDExecutorRenewRequest, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch, Extensions: []generated.ContractExtension{}},
		NextNonceDigest: string(digestForText("next-nonce-" + at.Format(time.RFC3339))), At: at, Attribution: fixture.attribution,
	}
}

func (fixture *executorLeaseFixture) receipt(lease generated.ExecutorLease, at time.Time) generated.ExecutionReceiptRequest {
	receipt := generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, OperationID: lease.OperationID, ExecutorID: lease.ExecutorID, AdapterID: lease.AdapterID, TargetID: lease.TargetID, ArtifactDigest: lease.ArtifactDigest, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch, ReceiptID: "receipt-external", Status: "succeeded", ResultDigest: string(digestForText("external-result")), RecordedAt: at.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	return generated.ExecutionReceiptRequest{Schema: generated.SchemaIDExecutionReceiptRequest, SchemaVersion: "1.0.0", Receipt: receipt, ExpectedBindingDigest: lease.BindingDigest, Extensions: []generated.ContractExtension{}}
}

func seedExternalRunPlan(t *testing.T, authority *Store, now time.Time) {
	t.Helper()
	declaration := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: "declaration-external-test", DeclarationType: "application", Revision: 1, StateRevision: 1, RecoveryEpoch: 0, ContentDigest: string(digestForText("external-content")), Status: "committed", Operations: []generated.DeclarationOperation{}, CreatedAt: now.Format(time.RFC3339), CreatedBy: "principal-run-test", AgentSessionID: "session-run-test", Extensions: []generated.ContractExtension{}}
	declarationBytes, _ := json.Marshal(declaration)
	if _, err := authority.conn.ExecContext(context.Background(), `INSERT INTO declaration_revisions(declaration_id,declaration_revision,declaration_type,state_revision,recovery_epoch,content_digest,reason_digest,status,canonical_bytes,created_at,created_by,agent_session_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, declaration.DeclarationID, declaration.Revision, declaration.DeclarationType, declaration.StateRevision, declaration.RecoveryEpoch, declaration.ContentDigest, digestForText("external-reason"), declaration.Status, declarationBytes, declaration.CreatedAt, declaration.CreatedBy, declaration.AgentSessionID); err != nil {
		t.Fatal(err)
	}
	executorID := "executor-external"
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-external-test", PlanDigest: string(digestForText("external-plan")), DeclarationID: declaration.DeclarationID, Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 0, StateRevision: 1, DeclarationRevision: 1, ObservationFingerprint: string(digestForText("external-observation")), TargetDigest: string(digestForText("external-target")), ReasonDigest: string(digestForText("external-reason")), PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-external-test", OperationType: "application.deploy.low-risk", AdapterID: "adapter-test", ExecutorID: executorID, TargetID: "target-external-test", InputDigest: string(digestForText("external-input")), ArtifactDigest: string(digestForText("external-artifact")), Idempotent: true}}, Status: "planned", Risk: "routine", AuthorizationBranch: "preauthorized", ExecutorMode: "external", ExecutorID: &executorID, CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339), ReadableDigest: string(digestForText("external-readable")), Extensions: []generated.ContractExtension{}}
	planBytes, _ := json.Marshal(plan)
	if _, err := authority.conn.ExecContext(context.Background(), `INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, plan.PlanID, plan.PlanDigest, plan.DeclarationID, plan.Binding.DeclarationRevision, plan.Binding.StateRevision, plan.Binding.RecoveryEpoch, plan.Binding.ObservationFingerprint, digestForText("external-plan-key"), digestForText("external-plan-request"), planBytes, "external test plan", plan.ReadableDigest, plan.CreatedAt, plan.ExpiresAt); err != nil {
		t.Fatal(err)
	}
}

func externalTestRun(at time.Time) generated.Run {
	return generated.Run{Schema: generated.SchemaIDRun, SchemaVersion: "1.0.0", RunID: "run-external-test", PlanID: "plan-external-test", PlanDigest: string(digestForText("external-plan")), AuthorizationDecisionID: "decision-external-test", PolicyVersion: "1.0.0", ExecutorMode: "external", ExecutorID: "executor-external", ExecutorBindingDigest: string(digestForText("external-binding")), Status: "queued", Steps: []generated.RunStep{{Sequence: 1, OperationID: "operation-external-test", OperationType: "application.deploy.low-risk", AdapterID: "adapter-test", ExecutorID: "executor-external", TargetID: "target-external-test", InputDigest: string(digestForText("external-input")), ArtifactDigest: string(digestForText("external-artifact")), Idempotent: true, StepID: "step-external-test", Status: "queued", EffectState: "not-started"}}, CancellationRequested: false, RollbackStatus: "not-requested", VerificationStatus: "pending", Changed: false, StateRevision: 1, RecoveryEpoch: 0, CreatedAt: at.Format(time.RFC3339), UpdatedAt: at.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
}

func externalTestLease(run generated.Run, at time.Time) generated.ExecutorLease {
	step := run.Steps[0]
	return generated.ExecutorLease{Schema: generated.SchemaIDExecutorLease, SchemaVersion: "1.0.0", LeaseID: "lease-external-test", PlanID: run.PlanID, PlanDigest: run.PlanDigest, RunID: run.RunID, StepID: step.StepID, OperationID: step.OperationID, ExecutorID: run.ExecutorID, AdapterID: step.AdapterID, TargetID: step.TargetID, ArtifactDigest: step.ArtifactDigest, BindingDigest: run.ExecutorBindingDigest, NonceDigest: string(digestForText("external-nonce")), RecoveryEpoch: run.RecoveryEpoch, ClaimedAt: at.Format(time.RFC3339), RenewAfter: at.Add(20 * time.Second).Format(time.RFC3339), LeaseExpiresAt: at.Add(60 * time.Second).Format(time.RFC3339), MaximumExpiresAt: at.Add(60 * time.Second).Format(time.RFC3339), Status: "active", Extensions: []generated.ContractExtension{}}
}
