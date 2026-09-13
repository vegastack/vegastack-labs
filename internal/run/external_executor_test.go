package run

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestExternalRunWaitsForClaimWithoutCallingAdapter(t *testing.T) {
	fixture := newEngineFixture(t)
	executorID := "executor-external"
	fixture.store.plan.ExecutorMode = "external"
	fixture.store.plan.ExecutorID = &executorID
	fixture.store.plan.Operations[0].ExecutorID = executorID

	got, err := fixture.engine.Submit(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "running" || len(got.Steps) != 1 || got.Steps[0].Status != "queued" || got.Steps[0].EffectState != "not-started" {
		t.Fatalf("external run = %#v", got)
	}
	if fixture.adapter.calls != 0 {
		t.Fatalf("external submission called adapter %d times", fixture.adapter.calls)
	}
}

func TestExternalClaimRenewProgressAndVerifiedReceipt(t *testing.T) {
	fixture := newExternalExecutorFixture(t)
	lease := fixture.claim(t)
	if parseTime(lease.LeaseExpiresAt).Sub(parseTime(lease.ClaimedAt)) != 60*time.Second || parseTime(lease.RenewAfter).Sub(parseTime(lease.ClaimedAt)) != 20*time.Second {
		t.Fatalf("lease timing = %#v", lease)
	}
	if fixture.engine.adapter.calls != 0 {
		t.Fatalf("claim called Execute %d times", fixture.engine.adapter.calls)
	}

	fixture.setNow(fixture.now.Add(10 * time.Second))
	if _, err := fixture.external.SubmitReceipt(context.Background(), fixture.principal, receiptRequest(lease, "receipt-progress", "running")); err != nil {
		t.Fatal(err)
	}
	run, _ := fixture.engine.engine.Get(context.Background(), fixture.engine.runID)
	if run.Status != "running" || run.Steps[0].EffectState != "intent-recorded" {
		t.Fatalf("progress changed authority state = %#v", run)
	}

	fixture.setNow(parseTime(lease.RenewAfter))
	renewed, err := fixture.external.Renew(context.Background(), fixture.principal, generated.ExecutorRenewRequest{
		Schema: generated.SchemaIDExecutorRenewRequest, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID,
		BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch,
		Extensions: []generated.ContractExtension{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if renewed.NonceDigest == lease.NonceDigest || renewed.LeaseExpiresAt != lease.LeaseExpiresAt {
		t.Fatalf("renewed lease widened or did not rotate = %#v", renewed)
	}

	fixture.setNow(fixture.now.Add(time.Second))
	if _, err := fixture.external.SubmitReceipt(context.Background(), fixture.principal, receiptRequest(renewed, "receipt-terminal", "succeeded")); err != nil {
		t.Fatal(err)
	}
	run, _ = fixture.engine.engine.Get(context.Background(), fixture.engine.runID)
	if run.Status != "succeeded" || run.VerificationStatus != "verified" || !run.Changed || run.Steps[0].EffectState != "verified" {
		t.Fatalf("verified external run = %#v", run)
	}
	if fixture.engine.adapter.calls != 0 {
		t.Fatalf("receipt called Execute %d times", fixture.engine.adapter.calls)
	}
}

func TestExternalClaimRejectsWrongIdentityBeforeReturningWork(t *testing.T) {
	fixture := newExternalExecutorFixture(t)
	wrong := fixture.principal
	wrong.ID = "executor-wrong"
	if _, err := fixture.external.Claim(context.Background(), wrong, fixture.claimRequest()); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("wrong identity code = %q", Code(err))
	}
	if len(fixture.leases.leases) != 0 || fixture.engine.adapter.calls != 0 {
		t.Fatalf("wrong identity returned work: leases=%d execute=%d", len(fixture.leases.leases), fixture.engine.adapter.calls)
	}
	if fixture.leases.denials != 1 {
		t.Fatalf("denial audits = %d", fixture.leases.denials)
	}
}

func TestExternalClaimIsServerOrderedSingleWorkAndStopsOnCancellation(t *testing.T) {
	t.Run("adapter cannot skip the first operation", func(t *testing.T) {
		fixture := newExternalExecutorFixtureWithSecondStep(t)
		request := fixture.claimRequest()
		request.AdapterID = "adapter-later"
		if _, err := fixture.external.Claim(context.Background(), fixture.principal, request); Code(err) != generated.ErrorCodeAuthorizationDenied {
			t.Fatalf("skip adapter code = %q", Code(err))
		}
		if len(fixture.leases.leases) != 0 {
			t.Fatal("caller-selected later step received work")
		}
		fixture.claim(t)
		request.AdapterID = "adapter-later"
		if _, err := fixture.external.Claim(context.Background(), fixture.principal, request); Code(err) != generated.ErrorCodeStateConflict {
			t.Fatalf("second active work code = %q", Code(err))
		}
		if len(fixture.leases.leases) != 1 {
			t.Fatalf("active leases = %d", len(fixture.leases.leases))
		}
	})

	t.Run("cancellation blocks the first claim", func(t *testing.T) {
		fixture := newExternalExecutorFixture(t)
		cancelled, err := fixture.engine.engine.Cancel(context.Background(), fixture.engine.runID)
		if err != nil || cancelled.Status != "interrupted" {
			t.Fatalf("cancel before claim = %#v, %v", cancelled, err)
		}
		if _, err := fixture.external.Claim(context.Background(), fixture.principal, fixture.claimRequest()); Code(err) != generated.ErrorCodeResourceNotFound {
			t.Fatalf("cancelled claim code = %q", Code(err))
		}
		if len(fixture.leases.leases) != 0 {
			t.Fatal("cancelled run received work")
		}
	})

	t.Run("cancellation after a claim stops the next operation", func(t *testing.T) {
		fixture := newExternalExecutorFixtureWithSecondStep(t)
		lease := fixture.claim(t)
		if _, err := fixture.engine.engine.Cancel(context.Background(), fixture.engine.runID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.external.SubmitReceipt(context.Background(), fixture.principal, receiptRequest(lease, "receipt-cancel-boundary", "succeeded")); err != nil {
			t.Fatal(err)
		}
		current, _ := fixture.engine.engine.Get(context.Background(), fixture.engine.runID)
		if current.Status != "interrupted" || current.Steps[1].Status != "interrupted" {
			t.Fatalf("cancel boundary run = %#v", current)
		}
		request := fixture.claimRequest()
		request.AdapterID = "adapter-later"
		if _, err := fixture.external.Claim(context.Background(), fixture.principal, request); Code(err) != generated.ErrorCodeResourceNotFound {
			t.Fatalf("claim after cancellation code = %q", Code(err))
		}
	})
}

func TestExternalReconcilerRetriesTransientFailureUntilLeaseIsSettled(t *testing.T) {
	fixture := newExternalExecutorFixture(t)
	lease := fixture.claim(t)
	fixture.setNow(parseTime(lease.LeaseExpiresAt).Add(time.Second))
	fixture.leases.expireFailures = 1
	fixture.external.sweepInterval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fixture.external.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		current, _ := fixture.engine.engine.Get(context.Background(), fixture.engine.runID)
		if current.Status == "partial" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("transient reconciliation failure permanently stopped expiry")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestExternalReconcilerFinishesRecoveryAfterCrashBetweenStepAndRunTransition(t *testing.T) {
	fixture := newExternalExecutorFixture(t)
	lease := fixture.claim(t)
	fixture.setNow(parseTime(lease.LeaseExpiresAt).Add(time.Second))
	expired, err := fixture.leases.Expire(context.Background(), store.ExecutorLeaseExpiryRequest{At: fixture.now, Attribution: systemAttribution()})
	if err != nil || len(expired) != 1 {
		t.Fatalf("expire = %#v, %v", expired, err)
	}
	if _, err := fixture.engine.store.MarkStepUnknown(context.Background(), fixture.engine.runID, lease.StepID, fixture.now, systemAttribution()); err != nil {
		t.Fatal(err)
	}
	if err := fixture.external.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, _ := fixture.engine.engine.Get(context.Background(), fixture.engine.runID)
	if current.Status != "partial" || current.Steps[0].Status != "partial" || current.Steps[0].EffectState != "effect-unknown" {
		t.Fatalf("recovered crash state = %#v", current)
	}
}

func TestExpiredLeaseAndTamperedOrUnverifiedSuccessRequireRecovery(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		fixture := newExternalExecutorFixture(t)
		lease := fixture.claim(t)
		fixture.setNow(parseTime(lease.LeaseExpiresAt).Add(time.Second))
		if err := fixture.external.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
		run, _ := fixture.engine.engine.Get(context.Background(), fixture.engine.runID)
		if run.Status != "partial" || run.VerificationStatus != "incomplete" || run.RollbackStatus != "required" {
			t.Fatalf("expired run = %#v", run)
		}
		if _, err := fixture.external.Claim(context.Background(), fixture.principal, fixture.claimRequest()); Code(err) != generated.ErrorCodeResourceNotFound {
			t.Fatalf("blind reassignment code = %q", Code(err))
		}
	})

	t.Run("tampered receipt", func(t *testing.T) {
		fixture := newExternalExecutorFixture(t)
		lease := fixture.claim(t)
		request := receiptRequest(lease, "receipt-tampered", "succeeded")
		request.Receipt.ArtifactDigest = digest("widened-artifact")
		if _, err := fixture.external.SubmitReceipt(context.Background(), fixture.principal, request); Code(err) != generated.ErrorCodeRecoveryRequired {
			t.Fatalf("tampered receipt code = %q", Code(err))
		}
		run, _ := fixture.engine.engine.Get(context.Background(), fixture.engine.runID)
		if run.Status != "partial" || len(fixture.leases.receipts) != 0 {
			t.Fatalf("tampered receipt state = %#v receipts=%d", run, len(fixture.leases.receipts))
		}
	})

	t.Run("independent verification failed", func(t *testing.T) {
		fixture := newExternalExecutorFixture(t)
		fixture.engine.adapter.verify = false
		lease := fixture.claim(t)
		if _, err := fixture.external.SubmitReceipt(context.Background(), fixture.principal, receiptRequest(lease, "receipt-unverified", "succeeded")); Code(err) != generated.ErrorCodeRecoveryRequired {
			t.Fatalf("unverified receipt code = %q", Code(err))
		}
		run, _ := fixture.engine.engine.Get(context.Background(), fixture.engine.runID)
		if run.Status != "partial" {
			t.Fatalf("unverified receipt run = %#v", run)
		}
	})
}

type externalExecutorFixture struct {
	engine    *engineFixture
	external  *ExternalExecutor
	leases    *memoryExternalLeases
	principal identity.Principal
	now       time.Time
}

func newExternalExecutorFixture(t *testing.T) *externalExecutorFixture {
	return newExternalExecutorFixtureWithPlan(t, false)
}

func newExternalExecutorFixtureWithSecondStep(t *testing.T) *externalExecutorFixture {
	return newExternalExecutorFixtureWithPlan(t, true)
}

func newExternalExecutorFixtureWithPlan(t *testing.T, secondStep bool) *externalExecutorFixture {
	t.Helper()
	engine := newEngineFixture(t)
	executorID := "executor-external"
	engine.store.plan.ExecutorMode = "external"
	engine.store.plan.ExecutorID = &executorID
	engine.store.plan.Operations[0].ExecutorID = executorID
	if secondStep {
		second := engine.store.plan.Operations[0]
		second.Sequence = 2
		second.OperationID = "operation-later"
		second.AdapterID = "adapter-later"
		second.TargetID = "target-later"
		second.InputDigest = digest("input-later")
		second.ArtifactDigest = digest("artifact-later")
		engine.store.plan.Operations = append(engine.store.plan.Operations, second)
	}
	got, err := engine.engine.Submit(context.Background(), engine.request)
	if err != nil || got.Status != "running" {
		t.Fatalf("submit external run = %#v, %v", got, err)
	}
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	leases := &memoryExternalLeases{runs: engine.store, leases: map[string]generated.ExecutorLease{}, receipts: map[string]generated.ExecutionReceipt{}}
	fixture := &externalExecutorFixture{engine: engine, leases: leases, principal: identity.Principal{ID: executorID, Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalPolicy}, now: now}
	fixture.external, err = NewExternalExecutor(ExternalExecutorConfig{Runs: engine.store, Leases: leases, Plans: engine.store, Admission: allowAdmission{}, Adapters: engine.engine.adapters, Clock: func() time.Time { return fixture.now }, IDs: &deterministicIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *externalExecutorFixture) setNow(value time.Time) { fixture.now = value.UTC() }

func (fixture *externalExecutorFixture) claimRequest() generated.ExecutorClaimRequest {
	return generated.ExecutorClaimRequest{Schema: generated.SchemaIDExecutorClaimRequest, SchemaVersion: "1.0.0", ExecutorID: fixture.principal.ID, PrincipalID: fixture.principal.ID, AdapterID: "adapter-test", RecoveryEpoch: 0, NonceDigest: digest("claim-nonce"), Extensions: []generated.ContractExtension{}}
}

func (fixture *externalExecutorFixture) claim(t *testing.T) generated.ExecutorLease {
	t.Helper()
	lease, err := fixture.external.Claim(context.Background(), fixture.principal, fixture.claimRequest())
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func receiptRequest(lease generated.ExecutorLease, id, status string) generated.ExecutionReceiptRequest {
	receipt := generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, OperationID: lease.OperationID, ExecutorID: lease.ExecutorID, AdapterID: lease.AdapterID, TargetID: lease.TargetID, ArtifactDigest: lease.ArtifactDigest, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch, ReceiptID: id, Status: status, ResultDigest: digest(id), RecordedAt: time.Date(2026, 9, 13, 0, 0, 10, 0, time.UTC).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	return generated.ExecutionReceiptRequest{Schema: generated.SchemaIDExecutionReceiptRequest, SchemaVersion: "1.0.0", Receipt: receipt, ExpectedBindingDigest: lease.BindingDigest, Extensions: []generated.ContractExtension{}}
}

type memoryExternalLeases struct {
	mu             sync.Mutex
	runs           *memoryRepository
	leases         map[string]generated.ExecutorLease
	receipts       map[string]generated.ExecutionReceipt
	expireFailures int
	denials        int
}

func (repository *memoryExternalLeases) Claim(_ context.Context, request store.ExecutorLeaseClaimRequest) (generated.ExecutorLease, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if len(repository.leases) != 0 {
		return generated.ExecutorLease{}, runError(generated.ErrorCodeRecoveryRequired, "executor-lease")
	}
	repository.runs.mu.Lock()
	defer repository.runs.mu.Unlock()
	run := repository.runs.runs[request.Lease.RunID]
	step := findRunStep(run, request.Lease.StepID)
	step.Status, step.EffectState = "running", "intent-recorded"
	repository.runs.runs[run.RunID] = run
	repository.runs.leases[request.Lease.LeaseID] = request.Lease
	repository.runs.targets[request.Lease.TargetID] = request.Lease.LeaseID
	repository.leases[request.Lease.LeaseID] = request.Lease
	return request.Lease, nil
}

func (repository *memoryExternalLeases) Renew(_ context.Context, request store.ExecutorLeaseRenewalRequest) (generated.ExecutorLease, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	lease := repository.leases[request.Request.LeaseID]
	if lease.Status != "active" || lease.NonceDigest != request.Request.NonceDigest || request.At.Before(parseTime(lease.RenewAfter)) || !request.At.Before(parseTime(lease.LeaseExpiresAt)) {
		return generated.ExecutorLease{}, runError(generated.ErrorCodeStateConflict, "executor-renew")
	}
	lease.NonceDigest = request.NextNonceDigest
	lease.RenewAfter = request.At.Add(20 * time.Second).Format(time.RFC3339)
	repository.leases[lease.LeaseID] = lease
	repository.runs.mu.Lock()
	repository.runs.leases[lease.LeaseID] = lease
	repository.runs.mu.Unlock()
	return lease, nil
}

func (repository *memoryExternalLeases) Expire(_ context.Context, request store.ExecutorLeaseExpiryRequest) ([]generated.ExecutorLease, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.expireFailures > 0 {
		repository.expireFailures--
		return nil, errors.New("transient expiry failure")
	}
	result := []generated.ExecutorLease{}
	for id, lease := range repository.leases {
		if lease.Status == "active" && !request.At.Before(parseTime(lease.LeaseExpiresAt)) {
			lease.Status = "expired"
			repository.leases[id] = lease
			repository.runs.mu.Lock()
			repository.runs.leases[id] = lease
			delete(repository.runs.targets, lease.TargetID)
			repository.runs.mu.Unlock()
			result = append(result, lease)
			continue
		}
		if lease.Status == "expired" {
			repository.runs.mu.Lock()
			run := repository.runs.runs[lease.RunID]
			step := findRunStep(run, lease.StepID)
			unsettled := run.Status == "running" && step != nil && step.Status == "partial" && step.EffectState == "effect-unknown"
			repository.runs.mu.Unlock()
			if unsettled {
				result = append(result, lease)
			}
		}
	}
	return result, nil
}

func (repository *memoryExternalLeases) RecordReceipt(_ context.Context, request store.ExecutorReceiptPersistenceRequest) (generated.ExecutionReceipt, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	receipt := request.Request.Receipt
	lease := repository.leases[receipt.LeaseID]
	if generated.ValidateExecutionReceiptBinding(lease, receipt) != nil {
		return generated.ExecutionReceipt{}, runError(generated.ErrorCodeAuthorizationDenied, "executor-receipt")
	}
	repository.receipts[receipt.ReceiptID] = receipt
	if receipt.Status != "running" {
		repository.runs.mu.Lock()
		run := repository.runs.runs[receipt.RunID]
		step := findRunStep(run, receipt.StepID)
		step.EffectState = "receipt-recorded"
		repository.runs.runs[run.RunID] = run
		repository.runs.mu.Unlock()
	}
	return receipt, nil
}

func (repository *memoryExternalLeases) Get(_ context.Context, id string) (generated.ExecutorLease, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	lease, ok := repository.leases[id]
	if !ok {
		return generated.ExecutorLease{}, runError(generated.ErrorCodeResourceNotFound, "executor-lease")
	}
	return lease, nil
}

func (repository *memoryExternalLeases) RecordAuthorizationDenial(_ context.Context, _ store.ExecutorAuthorizationDenialRequest) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.denials++
	return nil
}

func (adapterFixture *fakeAdapter) VerifyReceipt(_ context.Context, _ adapter.Operation, observation adapter.ReceiptObservation) (adapter.ReceiptVerification, error) {
	return adapter.ReceiptVerification{Verified: adapterFixture.verify, Digest: digest("receipt-verification", observation.ResultDigest), Changed: adapterFixture.changed}, nil
}

var _ ExternalLeaseRepository = (*memoryExternalLeases)(nil)
var _ adapter.ReceiptVerifier = (*fakeAdapter)(nil)
