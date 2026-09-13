package run

import (
	"context"
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
	t.Helper()
	engine := newEngineFixture(t)
	executorID := "executor-external"
	engine.store.plan.ExecutorMode = "external"
	engine.store.plan.ExecutorID = &executorID
	engine.store.plan.Operations[0].ExecutorID = executorID
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
	mu       sync.Mutex
	runs     *memoryRepository
	leases   map[string]generated.ExecutorLease
	receipts map[string]generated.ExecutionReceipt
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

func (adapterFixture *fakeAdapter) VerifyReceipt(_ context.Context, _ adapter.Operation, observation adapter.ReceiptObservation) (adapter.ReceiptVerification, error) {
	return adapter.ReceiptVerification{Verified: adapterFixture.verify, Digest: digest("receipt-verification", observation.ResultDigest), Changed: adapterFixture.changed}, nil
}

var _ ExternalLeaseRepository = (*memoryExternalLeases)(nil)
var _ adapter.ReceiptVerifier = (*fakeAdapter)(nil)
