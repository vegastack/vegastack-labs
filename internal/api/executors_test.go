package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type executorLifecycleStub struct {
	claim         generated.ExecutorLease
	renew         generated.ExecutorLease
	receipt       generated.ExecutionReceipt
	claimErr      error
	claimCalls    int
	renewCalls    int
	receiptCalls  int
	lastPrincipal identity.Principal
	lastClaim     generated.ExecutorClaimRequest
	lastRenew     generated.ExecutorRenewRequest
	lastReceipt   generated.ExecutionReceiptRequest
}

type executorTimeoutLifecycle struct{ executorLifecycleStub }

func (lifecycle *executorTimeoutLifecycle) Claim(ctx context.Context, _ identity.Principal, _ generated.ExecutorClaimRequest) (generated.ExecutorLease, error) {
	<-ctx.Done()
	return generated.ExecutorLease{}, failure.New(generated.ErrorCodeInterrupted, "executor-request", false)
}

func (stub *executorLifecycleStub) Claim(_ context.Context, principal identity.Principal, request generated.ExecutorClaimRequest) (generated.ExecutorLease, error) {
	stub.claimCalls++
	stub.lastPrincipal, stub.lastClaim = principal, request
	return stub.claim, stub.claimErr
}

func (stub *executorLifecycleStub) Renew(_ context.Context, principal identity.Principal, request generated.ExecutorRenewRequest) (generated.ExecutorLease, error) {
	stub.renewCalls++
	stub.lastPrincipal, stub.lastRenew = principal, request
	return stub.renew, nil
}

func (stub *executorLifecycleStub) SubmitReceipt(_ context.Context, principal identity.Principal, request generated.ExecutionReceiptRequest) (generated.ExecutionReceipt, error) {
	stub.receiptCalls++
	stub.lastPrincipal, stub.lastReceipt = principal, request
	return stub.receipt, nil
}

func TestExecutorAPIRejectsWrongBindingBeforeReturningWork(t *testing.T) {
	service := &executorLifecycleStub{claimErr: failure.New(generated.ErrorCodeAuthorizationDenied, "executor-binding", false)}
	app := newExecutorTestApplication(t, service)
	request := executorRequest(t, http.MethodPost, "/api/v1/executor-leases/claim", validExecutorClaim())
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || service.claimCalls != 1 {
		t.Fatalf("response/calls = %d/%d body=%s", response.Code, service.claimCalls, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "leaseId") || strings.Contains(response.Body.String(), "private-canary") {
		t.Fatalf("denial returned work or private input: %s", response.Body.String())
	}
}

func TestExecutorAPIAuthenticatesExecutorBeforeReadingBody(t *testing.T) {
	service := &executorLifecycleStub{}
	app := newExecutorTestApplication(t, service)
	for _, principal := range []*identity.Principal{nil, {ID: "invalid principal", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalAgent}} {
		body := &countingBody{data: bytes.NewReader([]byte(`{"private":"canary"}`))}
		request := httptest.NewRequest(http.MethodPost, "/api/v1/executor-leases/claim", nil)
		request.Body, request.ContentLength = body, int64(body.data.Len())
		request.Header.Set("Content-Type", "application/json")
		if principal != nil {
			request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), *principal))
		}
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || body.reads != 0 || service.claimCalls != 0 || strings.Contains(response.Body.String(), "canary") {
			t.Fatalf("response/reads/calls = %d/%d/%d body=%s", response.Code, body.reads, service.claimCalls, response.Body.String())
		}
	}
	wrongPrincipal := validExecutorClaim()
	wrongPrincipal.PrincipalID = "principal-other"
	response := httptest.NewRecorder()
	app.ServeHTTP(response, executorRequest(t, http.MethodPost, "/api/v1/executor-leases/claim", wrongPrincipal))
	if response.Code != http.StatusForbidden || service.claimCalls != 0 || strings.Contains(response.Body.String(), "leaseId") {
		t.Fatalf("wrong-principal response/calls = %d/%d body=%s", response.Code, service.claimCalls, response.Body.String())
	}
}

func TestExecutorAPIValidatesExactClaimsRenewalsAndReceipts(t *testing.T) {
	lease := validExecutorLease()
	receipt := validExecutionReceipt(lease)
	service := &executorLifecycleStub{claim: lease, renew: lease, receipt: receipt}
	app := newExecutorTestApplication(t, service)

	claimResponse := httptest.NewRecorder()
	app.ServeHTTP(claimResponse, executorRequest(t, http.MethodPost, "/api/v1/executor-leases/claim", validExecutorClaim()))
	if claimResponse.Code != http.StatusOK || service.claimCalls != 1 || !strings.Contains(claimResponse.Body.String(), lease.LeaseID) {
		t.Fatalf("claim response/calls = %d/%d body=%s", claimResponse.Code, service.claimCalls, claimResponse.Body.String())
	}

	renewal := generated.ExecutorRenewRequest{Schema: generated.SchemaIDExecutorRenewRequest, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, BindingDigest: lease.BindingDigest, NonceDigest: testAPIDigest("e"), RecoveryEpoch: lease.RecoveryEpoch, Extensions: []generated.ContractExtension{}}
	renewResponse := httptest.NewRecorder()
	app.ServeHTTP(renewResponse, executorRequest(t, http.MethodPost, "/api/v1/executor-leases/"+lease.LeaseID+"/renew", renewal))
	if renewResponse.Code != http.StatusOK || service.renewCalls != 1 || service.lastRenew.LeaseID != lease.LeaseID {
		t.Fatalf("renew response/calls = %d/%d body=%s", renewResponse.Code, service.renewCalls, renewResponse.Body.String())
	}

	receiptRequest := generated.ExecutionReceiptRequest{Schema: generated.SchemaIDExecutionReceiptRequest, SchemaVersion: "1.0.0", Receipt: receipt, ExpectedBindingDigest: lease.BindingDigest, Extensions: []generated.ContractExtension{}}
	receiptResponse := httptest.NewRecorder()
	app.ServeHTTP(receiptResponse, executorRequest(t, http.MethodPost, "/api/v1/execution-receipts", receiptRequest))
	if receiptResponse.Code != http.StatusOK || service.receiptCalls != 1 || service.lastReceipt.Receipt.ReceiptID != receipt.ReceiptID {
		t.Fatalf("receipt response/calls = %d/%d body=%s", receiptResponse.Code, service.receiptCalls, receiptResponse.Body.String())
	}

	wrongPath := httptest.NewRecorder()
	app.ServeHTTP(wrongPath, executorRequest(t, http.MethodPost, "/api/v1/executor-leases/lease-other/renew", renewal))
	if wrongPath.Code != http.StatusBadRequest || service.renewCalls != 1 {
		t.Fatalf("wrong-path response/calls = %d/%d body=%s", wrongPath.Code, service.renewCalls, wrongPath.Body.String())
	}
}

func TestExecutorAPIRejectsUnknownAndOversizedBodiesWithoutServiceCalls(t *testing.T) {
	service := &executorLifecycleStub{}
	app := newExecutorTestApplication(t, service)
	for _, raw := range []string{
		`{"schema":"vegastack-labs.dev/executor-claim-request","schemaVersion":"1.0.0","executorId":"executor-test","principalId":"executor-principal","adapterId":"adapter-test","recoveryEpoch":4,"nonceDigest":"` + testAPIDigest("a") + `","extensions":[],"token":"private-canary"}`,
		`{"schema":"vegastack-labs.dev/executor-claim-request","schemaVersion":"1.0.0","executorId":"executor-test","principalId":"executor-principal","adapterId":"adapter-test","recoveryEpoch":4,"nonceDigest":"` + testAPIDigest("a") + `","extensions":[]}` + strings.Repeat(" ", int(MaxExecutorRequestBytes)),
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/executor-leases/claim", strings.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), executorPrincipal()))
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || service.claimCalls != 0 || strings.Contains(response.Body.String(), "private-canary") {
			t.Fatalf("response/calls = %d/%d body=%s", response.Code, service.claimCalls, response.Body.String())
		}
	}
}

func TestExecutorAPIBoundsLifecycleCallsWithARequestTimeout(t *testing.T) {
	service := &executorTimeoutLifecycle{}
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: authorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
		return authorization.ReadScope{}, nil
	}), Reads: testReads{}, Results: result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-executor-timeout", nil }), Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterExecutorOperations(app, ExecutorOperationConfig{Lifecycle: service, Results: app.config.Results, RequestTimeout: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	app.ServeHTTP(response, executorRequest(t, http.MethodPost, "/api/v1/executor-leases/claim", validExecutorClaim()))
	if response.Code != http.StatusRequestTimeout || !strings.Contains(response.Body.String(), generated.ErrorCodeInterrupted) {
		t.Fatalf("timeout response = %d %s", response.Code, response.Body.String())
	}
}

func newExecutorTestApplication(t *testing.T, service ExecutorLifecycle) *Application {
	t.Helper()
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: authorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
		return authorization.ReadScope{}, nil
	}), Reads: testReads{}, Results: result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-executor-test", nil }), Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterExecutorOperations(app, ExecutorOperationConfig{Lifecycle: service, Results: app.config.Results}); err != nil {
		t.Fatal(err)
	}
	return app
}

func executorRequest(t *testing.T, method, path string, value any) *http.Request {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request.WithContext(identity.WithVerifiedPrincipal(request.Context(), executorPrincipal()))
}

func executorPrincipal() identity.Principal {
	return identity.Principal{ID: "executor-principal", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalAgent}
}

func validExecutorClaim() generated.ExecutorClaimRequest {
	return generated.ExecutorClaimRequest{Schema: generated.SchemaIDExecutorClaimRequest, SchemaVersion: "1.0.0", ExecutorID: "executor-test", PrincipalID: "executor-principal", AdapterID: "adapter-test", RecoveryEpoch: 4, NonceDigest: testAPIDigest("a"), Extensions: []generated.ContractExtension{{Name: "x-ref", ValueDigest: testAPIDigest("b")}}}
}

func validExecutorLease() generated.ExecutorLease {
	return generated.ExecutorLease{Schema: generated.SchemaIDExecutorLease, SchemaVersion: "1.0.0", LeaseID: "lease-test", PlanID: "plan-test", PlanDigest: testAPIDigest("c"), RunID: "run-test", StepID: "step-test", OperationID: "operation-test", ExecutorID: "executor-test", AdapterID: "adapter-test", TargetID: "target-test", ArtifactDigest: testAPIDigest("d"), BindingDigest: testAPIDigest("f"), NonceDigest: testAPIDigest("a"), RecoveryEpoch: 4, ClaimedAt: "2026-09-13T00:00:00Z", RenewAfter: "2026-09-13T00:00:20Z", LeaseExpiresAt: "2026-09-13T00:01:00Z", MaximumExpiresAt: "2026-09-13T00:01:00Z", Status: "active", Extensions: []generated.ContractExtension{}}
}

func validExecutionReceipt(lease generated.ExecutorLease) generated.ExecutionReceipt {
	return generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, OperationID: lease.OperationID, ExecutorID: lease.ExecutorID, AdapterID: lease.AdapterID, TargetID: lease.TargetID, ArtifactDigest: lease.ArtifactDigest, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch, ReceiptID: "receipt-test", Status: "succeeded", ResultDigest: testAPIDigest("9"), RecordedAt: "2026-09-13T00:00:30Z", Extensions: []generated.ContractExtension{}}
}
