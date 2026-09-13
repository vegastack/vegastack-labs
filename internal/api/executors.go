package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

const MaxExecutorRequestBytes int64 = 64 << 10

const maxExecutorRequestTimeout = 15 * time.Second

type ExecutorLifecycle interface {
	Claim(context.Context, identity.Principal, generated.ExecutorClaimRequest) (generated.ExecutorLease, error)
	Renew(context.Context, identity.Principal, generated.ExecutorRenewRequest) (generated.ExecutorLease, error)
	SubmitReceipt(context.Context, identity.Principal, generated.ExecutionReceiptRequest) (generated.ExecutionReceipt, error)
}

type ExecutorOperationConfig struct {
	Lifecycle      ExecutorLifecycle
	Results        *result.Factory
	MaxBodyBytes   int64
	RequestTimeout time.Duration
}

func RegisterExecutorOperations(app *Application, config ExecutorOperationConfig) error {
	if app == nil || config.Lifecycle == nil || config.Results == nil || config.Results != app.config.Results || app.executors != nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "executor-operation-config")
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = MaxExecutorRequestBytes
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > MaxExecutorRequestBytes {
		return apiFailure(generated.ErrorCodeInputInvalid, "executor-operation-limit")
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 5 * time.Second
	}
	if config.RequestTimeout < time.Millisecond || config.RequestTimeout > maxExecutorRequestTimeout {
		return apiFailure(generated.ErrorCodeInputInvalid, "executor-operation-timeout")
	}
	app.executors = config.Lifecycle
	app.routes = append(app.routes,
		route{id: "api.v1.executor-leases.claim", method: http.MethodPost, pattern: "/api/v1/executor-leases/claim", deferredAuthorization: true, handler: app.claimExecutorLease(config)},
		route{id: "api.v1.executor-leases.renew", method: http.MethodPost, pattern: "/api/v1/executor-leases/{leaseId}/renew", deferredAuthorization: true, handler: app.renewExecutorLease(config)},
		route{id: "api.v1.execution-receipts.create", method: http.MethodPost, pattern: "/api/v1/execution-receipts", deferredAuthorization: true, handler: app.submitExecutionReceipt(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-3]
		app.executors = nil
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) claimExecutorLease(config ExecutorOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.executor-leases.claim"
		principal, ok := requireExecutorPrincipal(request)
		if !ok {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthenticationRequired, "executor-principal"))
			return
		}
		var input generated.ExecutorClaimRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"schema", "schemaVersion", "executorId", "principalId", "adapterId", "recoveryEpoch", "nonceDigest", "extensions"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		if input.PrincipalID != principal.ID || !exactGeneratedContract(generated.SchemaIDExecutorClaimRequest, input) {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthorizationDenied, "executor-binding"))
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), config.RequestTimeout)
		defer cancel()
		lease, err := config.Lifecycle.Claim(ctx, principal, input)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		if !exactGeneratedContract(generated.SchemaIDExecutorLease, lease) || generated.ValidateLeaseTiming(lease) != nil || lease.ExecutorID != input.ExecutorID || lease.AdapterID != input.AdapterID || lease.RecoveryEpoch != input.RecoveryEpoch || lease.NonceDigest != input.NonceDigest {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "executor-lease"))
			return
		}
		app.success(writer, operation, 0, lease.RecoveryEpoch, lease)
	}
}

func (app *Application) renewExecutorLease(config ExecutorOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.executor-leases.renew"
		principal, ok := requireExecutorPrincipal(request)
		if !ok {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthenticationRequired, "executor-principal"))
			return
		}
		leaseID := params["leaseId"]
		if !pathToken.MatchString(leaseID) {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		var input generated.ExecutorRenewRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"schema", "schemaVersion", "leaseId", "bindingDigest", "nonceDigest", "recoveryEpoch", "extensions"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		if input.LeaseID != leaseID || !exactGeneratedContract(generated.SchemaIDExecutorRenewRequest, input) {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "executor-lease"))
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), config.RequestTimeout)
		defer cancel()
		lease, err := config.Lifecycle.Renew(ctx, principal, input)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		if !exactGeneratedContract(generated.SchemaIDExecutorLease, lease) || generated.ValidateLeaseTiming(lease) != nil || lease.LeaseID != input.LeaseID || lease.BindingDigest != input.BindingDigest || lease.RecoveryEpoch != input.RecoveryEpoch {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "executor-lease"))
			return
		}
		app.success(writer, operation, 0, lease.RecoveryEpoch, lease)
	}
}

func (app *Application) submitExecutionReceipt(config ExecutorOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.execution-receipts.create"
		principal, ok := requireExecutorPrincipal(request)
		if !ok {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthenticationRequired, "executor-principal"))
			return
		}
		var input generated.ExecutionReceiptRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"schema", "schemaVersion", "receipt", "expectedBindingDigest", "extensions"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		if !exactGeneratedContract(generated.SchemaIDExecutionReceiptRequest, input) || input.ExpectedBindingDigest != input.Receipt.BindingDigest {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthorizationDenied, "executor-receipt-binding"))
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), config.RequestTimeout)
		defer cancel()
		receipt, err := config.Lifecycle.SubmitReceipt(ctx, principal, input)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		if !exactGeneratedContract(generated.SchemaIDExecutionReceipt, receipt) || receipt.ReceiptID != input.Receipt.ReceiptID || receipt.BindingDigest != input.ExpectedBindingDigest || receipt.RecoveryEpoch != input.Receipt.RecoveryEpoch {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeIntegrityFailure, "execution-receipt"))
			return
		}
		app.success(writer, operation, 0, receipt.RecoveryEpoch, receipt)
	}
}

func requireExecutorPrincipal(request *http.Request) (identity.Principal, bool) {
	principal, ok := identity.PrincipalFromContext(request.Context())
	return principal, ok && identity.ValidPrincipal(principal)
}

func exactGeneratedContract(schema string, value any) bool {
	raw, err := json.Marshal(value)
	return err == nil && generated.ValidateContractJSON(schema, raw, generated.ContractExact) == nil
}
