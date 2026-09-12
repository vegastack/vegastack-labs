package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type AcknowledgementService interface {
	Request(context.Context, acknowledgement.Scope, string) (acknowledgement.RequestCard, error)
	Status(context.Context, string) (generated.Acknowledgement, error)
}

// AcknowledgementScopeResolver maps an exact provider-neutral request to a
// configured human, authority and protected one-time nonce. HTTP input alone
// can never assert an approval identity or reconstruct the nonce.
type AcknowledgementScopeResolver interface {
	Resolve(context.Context, generated.AcknowledgementRequest) (acknowledgement.Scope, error)
}

type AcknowledgementPublisher interface {
	Publish(context.Context, acknowledgement.RequestCard) error
}

type AcknowledgementOperationConfig struct {
	Plans            PlanService
	Acknowledgements AcknowledgementService
	Scopes           AcknowledgementScopeResolver
	Publisher        AcknowledgementPublisher
	Results          *result.Factory
	MaxBodyBytes     int64
}

func RegisterAcknowledgementOperations(app *Application, config AcknowledgementOperationConfig) error {
	if app == nil || config.Plans == nil || config.Acknowledgements == nil || config.Scopes == nil || config.Publisher == nil || config.Results == nil || config.Results != app.config.Results || app.effective.Authorizer == nil || app.effective.Recorder == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "acknowledgement-config")
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = MaxOperationRequestBytes
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > MaxOperationRequestBytes {
		return apiFailure(generated.ErrorCodeInputInvalid, "acknowledgement-limit")
	}
	app.routes = append(app.routes, route{id: "api.v1.plans.acknowledgements.create", method: http.MethodPost, pattern: "/api/v1/plans/{planId}/acknowledgements", capability: "plan.acknowledgement.request", kind: "plan", action: authorization.ActionAuthor, handler: app.createAcknowledgement(config)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-1]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) createAcknowledgement(config AcknowledgementOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.plans.acknowledgements.create"
		var input generated.AcknowledgementRequest
		fields := []string{"schema", "schemaVersion", "planId", "planDigest", "targetDigest", "reasonDigest", "humanId", "authorityId", "nonceDigest", "stateRevision", "recoveryEpoch", "expiresAt", "extensions"}
		if err := decodeOperationRequest(request, config.MaxBodyBytes, fields, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		if input.PlanID != params["planId"] || !exactAcknowledgementContract(input) {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "acknowledgement-request"))
			return
		}
		planResult, err := config.Plans.Get(request.Context(), input.PlanID)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		plan := planResult.Plan
		if input.PlanDigest != plan.PlanDigest || input.TargetDigest != plan.Binding.TargetDigest || input.ReasonDigest != plan.Binding.ReasonDigest || input.StateRevision != plan.Binding.StateRevision || input.RecoveryEpoch != plan.Binding.RecoveryEpoch || input.ExpiresAt != plan.ExpiresAt {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthorizationDenied, "acknowledgement-binding"))
			return
		}
		scope, err := config.Scopes.Resolve(request.Context(), input)
		if err != nil {
			stable, stableOK := failure.As(err)
			if stableOK && (stable.Code == generated.ErrorCodePrerequisiteBlocked || stable.Code == generated.ErrorCodeDependencyUnavailable) {
				app.failure(writer, operation, err)
			} else {
				app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthorizationDenied, "acknowledgement-scope"))
			}
			return
		}
		if scope.Human.ID != input.HumanID || scope.AuthorityID != input.AuthorityID || !secureAPIEqual(acknowledgementNonceDigest(scope.Nonce), input.NonceDigest) {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthorizationDenied, "acknowledgement-scope"))
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		card, err := config.Acknowledgements.Request(request.Context(), scope, input.PlanID)
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		if !sameAcknowledgementRequest(card.Request, input) {
			app.operationFailure(writer, operation, requestID, failure.New(generated.ErrorCodeIntegrityFailure, "acknowledgement-binding", false))
			return
		}
		if err := config.Publisher.Publish(request.Context(), card); err != nil {
			app.operationFailure(writer, operation, requestID, failure.New(generated.ErrorCodeDependencyUnavailable, "acknowledgement-provider", true))
			return
		}
		outcome, err := config.Acknowledgements.Status(request.Context(), input.PlanID)
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		app.operationSuccess(writer, operation, requestID, true, outcome.StateRevision, outcome.RecoveryEpoch, outcome)
	}
}

func exactAcknowledgementContract(input generated.AcknowledgementRequest) bool {
	raw, err := json.Marshal(input)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDAcknowledgementRequest, raw, generated.ContractExact) == nil
}

func sameAcknowledgementRequest(left, right generated.AcknowledgementRequest) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && secureAPIEqual(string(leftRaw), string(rightRaw))
}

func acknowledgementNonceDigest(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func secureAPIEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
