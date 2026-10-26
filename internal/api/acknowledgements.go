package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type AcknowledgementService interface {
	Request(context.Context, acknowledgement.Scope, string) (acknowledgement.RequestCard, error)
	Status(context.Context, string) (generated.Acknowledgement, error)
	Projection(context.Context, string) (generated.ApprovalStatus, error)
}

// AcknowledgementScopeResolver maps an exact provider-neutral request to a
// configured human, authority and protected one-time nonce. HTTP input alone
// can never assert an approval identity or reconstruct the nonce.
type AcknowledgementScopeResolver interface {
	Resolve(context.Context, generated.AcknowledgementRequest) (acknowledgement.Scope, error)
	ResolvePlan(context.Context, generated.Plan) (acknowledgement.Scope, error)
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
	app.routes = append(app.routes,
		route{id: "api.v1.plans.acknowledgements.create", method: http.MethodPost, pattern: "/api/v1/plans/{planId}/acknowledgements", capability: "plan.acknowledgement.request", kind: "plan", action: authorization.ActionAuthor, handler: app.createAcknowledgement(config)},
		route{id: "api.v1.plans.acknowledgements.get", method: http.MethodGet, pattern: "/api/v1/plans/{planId}/acknowledgements", capability: "plan.acknowledgement.read", kind: "plan", handler: app.getAcknowledgement(config)},
		route{id: "api.v1.plans.approval-request.create", method: http.MethodPost, pattern: "/api/v1/plans/{planId}/approval-request", capability: "plan.acknowledgement.request", kind: "plan", action: authorization.ActionAuthor, handler: app.createBrowserApprovalRequest(config)},
		route{id: "api.v1.plans.approval-status.get", method: http.MethodGet, pattern: "/api/v1/plans/{planId}/approval-status", capability: "plan.acknowledgement.read", kind: "plan", handler: app.getBrowserApprovalStatus(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-4]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) getBrowserApprovalStatus(config AcknowledgementOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.plans.approval-status.get"
		planID := params["planId"]
		if !pathToken.MatchString(planID) || request.URL.RawQuery != "" {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		projection, err := config.Acknowledgements.Projection(request.Context(), planID)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		app.success(writer, operation, projection.StateRevision, projection.RecoveryEpoch, projection)
	}
}

func (app *Application) createBrowserApprovalRequest(config AcknowledgementOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.plans.approval-request.create"
		var input generated.PlanReferenceRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"schema", "schemaVersion", "planId", "planDigest", "recoveryEpoch", "idempotencyKey", "extensions"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		if input.PlanID != params["planId"] {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "approval-request"))
			return
		}
		planResult, err := config.Plans.Get(request.Context(), input.PlanID)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		plan := planResult.Plan
		if plan.PlanDigest != input.PlanDigest || plan.Binding.RecoveryEpoch != input.RecoveryEpoch {
			app.failure(writer, operation, apiFailure(generated.ErrorCodePlanStale, "approval-request"))
			return
		}
		scope, err := config.Scopes.ResolvePlan(request.Context(), plan)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		card, err := config.Acknowledgements.Request(request.Context(), scope, plan.PlanID)
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		card.ReviewText = approvalReviewText(plan, planResult.Readable)
		if err := config.Publisher.Publish(request.Context(), card); err != nil {
			app.operationFailure(writer, operation, requestID, failure.New(generated.ErrorCodeDependencyUnavailable, "acknowledgement-provider", true))
			return
		}
		projection, err := config.Acknowledgements.Projection(request.Context(), plan.PlanID)
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		app.operationSuccess(writer, operation, requestID, true, plan.Binding.StateRevision, plan.Binding.RecoveryEpoch, projection)
	}
}

func (app *Application) getAcknowledgement(config AcknowledgementOperationConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.plans.acknowledgements.get"
		planID := params["planId"]
		if !pathToken.MatchString(planID) || request.URL.RawQuery != "" {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		outcome, err := config.Acknowledgements.Status(request.Context(), planID)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		app.success(writer, operation, outcome.StateRevision, outcome.RecoveryEpoch, outcome)
	}
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
		if scope.Human.ID != input.HumanID || scope.AuthorityID != input.AuthorityID || scope.Nonce == "" {
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
		if !sameAcknowledgementRequestExceptNonce(card.Request, input) {
			app.operationFailure(writer, operation, requestID, failure.New(generated.ErrorCodeIntegrityFailure, "acknowledgement-binding", false))
			return
		}
		card.ReviewText = approvalReviewText(plan, planResult.Readable)
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

func sameAcknowledgementRequestExceptNonce(left, right generated.AcknowledgementRequest) bool {
	right.NonceDigest = left.NonceDigest
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && secureAPIEqual(string(leftRaw), string(rightRaw))
}

func secureAPIEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// Render the server-owned plan, never caller-supplied approval prose.
func approvalReviewText(plan generated.Plan, readable string) string {
	var b strings.Builder
	if e := plan.NetworkEndpoint; e != nil {
		fmt.Fprintf(&b, "Endpoint %s for %s: LAN %s:%d; Mesh %s:%d; flow %s.\n\nChanges controller declarations only, no host/network configuration and no permission grant.\n\n", e.Action, e.Endpoint.HostID, e.Endpoint.LANAddress, e.Endpoint.LANPort, e.Endpoint.MeshAddress, e.Endpoint.MeshPort, e.Endpoint.Flow)
	}
	if batch := plan.AuthorizationGrantBatch; batch != nil {
		if binding := batch.IdentityBinding; binding != nil {
			fmt.Fprintf(&b, "Browser identity %s for %s\nMethod: %s\nIssuer: %s\nSubject: %s\nAudiences: %s\nThis changes only the exact local browser identity mapping and grants no permissions. Revocation ends sessions for this binding only.\n\n", binding.Action, batch.PrincipalID, binding.Method, binding.Issuer, binding.Subject, strings.Join(binding.Audiences, ", "))
		}
		if batch.DeviceAction != "" {
			fmt.Fprintf(&b, "Device %s: %s for human %s (expected device revision %d)\n\nRequests grant no access. Approval permits only existing owner grants. Revocation denies future controller requests attributed to this device; it does not delete OS/provider credentials or revoke unattributed browser sessions.\n\n", batch.DeviceAction, batch.DeviceID, batch.PrincipalID, batch.ExpectedDeviceRevision)
		}
		if batch.LifecycleAction != "" {
			fmt.Fprintf(&b, "User %s: %s\n\nThis changes only local controller access. Onboard creates no grants; suspend preserves grants and ends current browser sessions; resume requires fresh login; offboard permanently revokes local authority and bindings. External accounts, host accounts and credentials require their own workflows.\n\n", batch.LifecycleAction, batch.PrincipalID)
		}
		fmt.Fprintf(&b, "Permission changes for %s\n\nThis changes this account's permissions in the controller. It does not itself inspect, configure or register a host.\n\n", batch.PrincipalID)
		for _, g := range batch.Changes {
			fmt.Fprintf(&b, "• %s: %s — %s on %s %s (role: %s", g.Change, g.Action, g.Capability, g.ResourceKind, g.ResourceID, g.RoleID)
			if g.Branch != "" {
				fmt.Fprintf(&b, "; approval: %s", g.Branch)
			}
			fmt.Fprintf(&b, "; grant: %s)\n", g.GrantID)
		}
	} else {
		b.WriteString("Review the proposed change\n\n")
		b.WriteString(readable)
	}
	expiry := plan.ExpiresAt
	if t, err := time.Parse(time.RFC3339, expiry); err == nil {
		expiry = t.In(time.FixedZone("IST", 19800)).Format("02-01-2006 03:04:05 PM MST")
	}
	fmt.Fprintf(&b, "\nApprove authorizes only this exact plan; execution is a separate step.\nExpires: %s\nPlan: %s\nDigest: %s", expiry, plan.PlanID, plan.PlanDigest)
	return b.String()
}
