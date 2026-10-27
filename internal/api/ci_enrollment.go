package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type CIEnrollmentOperations struct {
	Enrollments  *store.CIEnrollmentRepository
	Declarations *change.Service
	Results      *result.Factory
	Prepare      func(context.Context, generated.CiEnrollmentDraftRequest) (generated.CiEnrollmentRequest, error)
}

func RegisterCIEnrollmentOperations(app *Application, c CIEnrollmentOperations) error {
	if app == nil || c.Enrollments == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results || c.Prepare == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "ci-enrollment-config")
	}
	before := len(app.routes)
	app.routes = append(app.routes,
		route{id: "api.v1.ci.enrollments.drafts.create", method: http.MethodPost, pattern: "/api/v1/ci/enrollments/drafts", deferredAuthorization: true, handler: app.ciEnrollmentDraft(c)},
		route{id: "api.v1.ci.enrollments.list", method: http.MethodGet, pattern: "/api/v1/ci/enrollments", deferredAuthorization: true, handler: app.ciEnrollmentList(c)},
		route{id: "api.v1.ci.enrollments.get", method: http.MethodGet, pattern: "/api/v1/ci/enrollments/{enrollmentID}", deferredAuthorization: true, handler: app.ciEnrollmentRead(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:before]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) ciEnrollmentDraft(c CIEnrollmentOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.ci.enrollments.drafts.create"
		var input generated.CiEnrollmentDraftRequest
		if err := decodeOperationRequest(r, 16384, []string{"schema", "schemaVersion", "enrollmentId", "bindingId", "expectedStateRevision", "recoveryEpoch", "idempotencyKey", "reasonDigest"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDCiEnrollmentDraftRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "ci-enrollment-request"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "ci.enrollment.prepare", ResourceKind: "ci-enrollment", ResourceID: input.EnrollmentID}); err != nil {
			app.failure(w, op, err)
			return
		}
		// Preparation checks current repository scope before borrowing protected
		// provider credentials; Stage checks it again after the observation.
		prepared, err := c.Prepare(r.Context(), input)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if prepared.Definition.EnrollmentID != input.EnrollmentID || prepared.Definition.BindingID != input.BindingID || prepared.ExpectedStateRevision != input.ExpectedStateRevision || prepared.RecoveryEpoch != input.RecoveryEpoch || prepared.IdempotencyKey != input.IdempotencyKey || prepared.ReasonDigest != input.ReasonDigest {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "ci-enrollment-request"))
			return
		}
		draft, err := c.Enrollments.Stage(r.Context(), prepared)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		actor, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		requestID, err := c.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		author := change.AuthorScope{PrincipalID: actor.ID, PrincipalMethod: actor.Method, AgentSessionID: requestID}
		if identity.EffectivePrincipalKind(actor) == identity.PrincipalAgent {
			author.AgentName = actor.ID
		}
		revised, err := c.Declarations.Revise(r.Context(), author, draft)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		app.operationSuccess(w, op, requestID, revised.Changed, revised.Document.StateRevision, revised.Document.RecoveryEpoch, revised.Document)
	}
}

func ciEnrollmentListQuery(raw string) (string, int, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", 0, apiFailure(generated.ErrorCodeInputInvalid, "ci-enrollment-query")
	}
	after, limit := "", 50
	for key, v := range values {
		if len(v) != 1 {
			return "", 0, apiFailure(generated.ErrorCodeInputInvalid, "ci-enrollment-query")
		}
		switch key {
		case "after":
			if !principal.ValidID(v[0]) {
				return "", 0, apiFailure(generated.ErrorCodeInputInvalid, "ci-enrollment-query")
			}
			after = v[0]
		case "limit":
			n, e := strconv.Atoi(v[0])
			if e != nil || n < 1 || n > 100 || strconv.Itoa(n) != v[0] {
				return "", 0, apiFailure(generated.ErrorCodeInputInvalid, "ci-enrollment-query")
			}
			limit = n
		default:
			return "", 0, apiFailure(generated.ErrorCodeInputInvalid, "ci-enrollment-query")
		}
	}
	return after, limit, nil
}

func (app *Application) ciEnrollmentList(c CIEnrollmentOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.ci.enrollments.list"
		after, limit, err := ciEnrollmentListQuery(r.URL.RawQuery)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		// List evaluates exact service grants in the current store snapshot rather
		// than requiring a wildcard grant or querying private records then filtering.
		value, err := c.Enrollments.List(r.Context(), after, limit)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, value.StateRevision, value.RecoveryEpoch, value)
	}
}

func (app *Application) ciEnrollmentRead(c CIEnrollmentOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.ci.enrollments.get"
		id := params["enrollmentID"]
		if r.URL.RawQuery != "" || !principal.ValidID(id) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "ci-enrollment-query"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "ci.enrollment.read", ResourceKind: "ci-enrollment", ResourceID: id}); err != nil {
			app.failure(w, op, err)
			return
		}
		value, err := c.Enrollments.Get(r.Context(), id)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, value.StateRevision, value.RecoveryEpoch, value)
	}
}
