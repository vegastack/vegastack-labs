package api

import (
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
)

type HostAdoptionOperations struct {
	Hosts        *store.HostAdoptionRepository
	Declarations *change.Service
	Results      *result.Factory
}

func RegisterHostAdoptionOperations(app *Application, c HostAdoptionOperations) error {
	if app == nil || c.Hosts == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "host-adoption-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.host-adoptions.draft", method: http.MethodPost, pattern: "/api/v1/host-adoptions/draft", deferredAuthorization: true, handler: app.adoptionDraft(c)}, route{id: "api.v1.hosts.get", method: http.MethodGet, pattern: "/api/v1/hosts/{hostID}", deferredAuthorization: true, handler: app.adoptionGet(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-2]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) adoptionGet(c HostAdoptionOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.hosts.get"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "host-query"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: params["hostID"]}); err != nil {
			app.failure(w, op, err)
			return
		}
		h, err := c.Hosts.Get(r.Context(), params["hostID"])
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, h.StateRevision, h.RecoveryEpoch, h)
	}
}
func (app *Application) adoptionDraft(c HostAdoptionOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.host-adoptions.draft"
		var input generated.HostAdoptionRequest
		if err := discoveryInput(r, generated.SchemaIDHostAdoptionRequest, []string{"schema", "schemaVersion", "hostId", "observationId", "observationDigest", "confirmation", "expectedStateRevision", "recoveryEpoch", "idempotencyKey"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		// StageDraft resolves the private observation target and checks the exact current preparation grant.
		declarationID := "host-adoption-" + hostdiscovery.Digest(input)[7:39]
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "declaration.author", ResourceKind: "declaration", ResourceID: declarationID}); err != nil {
			app.failure(w, op, err)
			return
		}
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		attribution, err := hostdiscovery.Attribution(r.Context(), declarationID)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		draft, err := c.Hosts.StageDraft(r.Context(), input, attribution)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		requestID, err := c.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		author := change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: requestID}
		declaration := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: declarationID, DeclarationType: "host.adoption", ExpectedRevision: 1, ExpectedStateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch, ReasonDigest: draft.Digest, Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "host-adopt", OperationType: "host.adopt", AdapterID: "core.host-adoption", TargetID: draft.ID, InputDigest: draft.Digest, ArtifactDigest: draft.Digest, Idempotent: true}}}
		revised, err := c.Declarations.Revise(r.Context(), author, declaration)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		value := generated.HostAdoptionSubmission{Schema: generated.SchemaIDHostAdoptionSubmission, SchemaVersion: "1.0.0", DraftID: draft.ID, DeclarationID: declarationID, ContentDigest: draft.Digest, StateRevision: revised.Document.StateRevision, RecoveryEpoch: input.RecoveryEpoch}
		app.success(w, op, value.StateRevision, value.RecoveryEpoch, value)
	}
}
