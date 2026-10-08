package api

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
)

type HostDiscoveryOperations struct {
	Service      *hostdiscovery.Service
	Targets      *store.HostDiscoveryRepository
	Declarations *change.Service
	Results      *result.Factory
}

func RegisterHostDiscoveryOperations(app *Application, c HostDiscoveryOperations) error {
	if app == nil || c.Service == nil || c.Targets == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "host-discovery-config")
	}
	app.routes = append(app.routes,
		route{id: "api.v1.host-discovery-targets.draft", method: http.MethodPost, pattern: "/api/v1/host-discovery-targets/draft", deferredAuthorization: true, handler: app.discoveryDraft(c)},
		route{id: "api.v1.host-observations.create", method: http.MethodPost, pattern: "/api/v1/host-observations", deferredAuthorization: true, handler: app.discoveryCollect(c)},
		route{id: "api.v1.host-observations.get", method: http.MethodGet, pattern: "/api/v1/host-observations/{observationID}", capability: "host.discovery.read", kind: "host-discovery-target", handler: app.discoveryGet(c)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-3]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func discoveryInput(r *http.Request, schema string, fields []string, out any) error {
	if err := decodeOperationRequest(r, 16384, fields, out); err != nil {
		return err
	}
	raw, _ := json.Marshal(out)
	if generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "host-discovery-request")
	}
	return nil
}
func (app *Application) discoveryCollect(c HostDiscoveryOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.host-observations.create"
		var input generated.HostDiscoveryRequest
		if err := discoveryInput(r, generated.SchemaIDHostDiscoveryRequest, []string{"schema", "schemaVersion", "targetId", "targetRevision", "expectedStateRevision", "recoveryEpoch", "idempotencyKey"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "host.discovery.collect", ResourceKind: "host-discovery-target", ResourceID: input.TargetID}); err != nil {
			app.failure(w, op, err)
			return
		}
		value, err := c.Service.Discover(r.Context(), input)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, value.Observation.StateRevision, value.Observation.RecoveryEpoch, value)
	}
}
func (app *Application) discoveryGet(c HostDiscoveryOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.host-observations.get"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "host-observation-query"))
			return
		}
		value, err := c.Service.Get(r.Context(), params["observationID"])
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, value.StateRevision, value.RecoveryEpoch, value)
	}
}
func (app *Application) discoveryDraft(c HostDiscoveryOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.host-discovery-targets.draft"
		var input generated.HostDiscoveryTargetDraftRequest
		if err := discoveryInput(r, generated.SchemaIDHostDiscoveryTargetDraftRequest, []string{"schema", "schemaVersion", "target", "action", "consoleConfirmation", "expectedTargetRevision", "expectedStateRevision", "idempotencyKey"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "host.discovery.target.prepare", ResourceKind: "host-discovery-target", ResourceID: input.Target.TargetID}); err != nil {
			app.failure(w, op, err)
			return
		}
		declarationID := "discovery-draft-" + hostdiscovery.Digest(input)[7:39]
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
		draft, err := c.Targets.StageDraft(r.Context(), input, attribution)
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
		declaration := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: declarationID, DeclarationType: "host.discovery-target", ExpectedRevision: 1, ExpectedStateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.Target.RecoveryEpoch, ReasonDigest: draft.Digest, Extensions: []generated.ContractExtension{}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "discovery-target-change", OperationType: "host.discovery-target." + input.Action, AdapterID: "core.host-discovery-target", TargetID: draft.ID, InputDigest: draft.Digest, ArtifactDigest: draft.Digest, Idempotent: true}}}
		revised, err := c.Declarations.Revise(r.Context(), author, declaration)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		value := generated.HostDiscoveryTargetDraftSubmission{Schema: generated.SchemaIDHostDiscoveryTargetDraftSubmission, SchemaVersion: "1.0.0", DraftID: draft.ID, DeclarationID: declarationID, ContentDigest: draft.Digest, StateRevision: revised.Document.StateRevision, RecoveryEpoch: input.Target.RecoveryEpoch}
		app.success(w, op, value.StateRevision, value.RecoveryEpoch, value)
	}
}
