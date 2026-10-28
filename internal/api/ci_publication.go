package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type CIPublicationOperations struct {
	Jobs         *store.CIPublicationRepository
	Declarations *change.Service
	Credentials  *store.CredentialRepository
	Results      *result.Factory
	Prepare      func(context.Context, generated.CiPublicationDraftRequest) (generated.DeclarationRevisionRequest, []credentialref.StepBinding, error)
}

func RegisterCIPublicationOperations(app *Application, c CIPublicationOperations) error {
	if app == nil || c.Jobs == nil || c.Declarations == nil || c.Credentials == nil || c.Results == nil || c.Results != app.config.Results || c.Prepare == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "ci-publication-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.ci.publications.drafts.create", method: http.MethodPost, pattern: "/api/v1/ci/publications/drafts", deferredAuthorization: true, handler: app.ciPublicationDraft(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-1]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) ciPublicationDraft(c CIPublicationOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.ci.publications.drafts.create"
		var input generated.CiPublicationDraftRequest
		if e := decodeOperationRequest(r, 16384, []string{"schema", "schemaVersion", "bindingId", "expectedStateRevision", "recoveryEpoch", "idempotencyKey", "reasonDigest"}, &input); e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDCiPublicationDraftRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "ci-publication-request"))
			return
		}
		if _, e := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "ci.publication.prepare", ResourceKind: "ci-publication", ResourceID: input.BindingID}); e != nil {
			app.failure(w, op, e)
			return
		}
		draft, bindings, e := c.Prepare(r.Context(), input)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		actor, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		id, e := c.Results.RequestID()
		if e != nil {
			app.failure(w, op, e)
			return
		}
		author := change.AuthorScope{PrincipalID: actor.ID, PrincipalMethod: actor.Method, AgentSessionID: id}
		if identity.EffectivePrincipalKind(actor) == identity.PrincipalAgent {
			author.AgentName = actor.ID
		}
		revised, e := c.Declarations.Revise(r.Context(), author, draft)
		if e != nil {
			app.operationFailure(w, op, id, e)
			return
		}
		a, e := hostdiscovery.Attribution(r.Context(), id)
		if e != nil {
			app.operationFailure(w, op, id, e)
			return
		}
		manifest := credentialref.ManifestDigest(bindings)
		_, e = c.Credentials.StageStepBindings(r.Context(), store.CredentialBindingStageRequest{DeclarationID: revised.Document.DeclarationID, DeclarationRevision: 1, Bindings: bindings, Expected: store.RevisionToken{StateRevision: revised.Document.StateRevision, RecoveryEpoch: input.RecoveryEpoch}, Attribution: a, KeyDigest: hostaction.Digest([]string{revised.Document.DeclarationID, "credentials"}), RequestDigest: manifest})
		if e != nil {
			app.operationFailure(w, op, id, e)
			return
		}
		app.operationSuccess(w, op, id, revised.Changed, revised.Document.StateRevision+1, revised.Document.RecoveryEpoch, revised.Document)
	}
}
