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

type CIJobOperations struct {
	Jobs         *store.CIJobRepository
	Declarations *change.Service
	Credentials  *store.CredentialRepository
	Results      *result.Factory
	Prepare      func(context.Context, generated.CiJobDraftRequest) (generated.CiJobRequest, error)
}

func RegisterCIJobOperations(app *Application, c CIJobOperations) error {
	if app == nil || c.Jobs == nil || c.Declarations == nil || c.Credentials == nil || c.Results == nil || c.Results != app.config.Results || c.Prepare == nil {
		return apiFailure(generated.ErrorCodeInputInvalid, "ci-job-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.ci.jobs.drafts.create", method: http.MethodPost, pattern: "/api/v1/ci/jobs/drafts", deferredAuthorization: true, handler: app.ciJobDraft(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-1]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) ciJobDraft(c CIJobOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.ci.jobs.drafts.create"
		var input generated.CiJobDraftRequest
		if e := decodeOperationRequest(r, 16384, []string{"schema", "schemaVersion", "enrollmentId", "executionBindingId", "runId", "attempt", "expectedStateRevision", "recoveryEpoch", "idempotencyKey", "reasonDigest"}, &input); e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDCiJobDraftRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "ci-job-request"))
			return
		}
		if _, e := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "ci.job.prepare", ResourceKind: "ci-enrollment", ResourceID: input.EnrollmentID}); e != nil {
			app.failure(w, op, e)
			return
		}
		in, e := c.Prepare(r.Context(), input)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		if in.Definition.EnrollmentID != input.EnrollmentID || in.ExecutionBindingID != input.ExecutionBindingID || in.RunID != input.RunID || in.Attempt != input.Attempt || in.ExpectedStateRevision != input.ExpectedStateRevision || in.RecoveryEpoch != input.RecoveryEpoch || in.IdempotencyKey != input.IdempotencyKey || in.ReasonDigest != input.ReasonDigest {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "ci-job-request"))
			return
		}
		draft, e := c.Jobs.Stage(r.Context(), in)
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
		bindings, e := c.Jobs.StepBindings(in)
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
		_, e = c.Credentials.StageStepBindings(r.Context(), store.CredentialBindingStageRequest{DeclarationID: revised.Document.DeclarationID, DeclarationRevision: 1, Bindings: bindings, Expected: store.RevisionToken{StateRevision: revised.Document.StateRevision, RecoveryEpoch: in.RecoveryEpoch}, Attribution: a, KeyDigest: hostaction.Digest([]string{revised.Document.DeclarationID, "credentials"}), RequestDigest: manifest})
		if e != nil {
			app.operationFailure(w, op, id, e)
			return
		}
		app.operationSuccess(w, op, id, revised.Changed, revised.Document.StateRevision+1, revised.Document.RecoveryEpoch, revised.Document)
	}
}
