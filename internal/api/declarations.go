package api

import (
	"context"
	"net/http"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type DeclarationService interface {
	Revise(context.Context, change.AuthorScope, generated.DeclarationRevisionRequest) (change.Result, error)
	Get(context.Context, string, int64) (generated.DeclarationRevision, error)
}

func (app *Application) reviseDeclaration(config DeclarationPlanConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.declarations.revise"
		var input generated.DeclarationRevisionRequest
		if err := decodeOperationRequest(request, config.MaxBodyBytes, []string{"schema", "schemaVersion", "declarationId", "declarationType", "expectedRevision", "expectedStateRevision", "recoveryEpoch", "operations", "reasonDigest", "extensions"}, &input); err != nil {
			app.failure(writer, operation, err)
			return
		}
		if input.DeclarationID != params["declarationId"] {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "authorization-target"))
			return
		}
		principal, ok := identity.PrincipalFromContext(request.Context())
		if !ok {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		if _, err := app.authorizeAction(request, authorization.ActionAuthor, authorization.Target{Capability: "declaration.author", ResourceKind: "declaration", ResourceID: input.DeclarationID}); err != nil {
			app.failure(writer, operation, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		value, err := config.Declarations.Revise(request.Context(), change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: requestID}, input)
		if err != nil {
			app.operationFailure(writer, operation, requestID, err)
			return
		}
		app.operationSuccess(writer, operation, requestID, value.Changed, value.Document.StateRevision, value.Document.RecoveryEpoch, presentDeclaration(value.Document))
	}
}

func (app *Application) getDeclaration(config DeclarationPlanConfig) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(writer http.ResponseWriter, request *http.Request, _ authorization.ReadScope, params map[string]string) {
		const operation = "api.v1.declarations.get"
		revision, err := strconv.ParseInt(params["revision"], 10, 64)
		if err != nil || revision < 1 || !pathToken.MatchString(params["declarationId"]) || request.URL.RawQuery != "" {
			app.failure(writer, operation, apiFailure(generated.ErrorCodeInputInvalid, "path"))
			return
		}
		value, err := config.Declarations.Get(request.Context(), params["declarationId"], revision)
		if err != nil {
			app.failure(writer, operation, err)
			return
		}
		app.success(writer, operation, value.StateRevision, value.RecoveryEpoch, presentDeclaration(value))
	}
}

func presentDeclaration(value generated.DeclarationRevision) generated.BrowserDeclarationRevision {
	return generated.BrowserDeclarationRevision{Schema: generated.SchemaIDBrowserDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: value.DeclarationID, DeclarationType: value.DeclarationType, Revision: value.Revision, StateRevision: value.StateRevision, RecoveryEpoch: value.RecoveryEpoch, ContentDigest: value.ContentDigest, Status: value.Status, Operations: append([]generated.DeclarationOperation(nil), value.Operations...), CreatedAt: value.CreatedAt, Extensions: append([]generated.ContractExtension(nil), value.Extensions...)}
}
