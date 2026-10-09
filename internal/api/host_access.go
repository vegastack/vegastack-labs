package api

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
)

type AccessRenderer interface {
	RenderRole(context.Context, generated.DebianAccessInput) (generated.RenderedAccess, error)
}
type HostAccessOperations struct {
	Hosts        *store.HostActionRepository
	Declarations *change.Service
	Credentials  *store.CredentialRepository
	Renderer     AccessRenderer
	Results      *result.Factory
}

func RegisterHostAccessOperations(app *Application, c HostAccessOperations) error {
	if app == nil || c.Hosts == nil || c.Declarations == nil || c.Credentials == nil || c.Renderer == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "host-access-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.host-access.draft", method: http.MethodPost, pattern: "/api/v1/host-access/draft", deferredAuthorization: true, handler: app.hostAccessDraft(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-1]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) hostAccessDraft(c HostAccessOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.host-access.draft"
		var input generated.HostAccessDraftRequest
		if e := decodeOperationRequest(r, 1048576, []string{"schema", "schemaVersion", "subject", "input", "probes"}, &input); e != nil {
			app.failure(w, operation, e)
			return
		}
		fail := func(e error) { app.failure(w, operation, e) }
		originalRequestDigest := hostaction.Digest(input)
		encodedInput, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDHostAccessDraftRequest, encodedInput, generated.ContractExact) != nil {
			fail(apiFailure(generated.ErrorCodeInputInvalid, "host-access-input"))
			return
		}
		requests := []generated.HostActionRequest{input.Subject}
		for _, p := range input.Probes {
			request := p.Request
			switch p.Kind {
			case "collect":
				request.ActionID = "debian.access.collect"
			case "local-probe":
				request.ActionID = "debian.access.probe.local"
			case "source-probe":
				request.ActionID = "debian.access.probe-source"
			default:
				fail(apiFailure(generated.ErrorCodeInputInvalid, "probe-kind"))
				return
			}
			requests = append(requests, request)
		}
		for _, request := range requests {
			if _, e := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "host.action.prepare", ResourceKind: "host", ResourceID: request.HostID}); e != nil {
				fail(e)
				return
			}
		}
		if e := c.Hosts.ValidateAccessPreparation(r.Context(), requests); e != nil {
			fail(e)
			return
		}
		if input.Subject.HostID != input.Input.HostID || input.Subject.ConsoleConfirmation.HostIdentityDigest != input.Input.HostIdentityDigest || input.Subject.CallerUID != input.Input.AutomationUID || debianaccess.ValidateDesiredInput(input.Input) != nil {
			fail(apiFailure(generated.ErrorCodeInputInvalid, "access-input"))
			return
		}
		rendered, e := c.Renderer.RenderRole(r.Context(), input.Input)
		if e != nil {
			fail(e)
			return
		}
		input.Input.RenderedAccess = rendered
		input.Input.RenderedAccessDigest = hostaction.Digest(rendered)
		raw, e := json.Marshal(input.Input)
		if e != nil {
			fail(e)
			return
		}
		if _, e = debianaccess.DecodeInput(raw); e != nil {
			fail(apiFailure(generated.ErrorCodeInputInvalid, "access-render"))
			return
		}
		compiled, e := debianaccess.BuildDraft(input)
		if e != nil {
			fail(apiFailure(generated.ErrorCodeInputInvalid, "access-sequence"))
			return
		}
		requests, ops, bindings, seq := compiled.Requests, compiled.Operations, compiled.Bindings, compiled.Sequence
		if e := c.Hosts.ValidateAccessPreparation(r.Context(), requests); e != nil {
			fail(e)
			return
		}
		apply := requests[0]
		id := "host-access-" + hostaction.Digest(seq)[7:39]
		if _, e = app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "declaration.author", ResourceKind: "declaration", ResourceID: id}); e != nil {
			fail(e)
			return
		}
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			fail(apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		attribution, e := hostdiscovery.Attribution(r.Context(), id)
		if e != nil {
			fail(e)
			return
		}
		for _, request := range requests {
			if _, e = c.Hosts.StageDraft(r.Context(), request, attribution); e != nil {
				fail(e)
				return
			}
		}
		declops := make([]generated.DeclarationOperation, len(ops))
		for i, op := range ops {
			declops[i] = generated.DeclarationOperation{Sequence: op.Sequence, OperationID: op.OperationID, OperationType: op.OperationType, AdapterID: op.AdapterID, TargetID: op.TargetID, InputDigest: op.InputDigest, ArtifactDigest: op.ArtifactDigest}
		}
		manifest := credentialref.ManifestDigest(bindings)
		decl := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: id, DeclarationType: "host.access", ExpectedRevision: 1, ExpectedStateRevision: apply.ExpectedStateRevision, RecoveryEpoch: apply.RecoveryEpoch, ReasonDigest: hostaction.Digest(seq), Extensions: []generated.ContractExtension{{Name: "x-host-access-sequence", ValueDigest: hostaction.Digest(seq)}, {Name: "x-credential-bindings", ValueDigest: manifest}}, Operations: declops}
		revised, e := c.Declarations.Revise(r.Context(), change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: id}, decl)
		if e != nil {
			fail(e)
			return
		}
		_, e = c.Credentials.StageStepBindings(r.Context(), store.CredentialBindingStageRequest{DeclarationID: id, DeclarationRevision: 1, Bindings: bindings, Expected: store.RevisionToken{StateRevision: revised.Document.StateRevision, RecoveryEpoch: apply.RecoveryEpoch}, Attribution: attribution, KeyDigest: hostaction.Digest([]string{id, "credentials"}), RequestDigest: manifest})
		if e != nil {
			fail(e)
			return
		}
		response := generated.HostActionSubmission{Schema: generated.SchemaIDHostActionSubmission, SchemaVersion: "1.0.0", DraftID: id, DeclarationID: id, ContentDigest: hostaction.Digest(seq), OriginalRequestDigest: originalRequestDigest, StateRevision: revised.Document.StateRevision + 1, RecoveryEpoch: apply.RecoveryEpoch}
		app.success(w, operation, response.StateRevision, response.RecoveryEpoch, response)
	}
}
