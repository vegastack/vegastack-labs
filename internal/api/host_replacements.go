package api

import (
	"context"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type HostReplacementRepository interface {
	Stage(context.Context, generated.HostReplacementRequest, audit.Attribution) (store.HostReplacementDraft, error)
	Get(context.Context, string) (generated.HostReplacementState, error)
}
type HostReplacementOperations struct {
	Replacements HostReplacementRepository
	Declarations DeclarationService
	Results      *result.Factory
}

func RegisterHostReplacementOperations(app *Application, c HostReplacementOperations) error {
	if app == nil || c.Replacements == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "host-replacement-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.host-replacements.create", method: http.MethodPost, pattern: "/api/v1/host-replacements", deferredAuthorization: true, handler: app.replacementDraft(c)}, route{id: "api.v1.host-replacements.get", method: http.MethodGet, pattern: "/api/v1/host-replacements/{replacementId}", deferredAuthorization: true, handler: app.replacementGet(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-2]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) replacementDraft(c HostReplacementOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.host-replacements.create"
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok || principal.Method != identity.LocalOSPeerMethod {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthorizationDenied, "operator-local"))
			return
		}
		var in generated.HostReplacementRequest
		required := []string{"schema", "schemaVersion", "replacementId", "operation", "restorationClass", "oldHostId", "newHostId", "oldIdentityDigest", "newIdentityDigest", "oldTargetDigest", "newTargetDigest", "oldTargetRevision", "newTargetRevision", "oldSshHostKeyDigest", "newSshHostKeyDigest", "profileId", "profileLockDigest", "oldRoleBindingDigest", "roleDeclarationId", "roleDeclarationRevision", "proposedRoleDeclarationId", "proposedRoleDeclarationRevision", "proposedRoleBindingDigest", "aliasBindings", "payloadIds", "volumeIds", "resourceIds", "preservedPreimageDigest", "osPreparation", "expectedDeclarationRevision", "expectedStateRevision", "recoveryEpoch", "idempotencyKey"}
		if decodeOperationRequest(r, hostreplacement.MaximumInput, required, &in, "source") != nil || hostreplacement.ValidateInput(in) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "host-replacement"))
			return
		}
		for _, id := range []string{in.OldHostID, in.NewHostID} {
			if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "host.replacement.prepare", ResourceKind: "host", ResourceID: id}); err != nil {
				app.failure(w, op, err)
				return
			}
		}
		d := hostaction.Digest(in)
		id := "host-replacement-" + d[7:39]
		if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "declaration.author", ResourceKind: "declaration", ResourceID: id}); err != nil {
			app.failure(w, op, err)
			return
		}
		attribution, err := hostdiscovery.Attribution(r.Context(), id)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		draft, err := c.Replacements.Stage(r.Context(), in, attribution)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if draft.ID != id || draft.Digest != d || hostaction.Digest(draft.Request) != d {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "replacement-draft"))
			return
		}
		requestID, err := c.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		author := change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: requestID}
		if attribution.Agent != nil {
			author.AgentName = attribution.Agent.Name
			author.AgentSessionID = attribution.Agent.SessionID
		}
		operation := hostreplacement.FreezeOperation
		if in.Operation == "commit" {
			operation = hostreplacement.CommitOperation
		}
		// Each attempt has its own deterministic draft/declaration, so revision one
		// is exact. ExpectedDeclarationRevision belongs to replacement continuation.
		req := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: id, DeclarationType: "host.replacement", ExpectedRevision: 1, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, ReasonDigest: d, Extensions: []generated.ContractExtension{{Name: hostreplacement.ReplacementExtension, ValueDigest: d}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "host-replacement-" + in.Operation, OperationType: operation, AdapterID: hostreplacement.AdapterID, TargetID: id, InputDigest: d, ArtifactDigest: d, Idempotent: true}}}
		revised, err := c.Declarations.Revise(r.Context(), author, req)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		out := generated.HostReplacementSubmission{Schema: generated.SchemaIDHostReplacementSubmission, SchemaVersion: "1.0.0", ReplacementID: in.ReplacementID, DraftID: id, DeclarationID: id, ContentDigest: d, StateRevision: revised.Document.StateRevision, RecoveryEpoch: revised.Document.RecoveryEpoch}
		app.success(w, op, out.StateRevision, out.RecoveryEpoch, out)
	}
}
func (app *Application) replacementGet(c HostReplacementOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, p map[string]string) {
		const op = "api.v1.host-replacements.get"
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok || principal.Method != identity.LocalOSPeerMethod {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthorizationDenied, "operator-local"))
			return
		}
		if r.URL.RawQuery != "" || !pathToken.MatchString(p["replacementId"]) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "replacement-query"))
			return
		}
		state, err := c.Replacements.Get(r.Context(), p["replacementId"])
		if err != nil {
			app.failure(w, op, err)
			return
		}
		for _, id := range []string{state.OldHostID, state.NewHostID} {
			if _, err := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "host.read", ResourceKind: "host", ResourceID: id}); err != nil {
				app.failure(w, op, err)
				return
			}
		}
		app.success(w, op, state.StateRevision, state.RecoveryEpoch, state)
	}
}
