package api

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	mesh "github.com/vegastack/vegastack-labs/internal/networkmesh"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
)

type MeshOperations struct {
	Repository   *store.MeshRepository
	Declarations *change.Service
	Credentials  *store.CredentialRepository
	Results      *result.Factory
	Observe      func(context.Context, generated.MeshDraftRequest) (generated.MeshStatusData, error)
}

func RegisterMeshOperations(app *Application, c MeshOperations) error {
	if app == nil || c.Repository == nil || c.Declarations == nil || c.Credentials == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "mesh-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.network.mesh.observe", method: http.MethodPost, pattern: "/api/v1/network/mesh/observe", deferredAuthorization: true, handler: app.meshObserve(c)}, route{id: "api.v1.network.mesh.draft", method: http.MethodPost, pattern: "/api/v1/network/mesh/draft", deferredAuthorization: true, handler: app.meshDraft(c)}, route{id: "api.v1.network.mesh.status", method: http.MethodGet, pattern: "/api/v1/network/mesh/{profileID}", deferredAuthorization: true, handler: app.meshStatus(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-3]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) meshDraft(c MeshOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.network.mesh.draft"
		var q generated.MeshDraftRequest
		if e := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "change", "expectedStateRevision", "recoveryEpoch", "idempotencyKey"}, &q); e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(q)
		if generated.ValidateContractJSON(generated.SchemaIDMeshDraftRequest, raw, generated.ContractExact) != nil || mesh.Validate(q.Change) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "mesh-request"))
			return
		}
		if _, e := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "network.mesh.prepare", ResourceKind: "mesh-profile", ResourceID: q.Change.ProfileID}); e != nil {
			app.failure(w, op, e)
			return
		}
		a, e := hostdiscovery.Attribution(r.Context(), "mesh-"+mesh.Digest(q)[7:39])
		if e != nil {
			app.failure(w, op, e)
			return
		}
		d, e := c.Repository.Stage(r.Context(), q, a)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		p, _ := identity.PrincipalFromContext(r.Context())
		requestID, e := c.Results.RequestID()
		if e != nil {
			app.failure(w, op, e)
			return
		}
		manifest := credentialref.ManifestDigest(d.Bindings)
		decl := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: d.ID, DeclarationType: "network.mesh", ExpectedRevision: 1, ExpectedStateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch, ReasonDigest: d.Digest, Extensions: []generated.ContractExtension{{Name: mesh.Extension, ValueDigest: d.Digest}, {Name: "x-credential-bindings", ValueDigest: manifest}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: mesh.OperationID, OperationType: "network.mesh." + q.Change.Action, AdapterID: mesh.AdapterID, TargetID: q.Change.ProfileID, InputDigest: credentialref.OperationManifestDigest(d.Bindings, mesh.OperationID), ArtifactDigest: d.Digest, Idempotent: false}}}
		revised, e := c.Declarations.Revise(r.Context(), change.AuthorScope{PrincipalID: p.ID, PrincipalMethod: p.Method, AgentSessionID: requestID}, decl)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		_, e = c.Credentials.StageStepBindings(r.Context(), store.CredentialBindingStageRequest{DeclarationID: d.ID, DeclarationRevision: 1, Bindings: d.Bindings, Expected: store.RevisionToken{StateRevision: revised.Document.StateRevision, RecoveryEpoch: q.RecoveryEpoch}, Attribution: a, KeyDigest: mesh.Digest([]string{d.ID, "credential-bindings"}), RequestDigest: manifest})
		if e != nil {
			app.failure(w, op, e)
			return
		}
		data := generated.MeshDraftSubmission{Schema: generated.SchemaIDMeshDraftSubmission, SchemaVersion: "1.0.0", DraftID: d.ID, DeclarationID: d.ID, ContentDigest: d.Digest, StateRevision: revised.Document.StateRevision + 1, RecoveryEpoch: q.RecoveryEpoch}
		app.success(w, op, data.StateRevision, data.RecoveryEpoch, data)
	}
}
func (app *Application) meshStatus(c MeshOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, p map[string]string) {
		const op = "api.v1.network.mesh.status"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "mesh-query"))
			return
		}
		if _, e := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "network.mesh.read", ResourceKind: "mesh-profile", ResourceID: p["profileID"]}); e != nil {
			app.failure(w, op, e)
			return
		}
		data, e := c.Repository.Status(r.Context(), p["profileID"])
		if e != nil {
			app.failure(w, op, e)
			return
		}
		app.success(w, op, data.StateRevision, data.RecoveryEpoch, data)
	}
}

func (app *Application) meshObserve(c MeshOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.network.mesh.observe"
		var q generated.MeshDraftRequest
		if e := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "change", "expectedStateRevision", "recoveryEpoch", "idempotencyKey"}, &q); e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(q)
		if generated.ValidateContractJSON(generated.SchemaIDMeshDraftRequest, raw, generated.ContractExact) != nil || mesh.Validate(q.Change) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "mesh-observe"))
			return
		}
		if _, e := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "network.mesh.read", ResourceKind: "mesh-profile", ResourceID: q.Change.ProfileID}); e != nil {
			app.failure(w, op, e)
			return
		}
		if c.Observe == nil {
			app.failure(w, op, apiFailure(generated.ErrorCodePrerequisiteBlocked, "mesh-observe"))
			return
		}
		d, e := c.Observe(r.Context(), q)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		app.success(w, op, d.StateRevision, d.RecoveryEpoch, d)
	}
}
