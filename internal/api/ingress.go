package api

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
)

type IngressOperations struct {
	PilotEvidence func(context.Context, generated.IngressPilotEvidenceRequest) (store.GateDraft, error)
	Revisions     *store.PlanRepository
	Rollout       func(context.Context, generated.IngressRolloutEvidenceRequest) (generated.IngressStatusData, error)
	Repository    *store.IngressRepository
	Declarations  *change.Service
	Credentials   *store.CredentialRepository
	Results       *result.Factory
	Observe       func(context.Context, generated.IngressDraftRequest) (generated.IngressStatusData, error)
}

func RegisterIngressOperations(app *Application, c IngressOperations) error {
	if app == nil || c.Repository == nil || c.Declarations == nil || c.Credentials == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "ingress-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.network.ingress.pilot-evidence", method: http.MethodPost, pattern: "/api/v1/network/ingress/pilot-evidence", deferredAuthorization: true, handler: app.ingressPilotEvidence(c)}, route{id: "api.v1.network.ingress.rollout-evidence", method: http.MethodPost, pattern: "/api/v1/network/ingress/rollout-evidence", deferredAuthorization: true, handler: app.ingressRollout(c)}, route{id: "api.v1.network.ingress.observe", method: http.MethodPost, pattern: "/api/v1/network/ingress/observe", deferredAuthorization: true, handler: app.ingressObserve(c)}, route{id: "api.v1.network.ingress.draft", method: http.MethodPost, pattern: "/api/v1/network/ingress/draft", deferredAuthorization: true, handler: app.ingressDraft(c)}, route{id: "api.v1.network.ingress.status", method: http.MethodGet, pattern: "/api/v1/network/ingress/{profileID}", deferredAuthorization: true, handler: app.ingressStatus(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-5]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) ingressDraft(c IngressOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.network.ingress.draft"
		var q generated.IngressDraftRequest
		if e := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "change", "expectedStateRevision", "recoveryEpoch", "idempotencyKey"}, &q); e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(q)
		if generated.ValidateContractJSON(generated.SchemaIDIngressDraftRequest, raw, generated.ContractExact) != nil || ingress.Validate(q.Change) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "ingress-request"))
			return
		}
		if _, e := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "network.ingress.prepare", ResourceKind: "ingress-profile", ResourceID: q.Change.ProfileID}); e != nil {
			app.failure(w, op, e)
			return
		}
		a, e := hostdiscovery.Attribution(r.Context(), "ingress-"+ingress.Digest(q)[7:39])
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
		decl := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: d.ID, DeclarationType: "network.ingress", ExpectedRevision: 1, ExpectedStateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch, ReasonDigest: d.Digest, Extensions: []generated.ContractExtension{{Name: ingress.Extension, ValueDigest: d.Digest}, {Name: "x-credential-bindings", ValueDigest: manifest}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: ingress.OperationID, OperationType: "network.ingress." + q.Change.Action, AdapterID: ingress.AdapterID, TargetID: q.Change.ProfileID, InputDigest: credentialref.OperationManifestDigest(d.Bindings, ingress.OperationID), ArtifactDigest: d.Digest, Idempotent: false}}}
		revised, e := c.Declarations.Revise(r.Context(), change.AuthorScope{PrincipalID: p.ID, PrincipalMethod: p.Method, AgentSessionID: requestID}, decl)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		_, e = c.Credentials.StageStepBindings(r.Context(), store.CredentialBindingStageRequest{DeclarationID: d.ID, DeclarationRevision: 1, Bindings: d.Bindings, Expected: store.RevisionToken{StateRevision: revised.Document.StateRevision, RecoveryEpoch: q.RecoveryEpoch}, Attribution: a, KeyDigest: ingress.Digest([]string{d.ID, "credential-bindings"}), RequestDigest: manifest})
		if e != nil {
			app.failure(w, op, e)
			return
		}
		data := generated.IngressDraftSubmission{Schema: generated.SchemaIDIngressDraftSubmission, SchemaVersion: "1.0.0", DraftID: d.ID, DeclarationID: d.ID, ContentDigest: d.Digest, StateRevision: revised.Document.StateRevision + 1, RecoveryEpoch: q.RecoveryEpoch}
		app.success(w, op, data.StateRevision, data.RecoveryEpoch, data)
	}
}
func (app *Application) ingressStatus(c IngressOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, p map[string]string) {
		const op = "api.v1.network.ingress.status"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "ingress-query"))
			return
		}
		if _, e := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "network.ingress.read", ResourceKind: "ingress-profile", ResourceID: p["profileID"]}); e != nil {
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

func (app *Application) ingressObserve(c IngressOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.network.ingress.observe"
		var q generated.IngressDraftRequest
		if e := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "change", "expectedStateRevision", "recoveryEpoch", "idempotencyKey"}, &q); e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(q)
		if generated.ValidateContractJSON(generated.SchemaIDIngressDraftRequest, raw, generated.ContractExact) != nil || ingress.Validate(q.Change) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "ingress-observe"))
			return
		}
		if _, e := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "network.ingress.read", ResourceKind: "ingress-profile", ResourceID: q.Change.ProfileID}); e != nil {
			app.failure(w, op, e)
			return
		}
		if c.Observe == nil {
			app.failure(w, op, apiFailure(generated.ErrorCodePrerequisiteBlocked, "ingress-observe"))
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

func (app *Application) ingressRollout(c IngressOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.network.ingress.rollout-evidence"
		var q generated.IngressRolloutEvidenceRequest
		if e := decodeOperationRequest(r, 16384, []string{"schema", "schemaVersion", "profileId", "rotationRunId", "materialVersion", "connectors", "expectedStateRevision", "recoveryEpoch", "idempotencyKey"}, &q); e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(q)
		if generated.ValidateContractJSON(generated.SchemaIDIngressRolloutEvidenceRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "ingress-rollout"))
			return
		}
		if _, e := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "network.ingress.read", ResourceKind: "ingress-profile", ResourceID: q.ProfileID}); e != nil {
			app.failure(w, op, e)
			return
		}
		if c.Rollout == nil {
			app.failure(w, op, apiFailure(generated.ErrorCodePrerequisiteBlocked, "ingress-rollout"))
			return
		}
		d, e := c.Rollout(r.Context(), q)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		app.success(w, op, d.StateRevision, d.RecoveryEpoch, d)
	}
}

func (app *Application) ingressPilotEvidence(c IngressOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.network.ingress.pilot-evidence"
		var q generated.IngressPilotEvidenceRequest
		if e := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "request", "gateId", "evidenceId"}, &q); e != nil {
			app.failure(w, op, e)
			return
		}
		raw, _ := json.Marshal(q)
		if generated.ValidateContractJSON(generated.SchemaIDIngressPilotEvidenceRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "pilot-evidence"))
			return
		}
		for _, target := range []authorization.Target{{Capability: "network.ingress.prepare", ResourceKind: "ingress-profile", ResourceID: q.Request.Change.ProfileID}, {Capability: "gate.evidence.author", ResourceKind: "gate", ResourceID: q.GateID}} {
			if _, e := app.authorizeAction(r, authorization.ActionAuthor, target); e != nil {
				app.failure(w, op, e)
				return
			}
		}
		if c.PilotEvidence == nil || c.Revisions == nil {
			app.failure(w, op, apiFailure(generated.ErrorCodePrerequisiteBlocked, "pilot-evidence"))
			return
		}
		id, e := c.Results.RequestID()
		if e != nil {
			app.failure(w, op, e)
			return
		}
		_, author, e := gateAuthor(r, id)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		draft, e := c.PilotEvidence(r.Context(), q)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		current, e := c.Revisions.CurrentRevision(r.Context())
		if e != nil {
			app.failure(w, op, e)
			return
		}
		declaration, e := gate.BuildEvidenceChange(draft, current)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		revised, e := c.Declarations.Revise(r.Context(), author, declaration)
		if e != nil {
			app.failure(w, op, e)
			return
		}
		data := generated.GateEvidenceSubmission{Schema: generated.SchemaIDGateEvidenceSubmission, SchemaVersion: "1.1.0", DraftID: draft.DraftID, ChangeID: revised.Document.DeclarationID, EvidenceID: q.EvidenceID, Status: "draft", StateRevision: revised.Document.StateRevision, RecoveryEpoch: revised.Document.RecoveryEpoch}
		app.operationSuccess(w, op, id, true, data.StateRevision, data.RecoveryEpoch, data)
	}
}
