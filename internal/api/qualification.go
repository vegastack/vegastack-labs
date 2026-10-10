package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// The constructor installs the concrete protected producer. HTTP input cannot
// supply an observer, observations, a report, or evidence classification.
type QualificationService interface {
	LookupNativeProducerData(context.Context, generated.NativeProducerLookupRequest) (generated.NativeProducerLookupData, error)
	Inspect(context.Context, generated.QualificationInspectRequest) (generated.QualificationInspectData, error)
	CollectDraft(context.Context, generated.NativeCollectRequest, audit.Attribution) (store.GateDraft, []generated.ScenarioResult, error)
}
type QualificationOperations struct {
	Service      QualificationService
	Revisions    *store.PlanRepository
	Declarations DeclarationService
	Results      *result.Factory
}

func RegisterQualificationOperations(app *Application, c QualificationOperations) error {
	if app == nil || c.Service == nil || c.Revisions == nil || c.Declarations == nil || c.Results == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "qualification-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.qualification.producer", method: http.MethodPost, pattern: "/api/v1/qualification/native/producer", deferredAuthorization: true, handler: app.qualificationProducer(c)}, route{id: "api.v1.qualification.inspect", method: http.MethodPost, pattern: "/api/v1/qualification/inspect", deferredAuthorization: true, handler: app.qualificationInspect(c)}, route{id: "api.v1.qualification.collect", method: http.MethodPost, pattern: "/api/v1/qualification/collect", deferredAuthorization: true, handler: app.qualificationCollect(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-3]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func qualificationLocal(r *http.Request) bool {
	p, ok := identity.PrincipalFromContext(r.Context())
	return ok && p.Method == identity.LocalOSPeerMethod
}
func (app *Application) qualificationInspect(c QualificationOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.qualification.inspect"
		if !qualificationLocal(r) {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthorizationDenied, "operator-local"))
			return
		}
		var in generated.QualificationInspectRequest
		if decodeOperationRequest(r, 32768, []string{"schema", "schemaVersion", "targetId", "targetRevision", "targetDigest", "scope", "expectedStateRevision", "recoveryEpoch"}, &in) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "qualification-inspect"))
			return
		}
		raw, _ := json.Marshal(in)
		if generated.ValidateContractJSON(generated.SchemaIDQualificationInspectRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "qualification-inspect"))
			return
		}
		if _, err := app.authorizeAction(r, authorization.ActionRead, authorization.Target{Capability: "host.discovery.collect", ResourceKind: "host-discovery-target", ResourceID: in.TargetID}); err != nil {
			app.failure(w, op, err)
			return
		}
		out, err := c.Service.Inspect(r.Context(), in)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if out.RequestDigest != hostaction.Digest(in) || out.StateRevision != in.ExpectedStateRevision || out.RecoveryEpoch != in.RecoveryEpoch || out.Facts.TargetID != in.TargetID || out.Facts.TargetRevision != in.TargetRevision || out.Facts.TargetDigest != in.TargetDigest {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "qualification-binding"))
			return
		}
		app.success(w, op, out.StateRevision, out.RecoveryEpoch, out)
	}
}
func (app *Application) qualificationCollect(c QualificationOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.qualification.collect"
		if !qualificationLocal(r) {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthorizationDenied, "operator-local"))
			return
		}
		var in generated.NativeCollectRequest
		if decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "scopeDigest", "stage", "evidenceId", "profileId", "producers", "expectedStateRevision", "recoveryEpoch", "idempotencyKey"}, &in, "hostId", "hostGateId") != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "native-collect"))
			return
		}
		raw, _ := json.Marshal(in)
		if generated.ValidateContractJSON(generated.SchemaIDNativeCollectRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "native-collect"))
			return
		}
		gateID, subjectID, valid := store.NativeCollectSubject(in)
		if !valid {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "native-host-subject"))
			return
		}
		targets := []authorization.Target{{Capability: "gate.evidence.author", ResourceKind: "gate", ResourceID: "native." + in.Stage}, {Capability: "declaration.author", ResourceKind: "declaration", ResourceID: "gate-evidence-" + in.EvidenceID}}
		if in.HostID != "" {
			targets = append(targets, authorization.Target{Capability: "gate.evidence.author", ResourceKind: "gate", ResourceID: gateID})
		}
		for _, target := range targets {
			if _, err := app.authorizeAction(r, authorization.ActionAuthor, target); err != nil {
				app.failure(w, op, err)
				return
			}
		}
		requestID, err := c.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		attribution, author, err := gateAuthor(r, requestID)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		draft, scenarios, err := c.Service.CollectDraft(r.Context(), in, attribution)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		if draft.SourceKind != "local" || draft.ProofClass != "live" || draft.EvidenceID != in.EvidenceID || draft.GateID != gateID || draft.SubjectID != subjectID || draft.RecoveryEpoch != in.RecoveryEpoch {
			app.operationFailure(w, op, requestID, apiFailure(generated.ErrorCodeIntegrityFailure, "native-draft"))
			return
		}
		current, err := c.Revisions.CurrentRevision(r.Context())
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		declaration, err := gate.BuildEvidenceChange(draft, current)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		revised, err := c.Declarations.Revise(r.Context(), author, declaration)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		submission := generated.GateEvidenceSubmission{Schema: generated.SchemaIDGateEvidenceSubmission, SchemaVersion: "1.1.0", DraftID: draft.DraftID, ChangeID: revised.Document.DeclarationID, EvidenceID: in.EvidenceID, Status: "draft", StateRevision: revised.Document.StateRevision, RecoveryEpoch: revised.Document.RecoveryEpoch}
		out := generated.NativeCollectData{Schema: generated.SchemaIDNativeCollectData, SchemaVersion: "1.0.0", Submission: submission, RequestDigest: hostaction.Digest(in), BundleDigest: draft.BundleDigest, Scenarios: scenarios}
		app.operationSuccess(w, op, requestID, true, submission.StateRevision, submission.RecoveryEpoch, out)
	}
}
