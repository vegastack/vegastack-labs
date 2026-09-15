package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// GateOperations only drafts source-generated, bounded input. It deliberately
// has no setter for an applied profile or a gate result.
type GateOperations struct {
	Gates        *store.GateRepository
	Revisions    *store.PlanRepository
	Declarations *change.Service
	Results      *result.Factory
	Build        result.BuildInfo
	Clock        func() time.Time
}

func RegisterGateOperations(app *Application, config GateOperations) error {
	if app == nil || config.Gates == nil || config.Revisions == nil || config.Declarations == nil || config.Results == nil || config.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "gate-config")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	app.routes = append(app.routes,
		route{id: "api.v1.gate-profile-drafts.create", method: http.MethodPost, pattern: "/api/v1/gates/profile-drafts", capability: "gate.profile.author", kind: "profile", action: authorization.ActionAuthor, handler: app.profileDraft(config)},
		route{id: "api.v1.gates.list", method: http.MethodGet, pattern: "/api/v1/gates", capability: "gate.read", kind: "gate", handler: app.gatesList(config)},
		route{id: "api.v1.gates.get", method: http.MethodGet, pattern: "/api/v1/gates/{gateId}", capability: "gate.read", kind: "gate", handler: app.gateGet(config)},
		route{id: "api.v1.gates.check", method: http.MethodPost, pattern: "/api/v1/gates/check", capability: "gate.read", kind: "gate", handler: app.gateCheck(config)},
		route{id: "api.v1.gate-evidence.create", method: http.MethodPost, pattern: "/api/v1/gates/{gateId}/evidence", capability: "gate.evidence.author", kind: "gate", action: authorization.ActionAuthor, handler: app.gateEvidenceDraft(config)},
	)
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-5]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func gateDefinition(id string) (generated.GateDefinition, bool) {
	for _, item := range generated.GeneratedGateDefinitions {
		if item.GateID == id {
			return item, true
		}
	}
	return generated.GateDefinition{}, false
}

func gateRevision(ctx context.Context, config GateOperations) (store.RevisionToken, error) {
	return config.Revisions.CurrentRevision(ctx)
}

func gateScope(ctx context.Context, config GateOperations) (gate.ResolvedScope, bool, error) {
	applied, err := config.Gates.GetAppliedProfileScope(ctx)
	if err != nil {
		if store.Code(err) == generated.ErrorCodeResourceNotFound {
			return gate.ResolvedScope{}, false, nil
		}
		return gate.ResolvedScope{}, false, err
	}
	return gate.ResolvedScope{ProfileID: applied.ProfileID, ProfileVersion: applied.ProfileVersion, PolicyID: applied.PolicyID, PolicyVersion: applied.PolicyVersion, Capabilities: applied.Capabilities, StateRevision: applied.StateRevision, RecoveryEpoch: applied.RecoveryEpoch}, true, nil
}

func gateUnknown(def generated.GateDefinition, subjectID, reason string, at time.Time, epoch int64) generated.GateEvaluation {
	sum := sha256.Sum256([]byte(def.GateID + "\x00" + subjectID + "\x00" + at.UTC().Format(time.RFC3339Nano)))
	return generated.GateEvaluation{Schema: generated.SchemaIDGateEvaluation, SchemaVersion: "1.1.0", EvaluationID: "eval-" + hex.EncodeToString(sum[:12]), GateID: def.GateID, SubjectID: subjectID, DefinitionVersion: def.DefinitionVersion, EvaluatorVersion: def.EvaluatorVersion, EvidenceIDs: []string{}, EvaluatedAt: at.UTC().Truncate(time.Second).Format(time.RFC3339), RecoveryEpoch: epoch, Outcome: "unknown", ReasonCode: reason, EvidenceSource: "none", ReadyForInput: false}
}

func gateResult(ctx context.Context, config GateOperations, def generated.GateDefinition, subjectID string, token store.RevisionToken) (generated.GateView, error) {
	at := config.Clock().UTC().Truncate(time.Second)
	scope, found, err := gateScope(ctx, config)
	if err != nil {
		return generated.GateView{}, err
	}
	evaluation := gateUnknown(def, subjectID, "applied-profile-missing", at, token.RecoveryEpoch)
	reason := "applied-profile-missing"
	if found {
		if scope.RecoveryEpoch != token.RecoveryEpoch || scope.StateRevision > token.StateRevision {
			evaluation.ReasonCode = "applied-profile-stale"
			reason = "applied-profile-stale"
		} else if len(def.SubjectKinds) == 0 {
			evaluation.ReasonCode = "subject-kind-unresolved"
			reason = "subject-kind-unresolved"
		} else {
			items := gate.ResolveDefinitions(scope, def.SubjectKinds[0])
			for _, item := range items {
				if item.Definition.ID == def.GateID {
					reason = item.ReasonCode
					break
				}
			}
			evaluation, err = gate.Evaluate(ctx, config.Gates, scope, gate.Subject{ID: subjectID, Kind: def.SubjectKinds[0], ReleaseBuildID: config.Build.ReleaseBuildID, ToolVersion: config.Build.ToolVersion, StateRevision: token.StateRevision}, def.GateID, at, gate.NewProofRegistry())
			if err != nil {
				return generated.GateView{}, err
			}
		}
	}
	view := generated.GateView{Schema: generated.SchemaIDGateView, SchemaVersion: "1.1.0", Definition: def, Evaluation: evaluation, ApplicabilityReasonCode: reason}
	raw, err := json.Marshal(view)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDGateView, raw, generated.ContractExact) != nil {
		return generated.GateView{}, apiFailure(generated.ErrorCodeIntegrityFailure, "gate-projection")
	}
	return view, nil
}

func (app *Application) gatesList(config GateOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.gates.list"
		if r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "query"))
			return
		}
		token, err := gateRevision(r.Context(), config)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		data := generated.GateListData{Schema: generated.SchemaIDGateListData, SchemaVersion: "1.1.0", Gates: []generated.GateView{}, RecoveryEpoch: token.RecoveryEpoch}
		for _, def := range generated.GeneratedGateDefinitions {
			view, err := gateResult(r.Context(), config, def, "scope", token)
			if err != nil {
				app.failure(w, op, err)
				return
			}
			data.Gates = append(data.Gates, view)
		}
		raw, _ := json.Marshal(data)
		if generated.ValidateContractJSON(generated.SchemaIDGateListData, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeIntegrityFailure, "gate-list"))
			return
		}
		app.success(w, op, token.StateRevision, token.RecoveryEpoch, data)
	}
}

func (app *Application) gateGet(config GateOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.gates.get"
		def, ok := gateDefinition(params["gateId"])
		if !ok || r.URL.RawQuery != "" {
			app.failure(w, op, apiFailure(generated.ErrorCodeResourceNotFound, "gate"))
			return
		}
		token, err := gateRevision(r.Context(), config)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		view, err := gateResult(r.Context(), config, def, "scope", token)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, token.StateRevision, token.RecoveryEpoch, view)
	}
}

func (app *Application) gateCheck(config GateOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.gates.check"
		var input generated.GateCheckRequest
		if err := decodeOperationRequest(r, 4096, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "gateId", "subjectId", "definitionVersion"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		def, ok := gateDefinition(input.GateID)
		if !ok || generated.ValidateContractJSON(generated.SchemaIDGateCheckRequest, raw, generated.ContractExact) != nil || def.DefinitionVersion != input.DefinitionVersion {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "gate-check"))
			return
		}
		principal, authenticated := identity.PrincipalFromContext(r.Context())
		if !authenticated {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		if _, err := app.config.Authorizer.AuthorizeRead(r.Context(), principal, authorization.ReadTarget{Capability: "gate.read", ResourceKind: "gate", ResourceID: strings.ToLower(input.GateID)}); err != nil {
			app.failure(w, op, err)
			return
		}
		token, err := gateRevision(r.Context(), config)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if token.StateRevision != input.ExpectedStateRevision || token.RecoveryEpoch != input.RecoveryEpoch {
			app.failure(w, op, apiFailure(generated.ErrorCodePlanStale, "gate-check"))
			return
		}
		view, err := gateResult(r.Context(), config, def, input.SubjectID, token)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		app.success(w, op, token.StateRevision, token.RecoveryEpoch, view.Evaluation)
	}
}

func gateAuthor(r *http.Request, requestID string) (audit.Attribution, change.AuthorScope, error) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		return audit.Attribution{}, change.AuthorScope{}, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal")
	}
	return audit.Attribution{AuthenticatedPrincipalID: principal.ID, AuthenticatedPrincipalMethod: principal.Method}, change.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: requestID}, nil
}

func gateRequestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (app *Application) profileDraft(config GateOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const op = "api.v1.gate-profile-drafts.create"
		var input generated.GateProfileDraftRequest
		if err := decodeOperationRequest(r, 4096, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "bindingId", "profileId", "profileVersion", "policyId", "policyVersion", "capabilities"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDGateProfileDraftRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "profile-contract"))
			return
		}
		scope := store.GateAppliedProfile{ProfileID: input.ProfileID, ProfileVersion: input.ProfileVersion, PolicyID: input.PolicyID, PolicyVersion: input.PolicyVersion, Capabilities: input.Capabilities}
		digest, err := store.ProfileScopeDigest(scope)
		if err != nil || digest != input.TargetDigest {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "profile-digest"))
			return
		}
		token, err := gateRevision(r.Context(), config)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if token.StateRevision != input.ExpectedStateRevision || token.RecoveryEpoch != input.RecoveryEpoch {
			app.failure(w, op, apiFailure(generated.ErrorCodePlanStale, "profile-draft"))
			return
		}
		if _, err = app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "declaration.author", ResourceKind: "declaration", ResourceID: "gate-profile-" + input.BindingID}); err != nil {
			app.failure(w, op, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		attribution, author, err := gateAuthor(r, requestID)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		draft, err := config.Gates.PutProfileDraft(r.Context(), store.ProfileDraftRequest{BindingID: input.BindingID, Scope: scope, TargetDigest: input.TargetDigest, Expected: token, KeyDigest: gateRequestDigest([]byte(input.IdempotencyKey)), RequestDigest: gateRequestDigest(raw), Attribution: attribution})
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		current, err := gateRevision(r.Context(), config)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		declaration, err := gate.BuildProfileChange(draft, current)
		if err != nil {
			app.operationFailure(w, op, requestID, apiFailure(generated.ErrorCodePlanStale, "profile-change"))
			return
		}
		revised, err := config.Declarations.Revise(r.Context(), author, declaration)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		data := generated.GateProfileDraftSubmission{Schema: generated.SchemaIDGateProfileDraftSubmission, SchemaVersion: "1.1.0", DraftID: input.BindingID, ChangeID: revised.Document.DeclarationID, BindingID: input.BindingID, Status: "draft", StateRevision: revised.Document.StateRevision, RecoveryEpoch: revised.Document.RecoveryEpoch}
		app.operationSuccess(w, op, requestID, true, data.StateRevision, data.RecoveryEpoch, data)
	}
}

func (app *Application) gateEvidenceDraft(config GateOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.gate-evidence.create"
		var input generated.GateEvidenceRequest
		if err := decodeOperationRequest(r, 65536, []string{"schema", "schemaVersion", "expectedStateRevision", "recoveryEpoch", "targetDigest", "idempotencyKey", "evidenceId", "gateId", "subjectId", "definitionVersion", "evaluatorVersion", "supersedesEvidenceId", "revokesEvidenceId", "artifactDigest", "observedAt", "bundle"}, &input); err != nil {
			app.failure(w, op, err)
			return
		}
		raw, _ := json.Marshal(input)
		def, ok := gateDefinition(input.GateID)
		if !ok || input.GateID != params["gateId"] || input.TargetDigest != input.ArtifactDigest || input.ObservedAt != input.Bundle.ObservedAt || len(input.Bundle.Attachments) != 0 || def.DefinitionVersion != input.DefinitionVersion || def.EvaluatorVersion != input.EvaluatorVersion || generated.ValidateContractJSON(generated.SchemaIDGateEvidenceRequest, raw, generated.ContractExact) != nil {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "gate-evidence-contract"))
			return
		}
		if len(def.SubjectKinds) == 0 {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "gate-subject"))
			return
		}
		token, err := gateRevision(r.Context(), config)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if token.StateRevision != input.ExpectedStateRevision || token.RecoveryEpoch != input.RecoveryEpoch {
			app.failure(w, op, apiFailure(generated.ErrorCodePlanStale, "gate-evidence"))
			return
		}
		if _, err = app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "declaration.author", ResourceKind: "declaration", ResourceID: "gate-evidence-" + input.EvidenceID}); err != nil {
			app.failure(w, op, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		attribution, author, err := gateAuthor(r, requestID)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		draft, err := config.Gates.PutGateDraft(r.Context(), store.GateDraftRequest{EvidenceID: input.EvidenceID, GateID: input.GateID, SubjectID: input.SubjectID, DefinitionVersion: input.DefinitionVersion, EvaluatorVersion: input.EvaluatorVersion, SourceKind: "fixture", ProofClass: "fixture", SupersedesEvidenceID: input.SupersedesEvidenceID, RevokesEvidenceID: input.RevokesEvidenceID, ArtifactDigest: input.ArtifactDigest, Bundle: input.Bundle, Expected: token, KeyDigest: gateRequestDigest([]byte(input.IdempotencyKey)), RequestDigest: gateRequestDigest(raw), Attribution: attribution})
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		current, err := gateRevision(r.Context(), config)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		declaration, err := gate.BuildEvidenceChange(draft, current)
		if err != nil {
			app.operationFailure(w, op, requestID, apiFailure(generated.ErrorCodePlanStale, "gate-change"))
			return
		}
		revised, err := config.Declarations.Revise(r.Context(), author, declaration)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		data := generated.GateEvidenceSubmission{Schema: generated.SchemaIDGateEvidenceSubmission, SchemaVersion: "1.1.0", DraftID: draft.DraftID, ChangeID: revised.Document.DeclarationID, EvidenceID: input.EvidenceID, Status: "draft", StateRevision: revised.Document.StateRevision, RecoveryEpoch: revised.Document.RecoveryEpoch}
		app.operationSuccess(w, op, requestID, true, data.StateRevision, data.RecoveryEpoch, data)
	}
}

// Gate authoring and profile drafts stay local/operator-only. A direct
// bind/pass/revoke route is intentionally not registered.
