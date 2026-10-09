package api

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net/http"
)

type BaselineRenderer interface {
	RenderPolicy(context.Context, generated.DebianBaselineInput) (string, error)
}
type RolePreparer interface {
	PrepareRole(context.Context, string, generated.LinuxRoleInput) (generated.LinuxRoleInput, error)
}
type HostActionOperations struct {
	RolePreparer     RolePreparer
	BaselineRenderer BaselineRenderer
	Hosts            *store.HostActionRepository
	Declarations     *change.Service
	Credentials      *store.CredentialRepository
	Results          *result.Factory
}

func RegisterHostActionOperations(app *Application, c HostActionOperations) error {
	if app == nil || c.Hosts == nil || c.Declarations == nil || c.Credentials == nil || c.Results == nil || c.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "host-action-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.host-actions.draft", method: http.MethodPost, pattern: "/api/v1/host-actions/draft", deferredAuthorization: true, handler: app.hostActionDraft(c)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-1]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}
func (app *Application) hostActionDraft(c HostActionOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, _ map[string]string) {
		const operation = "api.v1.host-actions.draft"
		var input generated.HostActionRequest
		if err := decodeOperationRequest(r, 131072, []string{"schema", "schemaVersion", "actionId", "actionVersion", "actionInputDigest", "actionInput", "hostId", "targetRevision", "targetDigest", "automationPrincipalId", "callerUid", "credentialReferenceId", "credentialMaterialVersion", "consoleConfirmation", "expectedStateRevision", "recoveryEpoch", "idempotencyKey"}, &input); err != nil {
			app.failure(w, operation, err)
			return
		}
		originalRequestDigest := hostaction.Digest(input)
		raw, _ := json.Marshal(input)
		if generated.ValidateContractJSON(generated.SchemaIDHostActionRequest, raw, generated.ContractExact) != nil {
			app.failure(w, operation, apiFailure(generated.ErrorCodeInputInvalid, "host-action"))
			return
		}
		if debianbaseline.IsAction(input.ActionID) {
			if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "host.action.prepare", ResourceKind: "host", ResourceID: input.HostID}); err != nil {
				app.failure(w, operation, err)
				return
			}
			if input.ActionID != "debian.volume-recovery.verify" {
				in, err := debianbaseline.DecodeDesiredInput([]byte(input.ActionInput))
				if err != nil || c.BaselineRenderer == nil {
					app.failure(w, operation, apiFailure(generated.ErrorCodePrerequisiteBlocked, "baseline-renderer"))
					return
				}
				in.RenderedPolicyDigest, err = c.BaselineRenderer.RenderPolicy(r.Context(), in)
				if err != nil || debianbaseline.ValidateInput(in) != nil {
					app.failure(w, operation, apiFailure(generated.ErrorCodeInputInvalid, "baseline-render"))
					return
				}
				raw, _ = json.Marshal(in)
				input.ActionInput = string(raw)
				input.ActionInputDigest = hostaction.BytesDigest(raw)
			}
			if err := c.Hosts.ValidateBaselinePreparation(r.Context(), input); err != nil {
				app.failure(w, operation, err)
				return
			}
		}
		if linuxrole.IsAction(input.ActionID) {
			if _, err := app.authorizeAction(r, authorization.ActionAuthor, authorization.Target{Capability: "host.action.prepare", ResourceKind: "host", ResourceID: input.HostID}); err != nil {
				app.failure(w, operation, err)
				return
			}
			desired, decodeErr := linuxrole.DecodeDesiredInput([]byte(input.ActionInput))
			if decodeErr != nil || c.RolePreparer == nil {
				app.failure(w, operation, apiFailure(generated.ErrorCodePrerequisiteBlocked, "role-preparation"))
				return
			}
			prepared, err := c.RolePreparer.PrepareRole(r.Context(), input.ActionID, desired)
			if err != nil || linuxrole.ValidateInput(prepared) != nil {
				app.failure(w, operation, apiFailure(generated.ErrorCodePrerequisiteBlocked, "role-baseline"))
				return
			}
			raw, _ = json.Marshal(prepared)
			input.ActionInput = string(raw)
			input.ActionInputDigest = hostaction.BytesDigest(raw)
			if err = c.Hosts.ValidateRolePreparation(r.Context(), input); err != nil {
				app.failure(w, operation, err)
				return
			}
		}
		id := hostaction.DraftID(input)
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			app.failure(w, operation, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal"))
			return
		}
		attribution, err := hostdiscovery.Attribution(r.Context(), id)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		d, err := c.Hosts.StageDraft(r.Context(), input, attribution)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		response, err := stageHostActionDeclaration(r.Context(), c, principal, attribution, d)
		if err != nil {
			app.failure(w, operation, err)
			return
		}
		response.OriginalRequestDigest = originalRequestDigest
		app.success(w, operation, response.StateRevision, response.RecoveryEpoch, response)
	}
}
func stageHostActionDeclaration(ctx context.Context, c HostActionOperations, p identity.Principal, a audit.Attribution, d store.HostActionDraft) (generated.HostActionSubmission, error) {
	r := d.Request
	b := credentialref.StepBinding{OperationID: "host-action", AdapterID: hostaction.AdapterID, TargetID: r.HostID, ReferenceID: r.CredentialReferenceID, ConsumerID: hostaction.AdapterID, PurposeID: hostaction.PurposeID, MaterialVersion: r.CredentialMaterialVersion, ResolverID: "native-systemd", StateRevision: r.ExpectedStateRevision + 3, RecoveryEpoch: r.RecoveryEpoch}
	bindings := []credentialref.StepBinding{b}
	manifest := credentialref.ManifestDigest(bindings)
	decl := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: d.ID, DeclarationType: "host.action", ExpectedRevision: 1, ExpectedStateRevision: r.ExpectedStateRevision, RecoveryEpoch: r.RecoveryEpoch, ReasonDigest: d.Digest, Extensions: []generated.ContractExtension{{Name: "x-host-action", ValueDigest: d.Digest}, {Name: "x-credential-bindings", ValueDigest: manifest}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: b.OperationID, OperationType: hostaction.OperationType, AdapterID: hostaction.AdapterID, TargetID: r.HostID, InputDigest: credentialref.OperationManifestDigest(bindings, b.OperationID), ArtifactDigest: d.Digest, Idempotent: false}}}
	revised, err := c.Declarations.Revise(ctx, change.AuthorScope{PrincipalID: p.ID, PrincipalMethod: p.Method, AgentSessionID: d.ID}, decl)
	if err != nil {
		return generated.HostActionSubmission{}, err
	}
	_, err = c.Credentials.StageStepBindings(ctx, store.CredentialBindingStageRequest{DeclarationID: d.ID, DeclarationRevision: 1, Bindings: bindings, Expected: store.RevisionToken{StateRevision: revised.Document.StateRevision, RecoveryEpoch: r.RecoveryEpoch}, Attribution: a, KeyDigest: hostaction.Digest([]string{d.ID, "credentials"}), RequestDigest: manifest})
	if err != nil {
		return generated.HostActionSubmission{}, err
	}
	return generated.HostActionSubmission{Schema: generated.SchemaIDHostActionSubmission, SchemaVersion: "1.0.0", DraftID: d.ID, DeclarationID: d.ID, ContentDigest: d.Digest, StateRevision: revised.Document.StateRevision + 1, RecoveryEpoch: r.RecoveryEpoch}, nil
}
