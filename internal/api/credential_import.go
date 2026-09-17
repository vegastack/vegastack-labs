package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type CredentialImportService interface {
	Preflight(context.Context, generated.CredentialImportRequest, identity.Principal) (*generated.CredentialImportSubmission, error)
	Import(context.Context, generated.CredentialImportRequest, []byte, identity.Principal) (generated.CredentialImportSubmission, error)
}

type CredentialImportOperations struct {
	Imports CredentialImportService
	Results *result.Factory
}

func RegisterCredentialImportOperation(app *Application, config CredentialImportOperations) error {
	if app == nil || config.Imports == nil || config.Results == nil || config.Results != app.config.Results {
		return apiFailure(generated.ErrorCodeInputInvalid, "credential-import-config")
	}
	app.routes = append(app.routes, route{id: "api.v1.credential-references.import-stream", method: http.MethodPost, pattern: "/api/v1/credential-references/{referenceId}/import-stream", capability: "credential.import.author", kind: "credential-reference", action: authorization.ActionAuthor, handler: app.importCredential(config)})
	if !routesAreGeneratedSubset(app.routes) {
		app.routes = app.routes[:len(app.routes)-1]
		return apiFailure(generated.ErrorCodeIntegrityFailure, "endpoint-registry")
	}
	return nil
}

func (app *Application) importCredential(config CredentialImportOperations) func(http.ResponseWriter, *http.Request, authorization.ReadScope, map[string]string) {
	return func(w http.ResponseWriter, r *http.Request, _ authorization.ReadScope, params map[string]string) {
		const op = "api.v1.credential-references.import-stream"
		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok || principal.Method != identity.LocalOSPeerMethod {
			app.failure(w, op, apiFailure(generated.ErrorCodeAuthorizationDenied, "credential-local-only"))
			return
		}
		if r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/octet-stream" || len(r.Header.Values("X-Vsk-Credential-Request")) != 1 || len(r.Header.Get("X-Vsk-Credential-Request")) > 5464 {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "credential-import-header"))
			return
		}
		metadata, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Vsk-Credential-Request"))
		if err != nil || len(metadata) == 0 || len(metadata) > 4096 {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "credential-import-metadata"))
			return
		}
		var input generated.CredentialImportRequest
		if generated.ValidateContractJSON(generated.SchemaIDCredentialImportRequest, metadata, generated.ContractExact) != nil || json.Unmarshal(metadata, &input) != nil || input.ReferenceID != params["referenceId"] || input.ResolverID != "native-systemd" {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "credential-import-request"))
			return
		}
		if _, err := credentialref.ParseID(input.ReferenceID); err != nil || input.TargetDigest == "" || input.TargetDigest != credentialref.ImportTargetDigest(input) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "credential-import-target"))
			return
		}
		if r.Body == nil || (r.ContentLength >= 0 && (r.ContentLength < 8 || r.ContentLength > 4096)) {
			app.failure(w, op, apiFailure(generated.ErrorCodeInputInvalid, "credential-import-size"))
			return
		}
		existing, err := config.Imports.Preflight(r.Context(), input, principal)
		if err != nil {
			app.failure(w, op, err)
			return
		}
		requestID, err := config.Results.RequestID()
		if err != nil {
			app.failure(w, op, err)
			return
		}
		if existing != nil {
			if !validCredentialImportSubmission(*existing, input) {
				app.operationFailure(w, op, requestID, apiFailure(generated.ErrorCodeIntegrityFailure, "credential-import-submission"))
				return
			}
			app.operationSuccess(w, op, requestID, false, existing.StateRevision, existing.RecoveryEpoch, *existing)
			return
		}
		private, err := io.ReadAll(io.LimitReader(r.Body, 4097))
		defer zeroCredentialImportBody(private)
		if err != nil || len(private) < 8 || len(private) > 4096 {
			app.operationFailure(w, op, requestID, apiFailure(generated.ErrorCodeInputInvalid, "credential-import-size"))
			return
		}
		value, err := config.Imports.Import(r.Context(), input, private, principal)
		if err != nil {
			app.operationFailure(w, op, requestID, err)
			return
		}
		if !validCredentialImportSubmission(value, input) {
			app.operationFailure(w, op, requestID, apiFailure(generated.ErrorCodeIntegrityFailure, "credential-import-submission"))
			return
		}
		app.operationSuccess(w, op, requestID, true, value.StateRevision, value.RecoveryEpoch, value)
	}
}

func validCredentialImportSubmission(value generated.CredentialImportSubmission, input generated.CredentialImportRequest) bool {
	raw, err := json.Marshal(value)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDCredentialImportSubmission, raw, generated.ContractExact) == nil && value.ReferenceID == input.ReferenceID && value.RecoveryEpoch == input.RecoveryEpoch && value.StateRevision >= input.ExpectedStateRevision && value.Status == "draft"
}

func zeroCredentialImportBody(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
