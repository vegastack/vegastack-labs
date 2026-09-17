package localapi

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"runtime"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

// ImportCredential is deliberately separate from JSON requestTyped. Private
// bytes travel only over the local Unix socket, never SSH or a browser route.
func (client *client) ImportCredential(ctx context.Context, profile serverconfig.Profile, input generated.CredentialImportRequest, source io.Reader) (TypedResponse[generated.CredentialImportSubmission], error) {
	var zero TypedResponse[generated.CredentialImportSubmission]
	if profile.ConstrainedSSH != nil {
		return zero, failure.New(generated.ErrorCodeAuthorizationDenied, "credential-import-local-only", false)
	}
	if client == nil || client.results == nil || ctx == nil || source == nil || profile.SocketPath == "" || runtime.GOOS == "windows" || !validPathToken(input.ReferenceID) {
		return zero, failure.New(generated.ErrorCodePrerequisiteBlocked, "credential-import", false)
	}
	metadata, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDCredentialImportRequest, metadata, generated.ContractExact) != nil || input.ResolverID != "native-systemd" || input.TargetDigest != credentialref.ImportTargetDigest(input) || len(metadata) > 4096 {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "credential-import-metadata", false)
	}
	private, err := io.ReadAll(io.LimitReader(source, 4097))
	defer zeroCredentialImportBytes(private)
	if err != nil || len(private) < 8 || len(private) > 4096 {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "credential-import-stream", false)
	}
	spec := requestSpec{localtransport.MethodPost, "/api/v1/credential-references/" + input.ReferenceID + "/import-stream", "api.v1.credential-references.import-stream", maxOperationResponseBodyBytes, operationTimeout, true}
	response, err := localtransport.RoundTrip(ctx, localtransport.Request{SocketPath: profile.SocketPath, Method: spec.method, Path: spec.path, Body: private, BinaryCredential: true, CredentialMetadata: metadata, Timeout: spec.timeout, ResponseLimit: spec.responseLimit})
	if err != nil {
		if ctx.Err() != nil {
			return zero, failure.New(generated.ErrorCodeInterrupted, "credential-import", false)
		}
		return zero, failure.New(generated.ErrorCodeDependencyUnavailable, "credential-import", true)
	}
	mediaType, _, err := mime.ParseMediaType(response.ContentType)
	if err != nil || mediaType != "application/json" {
		return zero, responseFailure()
	}
	return validateTypedResponse(response.Body, response.StatusCode, spec, func(data generated.CredentialImportSubmission, envelope generated.RunResult) bool {
		encoded, encodeErr := json.Marshal(data)
		return encodeErr == nil && generated.ValidateContractJSON(generated.SchemaIDCredentialImportSubmission, encoded, generated.ContractExact) == nil && data.ReferenceID == input.ReferenceID && data.Status == "draft" && data.StateRevision == envelope.StateRevision && data.RecoveryEpoch == envelope.RecoveryEpoch
	})
}

func zeroCredentialImportBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
