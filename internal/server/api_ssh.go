package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"time"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/apissh"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

const apiSSHCommand = "api-ssh"

type apiSSHForward func(context.Context, localtransport.Request) (localtransport.Response, error)

type apiSSHHandler struct {
	build               result.BuildInfo
	profile             serverconfig.Profile
	peerUID             uint32
	verifiedPrincipalID string
	verifiedDeviceID    string
	forward             apiSSHForward
}

// ServeAPISSH serves one versioned frame for an SSH forced command. The fixed
// principal and device arguments belong to server-side SSH configuration; the
// request merely declares the values that must match them.
func (operations *Operations) ServeAPISSH(ctx context.Context, configPath, verifiedPrincipalID, verifiedDeviceID string, input io.Reader, output io.Writer) error {
	if operations == nil || ctx == nil || input == nil || output == nil || !principal.ValidID(verifiedPrincipalID) || !principal.ValidID(verifiedDeviceID) {
		return failure.New(generated.ErrorCodeInputInvalid, "api-ssh-binding", false)
	}
	uid, err := currentServiceOwnerUID()
	if err != nil {
		return failure.New(generated.ErrorCodeUnsupportedPlatform, "server-platform", false)
	}
	profile, err := serverconfig.NewLoader(uid).Load(ctx, configPath)
	if err != nil {
		return err
	}
	handler := apiSSHHandler{
		build: operations.build, profile: profile, peerUID: uid,
		verifiedPrincipalID: verifiedPrincipalID, verifiedDeviceID: verifiedDeviceID,
		forward: localtransport.RoundTrip,
	}
	return handler.Serve(ctx, input, output)
}

func (handler apiSSHHandler) Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	request, err := apissh.ReadRequest(input)
	if err != nil {
		return err
	}
	operationID, allowed := api.ConstrainedSSHOperation(request.Method, request.Path)
	if !allowed {
		return handler.writeFailure(output, request.Header.RequestID, operationID, generated.ErrorCodeInputInvalid, "api-ssh-operation", 0, 0)
	}
	if request.Header.SSHPrincipalID != handler.verifiedPrincipalID || request.Header.DeviceID != handler.verifiedDeviceID || !handler.bindingMatches() {
		return handler.writeFailure(output, request.Header.RequestID, operationID, generated.ErrorCodeAuthorizationDenied, "api-ssh-binding", 0, 0)
	}
	health, err := handler.forward(ctx, localtransport.Request{
		SocketPath: handler.profile.SocketPath, Method: localtransport.MethodGet, Path: "/api/v1/health",
		Timeout: 3 * time.Second, ResponseLimit: 64 * 1024,
	})
	if err != nil {
		return handler.writeFailure(output, request.Header.RequestID, operationID, generated.ErrorCodeDependencyUnavailable, "control-service", 0, 0)
	}
	healthEnvelope, err := decodeAPIEnvelope(health, generated.CommandNameServerStatus)
	if err != nil || len(healthEnvelope.Errors) != 0 {
		return handler.writeFailure(output, request.Header.RequestID, operationID, generated.ErrorCodeIntegrityFailure, "control-service-response", 0, 0)
	}
	if request.Header.RecoveryEpoch != healthEnvelope.RecoveryEpoch {
		return handler.writeFailure(output, request.Header.RequestID, operationID, generated.ErrorCodeRecoveryEpochMismatch, "recovery-epoch", healthEnvelope.RecoveryEpoch, healthEnvelope.StateRevision)
	}
	response, err := handler.forward(ctx, localtransport.Request{
		SocketPath: handler.profile.SocketPath, Method: request.Method, Path: request.Path, Body: request.Payload,
		Timeout: 30 * time.Second, ResponseLimit: 24 << 20,
	})
	if err != nil {
		return handler.writeFailure(output, request.Header.RequestID, operationID, generated.ErrorCodeDependencyUnavailable, "control-service", healthEnvelope.RecoveryEpoch, healthEnvelope.StateRevision)
	}
	envelope, err := decodeAPIEnvelope(response, operationID)
	if err != nil {
		return handler.writeFailure(output, request.Header.RequestID, operationID, generated.ErrorCodeIntegrityFailure, "control-service-response", healthEnvelope.RecoveryEpoch, healthEnvelope.StateRevision)
	}
	envelope.RequestID = request.Header.RequestID
	return apissh.WriteResponse(output, request.Header.RequestID, envelope)
}

func (handler apiSSHHandler) bindingMatches() bool {
	for _, binding := range handler.profile.PrincipalBindings {
		if binding.UID == handler.peerUID && binding.PrincipalID == handler.verifiedPrincipalID {
			return true
		}
	}
	return false
}

func (handler apiSSHHandler) writeFailure(output io.Writer, requestID, operationID, code, target string, epoch, revision int64) error {
	if operationID == "" {
		operationID = apiSSHCommand
	}
	factory := result.NewFactory(handler.build, nil)
	envelope, err := factory.FailureWithRequestID(operationID, requestID, generated.RunStatusFailed, code, target, false, epoch, revision, struct{}{})
	if err != nil {
		return err
	}
	return apissh.WriteResponse(output, requestID, envelope)
}

func decodeAPIEnvelope(response localtransport.Response, expectedCommand string) (generated.RunResult, error) {
	mediaType, _, err := mime.ParseMediaType(response.ContentType)
	if err != nil || mediaType != "application/json" || len(response.Body) < 2 || response.Body[len(response.Body)-1] != '\n' {
		return generated.RunResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "control-service-response", false)
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Body))
	decoder.DisallowUnknownFields()
	var envelope generated.RunResult
	if decoder.Decode(&envelope) != nil || envelope.Schema != generated.SchemaIDRunResult || envelope.SchemaVersion != generated.RegistrySchemaVersion || envelope.Command != expectedCommand || envelope.RequestID == "" {
		return generated.RunResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "control-service-response", false)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || generated.ValidateContractJSON(generated.SchemaIDRunResult, bytes.TrimSuffix(response.Body, []byte{'\n'}), generated.ContractExact) != nil {
		return generated.RunResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "control-service-response", false)
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(response.Body, append(canonical, '\n')) {
		return generated.RunResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "control-service-response", false)
	}
	return envelope, nil
}
