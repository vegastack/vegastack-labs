package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"reflect"
	"strings"
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

const (
	apiSSHCommand     = generated.CommandNameServerStatus
	apiSSHReadTimeout = 30 * time.Second
)

type apiSSHForward func(context.Context, localtransport.Request) (localtransport.Response, error)

type apiSSHReadResult struct {
	request apissh.Request
	err     error
}

type apiSSHHandler struct {
	build               result.BuildInfo
	profile             serverconfig.Profile
	peerUID             uint32
	verifiedPrincipalID string
	verifiedDeviceID    string
	forward             apiSSHForward
	readTimeout         time.Duration
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
	request, err := handler.readRequest(ctx, input)
	if err != nil {
		requestID := apissh.RecoverableRequestID(err)
		if requestID != "" {
			code := apissh.ErrorCode(err)
			if code == "" {
				code = generated.ErrorCodeInputInvalid
			}
			return handler.writeFailure(output, requestID, apiSSHCommand, code, "api-ssh-request-frame", 0, 0)
		}
		return err
	}
	operationID, allowed := api.ConstrainedSSHOperation(request.Method, request.Path)
	if !allowed && request.Method == localtransport.MethodPost && request.Path == "/api/v1/plans" {
		operationID, allowed = "api.v1.plans.create", true
	}
	if !allowed {
		return handler.writeFailure(output, request.Header.RequestID, operationID, generated.ErrorCodeInputInvalid, "api-ssh-operation", 0, 0)
	}
	backendCommand := operationID
	if operationID == "api.v1.health.get" {
		backendCommand = generated.CommandNameServerStatus
	}
	forwardPath, allowed := apiSSHArgumentsAllowed(operationID, request.Path, request.Header.Arguments)
	if !allowed {
		return handler.writeFailure(output, request.Header.RequestID, backendCommand, generated.ErrorCodeInputInvalid, "api-ssh-arguments", 0, 0)
	}
	if request.Header.SSHPrincipalID != handler.verifiedPrincipalID || request.Header.DeviceID != handler.verifiedDeviceID || !handler.bindingMatches() {
		return handler.writeFailure(output, request.Header.RequestID, backendCommand, generated.ErrorCodeAuthorizationDenied, "api-ssh-binding", 0, 0)
	}
	if operationID == "api.v1.credential-lifecycle-drafts.create" {
		var metadata generated.CredentialLifecycleRequest
		if len(request.Payload) > 4096 || generated.ValidateContractJSON(generated.SchemaIDCredentialLifecycleRequest, request.Payload, generated.ContractExact) != nil || json.Unmarshal(request.Payload, &metadata) != nil || metadata.Action != "credential."+request.Header.Arguments[1] {
			return handler.writeFailure(output, request.Header.RequestID, backendCommand, generated.ErrorCodeInputInvalid, "api-ssh-lifecycle-metadata", 0, 0)
		}
	}
	health, err := handler.forward(ctx, localtransport.Request{
		SocketPath: handler.profile.SocketPath, Method: localtransport.MethodGet, Path: "/api/v1/health",
		Timeout: 3 * time.Second, ResponseLimit: 64 * 1024,
	})
	if err != nil {
		return handler.writeFailure(output, request.Header.RequestID, backendCommand, generated.ErrorCodeDependencyUnavailable, "control-service", 0, 0)
	}
	healthEnvelope, err := decodeAPIEnvelope(health, generated.CommandNameServerStatus)
	if err != nil || len(healthEnvelope.Errors) != 0 {
		return handler.writeFailure(output, request.Header.RequestID, backendCommand, generated.ErrorCodeIntegrityFailure, "control-service-response", 0, 0)
	}
	if request.Header.RecoveryEpoch != healthEnvelope.RecoveryEpoch {
		return handler.writeFailure(output, request.Header.RequestID, backendCommand, generated.ErrorCodeRecoveryEpochMismatch, "recovery-epoch", healthEnvelope.RecoveryEpoch, healthEnvelope.StateRevision)
	}
	response, err := handler.forward(ctx, localtransport.Request{
		SocketPath: handler.profile.SocketPath, Method: request.Method, Path: forwardPath, Body: request.Payload,
		Timeout: 30 * time.Second, ResponseLimit: 24 << 20,
	})
	if err != nil {
		return handler.writeFailure(output, request.Header.RequestID, backendCommand, generated.ErrorCodeDependencyUnavailable, "control-service", healthEnvelope.RecoveryEpoch, healthEnvelope.StateRevision)
	}
	envelope, err := decodeAPIEnvelope(response, backendCommand)
	if err != nil {
		return handler.writeFailure(output, request.Header.RequestID, backendCommand, generated.ErrorCodeIntegrityFailure, "control-service-response", healthEnvelope.RecoveryEpoch, healthEnvelope.StateRevision)
	}
	if envelope.RecoveryEpoch != healthEnvelope.RecoveryEpoch {
		return handler.writeFailure(output, request.Header.RequestID, backendCommand, generated.ErrorCodeRecoveryEpochMismatch, "recovery-epoch", envelope.RecoveryEpoch, envelope.StateRevision)
	}
	envelope.RequestID = request.Header.RequestID
	return apissh.WriteResponse(output, request.Header.RequestID, envelope)
}

func (handler apiSSHHandler) readRequest(ctx context.Context, input io.Reader) (apissh.Request, error) {
	timeout := handler.readTimeout
	if timeout <= 0 || timeout > apiSSHReadTimeout {
		timeout = apiSSHReadTimeout
	}
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := make(chan apiSSHReadResult, 1)
	go func() {
		request, err := apissh.ReadRequest(input)
		result <- apiSSHReadResult{request: request, err: err}
	}()
	select {
	case completed := <-result:
		return completed.request, completed.err
	case <-readCtx.Done():
		code := generated.ErrorCodeInputInvalid
		if ctx.Err() != nil {
			code = generated.ErrorCodeInterrupted
		}
		return apissh.Request{}, failure.New(code, "api-ssh-request-frame", false)
	}
}

func apiSSHArgumentsAllowed(operationID, requestPath string, arguments []string) (string, bool) {
	if operationID == "api.v1.credential-lifecycle-drafts.create" {
		if requestPath != "/api/v1/credential-lifecycle-drafts" || len(arguments) != 2 || arguments[0] != "credential" {
			return "", false
		}
		for _, action := range []string{"stage", "activate", "rotate", "revoke", "recover"} {
			if arguments[1] == action {
				for _, command := range generated.Commands {
					if command.Availability == generated.AvailabilityAvailable && reflect.DeepEqual(command.Path, arguments) {
						return requestPath, true
					}
				}
				return "", false
			}
		}
		return "", false
	}
	commandArguments, available := apiSSHCommandArguments(operationID)
	if !available {
		return "", false
	}
	switch operationID {
	case "api.v1.summary.get":
		return requestPath, reflect.DeepEqual(arguments, []string{"--output", "json"})
	case "api.v1.plans.create":
		if len(arguments) == 4 && arguments[0] == "--change" && principal.ValidID(arguments[1]) && arguments[2] == "--output" && arguments[3] == "json" {
			mappedPath := "/api/v1/declarations/" + arguments[1] + "/plans"
			if requestPath != "/api/v1/plans" && requestPath != mappedPath {
				return "", false
			}
			mappedOperation, mapped := api.ConstrainedSSHOperation(localtransport.MethodPost, mappedPath)
			if mapped && mappedOperation == operationID {
				return mappedPath, true
			}
		}
	case "api.v1.plans.execute":
		if id, ok := apiSSHPathID(requestPath, "/api/v1/plans/", "/execute"); ok && reflect.DeepEqual(arguments, []string{"--plan-id", id, "--output", "json"}) {
			return requestPath, true
		}
	case "api.v1.runs.get":
		if id, ok := apiSSHPathID(requestPath, "/api/v1/runs/", ""); ok && reflect.DeepEqual(arguments, []string{"--run-id", id, "--output", "json"}) {
			return requestPath, true
		}
	default:
		return requestPath, reflect.DeepEqual(arguments, commandArguments)
	}
	return "", false
}

func apiSSHPathID(path, prefix, suffix string) (string, bool) {
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	return id, principal.ValidID(id)
}

func apiSSHCommandArguments(operationID string) ([]string, bool) {
	commands := map[string][]string{
		"api.v1.health.get":                        {"server", "status"},
		"api.v1.summary.get":                       {"status"},
		"api.v1.database-status.get":               {"database", "status"},
		"api.v1.inventory-drafts.import":           {"inventory", "import"},
		"api.v1.inventory-diffs.create":            {"inventory", "diff"},
		"api.v1.inventory-exports.create":          {"inventory", "export"},
		"api.v1.declarations.plan-preparation.get": {"plan"},
		"api.v1.plans.create":                      {"plan"},
		"api.v1.plans.get":                         {"apply"},
		"api.v1.plans.execute":                     {"apply"},
		"api.v1.runs.get":                          {"run", "inspect"},
		"api.v1.runs.cancel":                       {"run", "cancel"},
		"api.v1.runs.resume":                       {"run", "resume"},
	}
	arguments, ok := commands[operationID]
	if !ok {
		return nil, false
	}
	for _, command := range generated.Commands {
		if command.Availability == generated.AvailabilityAvailable && reflect.DeepEqual(command.Path, arguments) {
			return append([]string(nil), arguments...), true
		}
	}
	return nil, false
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
	if decoder.Decode(&envelope) != nil || envelope.Schema != generated.SchemaIDRunResult || envelope.SchemaVersion != generated.RegistrySchemaVersion || envelope.Command != expectedCommand || envelope.RequestID == "" || envelope.ToolVersion == "" || envelope.ReleaseBuildID == "" || envelope.Data == nil {
		return generated.RunResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "control-service-response", false)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || !validAPIEnvelopeStatus(response.StatusCode, envelope) {
		return generated.RunResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "control-service-response", false)
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(response.Body, append(canonical, '\n')) {
		return generated.RunResult{}, failure.New(generated.ErrorCodeIntegrityFailure, "control-service-response", false)
	}
	return envelope, nil
}

func validAPIEnvelopeStatus(statusCode int, envelope generated.RunResult) bool {
	if len(envelope.Errors) == 0 {
		return statusCode == localtransport.StatusOK && envelope.Status == generated.RunStatusSucceeded
	}
	if envelope.Status != generated.RunStatusFailed && envelope.Status != generated.RunStatusInterrupted && envelope.Status != generated.RunStatusPartial && envelope.Status != generated.RunStatusCancelled {
		return false
	}
	for _, resultError := range envelope.Errors {
		if resultError.Target == "" {
			return false
		}
		if _, ok := generated.ErrorExitCodes[resultError.Code]; !ok {
			return false
		}
	}
	return statusCode == apiSSHStatusForCode(envelope.Errors[0].Code)
}

func apiSSHStatusForCode(code string) int {
	return map[string]int{
		generated.ErrorCodeAuthenticationRequired: localtransport.StatusUnauthorized,
		generated.ErrorCodeAuthorizationDenied:    localtransport.StatusForbidden,
		generated.ErrorCodeInputInvalid:           localtransport.StatusBadRequest,
		generated.ErrorCodeSchemaUnsupported:      localtransport.StatusBadRequest,
		generated.ErrorCodeStateConflict:          localtransport.StatusConflict,
		generated.ErrorCodeRecoveryEpochMismatch:  localtransport.StatusConflict,
		generated.ErrorCodeResourceNotFound:       localtransport.StatusNotFound,
		generated.ErrorCodePrerequisiteBlocked:    localtransport.StatusPreconditionFailed,
		generated.ErrorCodeInterrupted:            localtransport.StatusRequestTimeout,
		generated.ErrorCodeDependencyUnavailable:  localtransport.StatusServiceUnavailable,
		generated.ErrorCodeIntegrityFailure:       localtransport.StatusServiceUnavailable,
		generated.ErrorCodeApprovalRequired:       localtransport.StatusPreconditionFailed,
		generated.ErrorCodePlanStale:              localtransport.StatusConflict,
		generated.ErrorCodeExecutionFailed:        localtransport.StatusBadGateway,
		generated.ErrorCodeExecutionPartial:       localtransport.StatusConflict,
		generated.ErrorCodeRecoveryRequired:       localtransport.StatusConflict,
	}[code]
}
