package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/apissh"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

const (
	apiSSHRequestID   = "request-api-ssh-test"
	apiSSHPrincipalID = "principal.api-ssh-test"
	apiSSHDeviceID    = "device.api-ssh-test"
)

type apiSSHRecorder struct {
	requests  []localtransport.Request
	responses []localtransport.Response
	errors    []error
}

func (recorder *apiSSHRecorder) forward(_ context.Context, request localtransport.Request) (localtransport.Response, error) {
	recorder.requests = append(recorder.requests, request)
	index := len(recorder.requests) - 1
	if index < len(recorder.errors) && recorder.errors[index] != nil {
		return localtransport.Response{}, recorder.errors[index]
	}
	if index >= len(recorder.responses) {
		return localtransport.Response{}, errors.New("unexpected forward")
	}
	return recorder.responses[index], nil
}

func TestAPISSHForwardsOneAdmittedOperationWithExactBindingAndCommand(t *testing.T) {
	recorder := &apiSSHRecorder{responses: []localtransport.Response{
		apiSSHLocalResponse(t, apiSSHEnvelope("server status", "local-health", 4, 9)),
		apiSSHLocalResponse(t, apiSSHEnvelope("server status", "local-operation", 4, 9)),
	}}
	handler := newAPISSHTestHandler(recorder)
	payload := []byte{}
	wire := apiSSHRequestWire(t, "GET /api/v1/health", []string{"server", "status"}, 4, payload)
	var output bytes.Buffer
	if err := handler.Serve(context.Background(), bytes.NewReader(wire), &output); err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	response, err := apissh.ReadResponse(&output, apiSSHRequestID)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	if response.Envelope.Command != "server status" || response.Envelope.RequestID != apiSSHRequestID || len(response.Envelope.Errors) != 0 {
		t.Fatalf("response envelope = %#v", response.Envelope)
	}
	if len(recorder.requests) != 2 {
		t.Fatalf("forward count = %d, want health plus one operation", len(recorder.requests))
	}
	if got := recorder.requests[0]; got.Method != localtransport.MethodGet || got.Path != "/api/v1/health" || len(got.Body) != 0 || got.SocketPath != "/run/vsk-labs/control.sock" {
		t.Fatalf("health forward = %#v", got)
	}
	if got := recorder.requests[1]; got.Method != localtransport.MethodGet || got.Path != "/api/v1/health" || !bytes.Equal(got.Body, payload) || got.SocketPath != "/run/vsk-labs/control.sock" {
		t.Fatalf("operation forward = %#v", got)
	}
}

func TestAPISSHForwardsExactVerifiedPayloadOnce(t *testing.T) {
	payload := []byte(`{"schema":"vegastack-labs.dev/plan-reference-request","schemaVersion":"1.0.0","planId":"plan-test"}`)
	recorder := &apiSSHRecorder{responses: []localtransport.Response{
		apiSSHLocalResponse(t, apiSSHEnvelope("server status", "local-health", 4, 9)),
		apiSSHLocalResponse(t, apiSSHEnvelope("api.v1.plans.execute", "local-operation", 4, 10)),
	}}
	handler := newAPISSHTestHandler(recorder)
	var output bytes.Buffer
	if err := handler.Serve(context.Background(), bytes.NewReader(apiSSHRequestWire(t, "POST /api/v1/plans/plan-test/execute", []string{"apply"}, 4, payload)), &output); err != nil {
		t.Fatal(err)
	}
	response, err := apissh.ReadResponse(&output, apiSSHRequestID)
	if err != nil || response.Envelope.Command != "apply" || response.Envelope.RequestID != apiSSHRequestID || len(response.Envelope.Errors) != 0 {
		t.Fatalf("response=%#v err=%v", response, err)
	}
	if len(recorder.requests) != 2 {
		t.Fatalf("forward count = %d", len(recorder.requests))
	}
	operation := recorder.requests[1]
	if operation.Method != localtransport.MethodPost || operation.Path != "/api/v1/plans/plan-test/execute" || !bytes.Equal(operation.Body, payload) {
		t.Fatalf("operation forward = %#v", operation)
	}
}

func TestAPISSHRejectsUnboundIdentityAndStaleEpochWithoutOperationForward(t *testing.T) {
	for name, test := range map[string]struct {
		mutate       func(*apiSSHHandler, *generated.ApiSshRequestFrameHeader)
		responses    []localtransport.Response
		wantCode     string
		wantForwards int
	}{
		"principal": {
			mutate: func(_ *apiSSHHandler, header *generated.ApiSshRequestFrameHeader) {
				header.SSHPrincipalID = "principal.other"
			},
			wantCode: generated.ErrorCodeAuthorizationDenied,
		},
		"device": {
			mutate:   func(_ *apiSSHHandler, header *generated.ApiSshRequestFrameHeader) { header.DeviceID = "device.other" },
			wantCode: generated.ErrorCodeAuthorizationDenied,
		},
		"forced principal": {
			mutate: func(handler *apiSSHHandler, _ *generated.ApiSshRequestFrameHeader) {
				handler.verifiedPrincipalID = "principal.other"
			},
			wantCode: generated.ErrorCodeAuthorizationDenied,
		},
		"forced device": {
			mutate: func(handler *apiSSHHandler, _ *generated.ApiSshRequestFrameHeader) {
				handler.verifiedDeviceID = "device.other"
			},
			wantCode: generated.ErrorCodeAuthorizationDenied,
		},
		"profile binding": {
			mutate: func(handler *apiSSHHandler, _ *generated.ApiSshRequestFrameHeader) {
				handler.profile.PrincipalBindings = nil
			},
			wantCode: generated.ErrorCodeAuthorizationDenied,
		},
		"recovery epoch": {
			mutate:    func(_ *apiSSHHandler, header *generated.ApiSshRequestFrameHeader) { header.RecoveryEpoch = 3 },
			responses: []localtransport.Response{apiSSHLocalResponse(t, apiSSHEnvelope("server status", "local-health", 4, 9))},
			wantCode:  generated.ErrorCodeRecoveryEpochMismatch, wantForwards: 1,
		},
		"epoch changed during operation": {
			mutate: func(_ *apiSSHHandler, _ *generated.ApiSshRequestFrameHeader) {},
			responses: []localtransport.Response{
				apiSSHLocalResponse(t, apiSSHEnvelope("server status", "local-health", 4, 9)),
				apiSSHLocalResponse(t, apiSSHEnvelope("server status", "local-operation", 5, 10)),
			},
			wantCode: generated.ErrorCodeRecoveryEpochMismatch, wantForwards: 2,
		},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := &apiSSHRecorder{responses: test.responses}
			handler := newAPISSHTestHandler(recorder)
			header := apiSSHRequestHeader(t, "GET /api/v1/health", []string{"server", "status"}, 4, nil)
			test.mutate(&handler, &header)
			var input, output bytes.Buffer
			writeAPISSHRequest(t, &input, header, nil)
			if err := handler.Serve(context.Background(), &input, &output); err != nil {
				t.Fatalf("Serve() error = %v", err)
			}
			response, err := apissh.ReadResponse(&output, apiSSHRequestID)
			if err != nil {
				t.Fatal(err)
			}
			if len(response.Envelope.Errors) != 1 || response.Envelope.Errors[0].Code != test.wantCode || response.Envelope.RequestID != apiSSHRequestID || len(recorder.requests) != test.wantForwards {
				t.Fatalf("response=%#v forwards=%d", response.Envelope, len(recorder.requests))
			}
		})
	}
}

func TestAPISSHGeneratedRouteRequiresExactTokenizedCommandArguments(t *testing.T) {
	for name, test := range map[string]struct {
		operation string
		arguments []string
	}{
		"unknown route":           {"GET /api/v1/not-a-route", []string{"server", "status"}},
		"disallowed operator op":  {"POST /api/v1/plans/plan-test/acknowledgements", []string{"apply"}},
		"endpoint id":             {"GET /api/v1/health", []string{"api.v1.health.get"}},
		"wrong generated command": {"GET /api/v1/health", []string{"status"}},
		"extra token":             {"GET /api/v1/health", []string{"server", "status", "extra"}},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := &apiSSHRecorder{}
			handler := newAPISSHTestHandler(recorder)
			wire := apiSSHRequestWire(t, test.operation, test.arguments, 4, nil)
			var output bytes.Buffer
			if err := handler.Serve(context.Background(), bytes.NewReader(wire), &output); err != nil {
				t.Fatalf("Serve() error = %v", err)
			}
			response, err := apissh.ReadResponse(&output, apiSSHRequestID)
			if err != nil {
				t.Fatal(err)
			}
			if len(response.Envelope.Errors) != 1 || response.Envelope.Errors[0].Code != generated.ErrorCodeInputInvalid || response.Envelope.RequestID != apiSSHRequestID || len(recorder.requests) != 0 {
				t.Fatalf("response=%#v forwards=%d", response.Envelope, len(recorder.requests))
			}
		})
	}
}

func TestAPISSHDenialAuditEnvelopeIsSanitizedAndNeverForwardsDeniedOperation(t *testing.T) {
	recorder := &apiSSHRecorder{}
	handler := newAPISSHTestHandler(recorder)
	privateOperation := "GET /api/v1/private-target-canary"
	var output bytes.Buffer
	if err := handler.Serve(context.Background(), bytes.NewReader(apiSSHRequestWire(t, privateOperation, []string{"server", "status"}, 4, nil)), &output); err != nil {
		t.Fatal(err)
	}
	response, err := apissh.ReadResponse(bytes.NewReader(output.Bytes()), apiSSHRequestID)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Envelope.Errors) != 1 || response.Envelope.Errors[0].Code != generated.ErrorCodeInputInvalid || response.Envelope.Errors[0].Target != "api-ssh-operation" || response.Envelope.RequestID != apiSSHRequestID {
		t.Fatalf("denial envelope = %#v", response.Envelope)
	}
	serialized := output.String()
	if strings.Contains(serialized, privateOperation) || strings.Contains(serialized, apiSSHPrincipalID) || strings.Contains(serialized, apiSSHDeviceID) || len(recorder.requests) != 0 {
		t.Fatalf("unsafe denial output or forward: output=%q forwards=%d", serialized, len(recorder.requests))
	}
}

func TestAPISSHRejectsPayloadLengthAndDigestBeforeForward(t *testing.T) {
	valid := apiSSHRequestHeader(t, "POST /api/v1/plans/plan-test/execute", []string{"apply"}, 4, []byte(`{}`))
	for name, test := range map[string]struct {
		edit    func(*generated.ApiSshRequestFrameHeader)
		payload []byte
		code    string
	}{
		"declared length": {func(header *generated.ApiSshRequestFrameHeader) { header.DeclaredPayloadBytes++ }, []byte(`{}`), generated.ErrorCodeInputInvalid},
		"actual length":   {func(header *generated.ApiSshRequestFrameHeader) { header.ActualPayloadBytes++ }, []byte(`{}`), generated.ErrorCodeInputInvalid},
		"digest": {func(header *generated.ApiSshRequestFrameHeader) {
			header.PayloadDigest = "sha256:" + string(bytes.Repeat([]byte{'0'}, 64))
		}, []byte(`{}`), generated.ErrorCodeIntegrityFailure},
	} {
		t.Run(name, func(t *testing.T) {
			header := valid
			test.edit(&header)
			recorder := &apiSSHRecorder{}
			handler := newAPISSHTestHandler(recorder)
			err := handler.Serve(context.Background(), bytes.NewReader(apiSSHRawFrame(t, header, test.payload)), io.Discard)
			if apissh.ErrorCode(err) != test.code || len(recorder.requests) != 0 {
				t.Fatalf("error=%v forwards=%d", err, len(recorder.requests))
			}
		})
	}
}

func TestAPISSHRejectsNoncanonicalControlResponseAndCorrelatesAcceptedResponse(t *testing.T) {
	valid := apiSSHEnvelope("server status", "local-operation", 4, 9)
	validRaw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	validRaw = append(validRaw, '\n')
	for name, response := range map[string]localtransport.Response{
		"content type":     {StatusCode: 200, ContentType: "text/plain", Body: validRaw},
		"http status":      {StatusCode: 503, ContentType: "application/json", Body: validRaw},
		"missing newline":  {StatusCode: 200, ContentType: "application/json", Body: bytes.TrimSuffix(validRaw, []byte{'\n'})},
		"noncanonical":     {StatusCode: 200, ContentType: "application/json", Body: append([]byte{' '}, validRaw...)},
		"unknown field":    {StatusCode: 200, ContentType: "application/json", Body: append(bytes.TrimSuffix(validRaw, []byte{'\n'}), []byte(",\"unknown\":true}\n")...)},
		"empty request id": apiSSHLocalResponse(t, apiSSHEnvelope("server status", "", 4, 9)),
		"wrong command":    apiSSHLocalResponse(t, apiSSHEnvelope("status", "local-operation", 4, 9)),
		"wrong schema": func() localtransport.Response {
			envelope := valid
			envelope.Schema = "vegastack-labs.dev/other"
			return apiSSHLocalResponse(t, envelope)
		}(),
		"wrong version": func() localtransport.Response {
			envelope := valid
			envelope.SchemaVersion = "1.13.0"
			return apiSSHLocalResponse(t, envelope)
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			recorder := &apiSSHRecorder{responses: []localtransport.Response{
				apiSSHLocalResponse(t, apiSSHEnvelope("server status", "local-health", 4, 9)), response,
			}}
			handler := newAPISSHTestHandler(recorder)
			var output bytes.Buffer
			if err := handler.Serve(context.Background(), bytes.NewReader(apiSSHRequestWire(t, "GET /api/v1/health", []string{"server", "status"}, 4, nil)), &output); err != nil {
				t.Fatal(err)
			}
			decoded, err := apissh.ReadResponse(&output, apiSSHRequestID)
			if err != nil || len(decoded.Envelope.Errors) != 1 || decoded.Envelope.Errors[0].Code != generated.ErrorCodeIntegrityFailure {
				t.Fatalf("decoded=%#v err=%v", decoded, err)
			}
		})
	}
}

func newAPISSHTestHandler(recorder *apiSSHRecorder) apiSSHHandler {
	return apiSSHHandler{
		build:   result.BuildInfo{ToolVersion: "vsk-labs-test", ReleaseBuildID: "release-test"},
		profile: serverconfig.Profile{SocketPath: "/run/vsk-labs/control.sock", PrincipalBindings: []principal.Binding{{UID: 1000, PrincipalID: apiSSHPrincipalID}}},
		peerUID: 1000, verifiedPrincipalID: apiSSHPrincipalID, verifiedDeviceID: apiSSHDeviceID, forward: recorder.forward,
	}
}

func apiSSHRequestWire(t *testing.T, operation string, arguments []string, epoch int64, payload []byte) []byte {
	t.Helper()
	header := apiSSHRequestHeader(t, operation, arguments, epoch, payload)
	var wire bytes.Buffer
	writeAPISSHRequest(t, &wire, header, payload)
	return wire.Bytes()
}

func apiSSHRequestHeader(t *testing.T, operation string, arguments []string, epoch int64, payload []byte) generated.ApiSshRequestFrameHeader {
	t.Helper()
	header, err := apissh.NewRequestHeader(apiSSHRequestID, apiSSHPrincipalID, apiSSHDeviceID, operation, arguments, epoch, payload)
	if err != nil {
		t.Fatal(err)
	}
	return header
}

func writeAPISSHRequest(t *testing.T, output io.Writer, header generated.ApiSshRequestFrameHeader, payload []byte) {
	t.Helper()
	if err := apissh.WriteRequest(output, header, payload); err != nil {
		t.Fatal(err)
	}
}

func apiSSHRawFrame(t *testing.T, header generated.ApiSshRequestFrameHeader, payload []byte) []byte {
	t.Helper()
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	return append(append(raw, '\n'), payload...)
}

func apiSSHEnvelope(command, requestID string, epoch, revision int64) generated.RunResult {
	return generated.RunResult{
		Schema: generated.SchemaIDRunResult, SchemaVersion: generated.RegistrySchemaVersion,
		ToolVersion: "vsk-labs-test", Command: command, RequestID: requestID,
		Status: generated.RunStatusSucceeded, Changed: false, RecoveryEpoch: epoch, StateRevision: revision,
		ReleaseBuildID: "release-test", Errors: []generated.ResultError{}, Data: json.RawMessage(`{}`),
	}
}

func apiSSHLocalResponse(t *testing.T, envelope generated.RunResult) localtransport.Response {
	t.Helper()
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return localtransport.Response{StatusCode: 200, ContentType: "application/json", Body: append(raw, '\n')}
}

func TestAPISSHGeneratedCommandPathsRemainStable(t *testing.T) {
	want := map[string][]string{
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
	for operation, command := range want {
		got, ok := apiSSHCommandArguments(operation)
		if !ok || !reflect.DeepEqual(got, command) {
			t.Fatalf("%s command = %#v, %t", operation, got, ok)
		}
	}
	if _, ok := apiSSHCommandArguments("api.v1.events.stream"); ok {
		t.Fatal("stream route gained a framed command")
	}
}
