package apissh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type phase03Fixture struct {
	Cases []struct {
		ID    string `json:"id"`
		Input struct {
			Protocol             string                              `json:"protocol"`
			Version              string                              `json:"version"`
			RequestID            string                              `json:"requestId"`
			SSHPrincipalID       string                              `json:"sshPrincipalId"`
			DeviceID             string                              `json:"deviceId"`
			Operation            string                              `json:"operation"`
			Arguments            []string                            `json:"arguments"`
			PayloadDigest        string                              `json:"payloadDigest"`
			DeclaredPayloadBytes int64                               `json:"declaredPayloadBytes"`
			ActualPayloadBytes   int64                               `json:"actualPayloadBytes"`
			RecoveryEpoch        int64                               `json:"recoveryEpoch"`
			ResponseFrame        generated.ApiSshResponseFrameHeader `json:"responseFrame"`
		} `json:"input"`
		Expected struct {
			Status    string  `json:"status"`
			ErrorCode *string `json:"errorCode"`
		} `json:"expected"`
	} `json:"cases"`
}

func TestRequestRoundTripValidatesStreamingLengthAndDigest(t *testing.T) {
	payload := []byte(`{"schema":"vegastack-labs.dev/plan-reference-request"}`)
	header, err := NewRequestHeader("request-ssh-test-001", "ssh-principal-test", "device-test", "POST /api/v1/plans/plan-test/execute", []string{"--plan-id", "plan-test", "--output", "json"}, 3, payload)
	if err != nil {
		t.Fatalf("NewRequestHeader() error = %v", err)
	}
	var wire bytes.Buffer
	if err := WriteRequest(&wire, header, payload); err != nil {
		t.Fatalf("WriteRequest() error = %v", err)
	}
	decoded, err := ReadRequest(bytes.NewReader(wire.Bytes()))
	if err != nil {
		t.Fatalf("ReadRequest() error = %v", err)
	}
	if decoded.Method != "POST" || decoded.Path != "/api/v1/plans/plan-test/execute" || !bytes.Equal(decoded.Payload, payload) || decoded.ActualPayloadBytes != int64(len(payload)) || !reflect.DeepEqual(decoded.Header, header) {
		t.Fatalf("decoded request = %#v", decoded)
	}
}

func TestRequestRejectsMalformedFraming(t *testing.T) {
	payload := []byte("payload")
	valid, err := NewRequestHeader("request-ssh-test-002", "ssh-principal-test", "device-test", "GET /api/v1/summary", []string{"--output", "json"}, 3, payload)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*generated.ApiSshRequestFrameHeader)
		body []byte
		code string
	}{
		{name: "declared length", edit: func(h *generated.ApiSshRequestFrameHeader) { h.DeclaredPayloadBytes++ }, body: payload, code: generated.ErrorCodeInputInvalid},
		{name: "claimed actual length", edit: func(h *generated.ApiSshRequestFrameHeader) { h.ActualPayloadBytes++ }, body: payload, code: generated.ErrorCodeInputInvalid},
		{name: "digest", edit: func(h *generated.ApiSshRequestFrameHeader) {
			h.PayloadDigest = "sha256:" + string(bytes.Repeat([]byte("0"), 64))
		}, body: payload, code: generated.ErrorCodeIntegrityFailure},
		{name: "version", edit: func(h *generated.ApiSshRequestFrameHeader) { h.Version = "2.0.0" }, body: payload, code: generated.ErrorCodeSchemaUnsupported},
		{name: "protocol", edit: func(h *generated.ApiSshRequestFrameHeader) { h.Protocol = "other" }, body: payload, code: generated.ErrorCodeSchemaUnsupported},
		{name: "shell operation", edit: func(h *generated.ApiSshRequestFrameHeader) { h.Operation = "shell" }, body: payload, code: generated.ErrorCodeInputInvalid},
		{name: "file operation", edit: func(h *generated.ApiSshRequestFrameHeader) { h.Operation = "read-file" }, body: payload, code: generated.ErrorCodeInputInvalid},
		{name: "sqlite operation", edit: func(h *generated.ApiSshRequestFrameHeader) { h.Operation = "sqlite-query" }, body: payload, code: generated.ErrorCodeAuthorizationDenied},
		{name: "shell argument", edit: func(h *generated.ApiSshRequestFrameHeader) { h.Arguments = []string{"status; uname"} }, body: payload, code: generated.ErrorCodeInputInvalid},
		{name: "path argument", edit: func(h *generated.ApiSshRequestFrameHeader) { h.Arguments = []string{"server-state/control.db"} }, body: payload, code: generated.ErrorCodeInputInvalid},
		{name: "short body", edit: func(*generated.ApiSshRequestFrameHeader) {}, body: payload[:3], code: generated.ErrorCodeInputInvalid},
		{name: "long body", edit: func(*generated.ApiSshRequestFrameHeader) {}, body: append(append([]byte(nil), payload...), 'x'), code: generated.ErrorCodeInputInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := valid
			header.Arguments = append([]string(nil), valid.Arguments...)
			test.edit(&header)
			_, err := ReadRequest(bytes.NewReader(rawFrame(t, header, test.body)))
			if got := ErrorCode(err); got != test.code {
				t.Fatalf("ErrorCode(ReadRequest()) = %q, want %q (err %v)", got, test.code, err)
			}
		})
	}
}

func TestResponseRoundTripRequiresCanonicalCorrelatedEnvelope(t *testing.T) {
	envelope := testEnvelope("request-ssh-test-003")
	var wire bytes.Buffer
	if err := WriteResponse(&wire, envelope.RequestID, envelope); err != nil {
		t.Fatalf("WriteResponse() error = %v", err)
	}
	decoded, err := ReadResponse(bytes.NewReader(wire.Bytes()), envelope.RequestID)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	wantEnvelope, _ := json.Marshal(envelope)
	wantEnvelope = append(wantEnvelope, '\n')
	if !reflect.DeepEqual(decoded.Envelope, envelope) || !bytes.Equal(decoded.RawEnvelope, wantEnvelope) || decoded.ActualPayloadBytes != int64(len(wantEnvelope)) {
		t.Fatalf("decoded response = %#v", decoded)
	}
}

func TestResponseRejectsLengthVersionAndCorrelation(t *testing.T) {
	envelope := testEnvelope("request-ssh-test-004")
	payload, _ := json.Marshal(envelope)
	payload = append(payload, '\n')
	valid := generated.ApiSshResponseFrameHeader{Protocol: Protocol, Version: Version, RequestID: envelope.RequestID, DeclaredPayloadBytes: int64(len(payload)), ActualPayloadBytes: int64(len(payload))}
	tests := []struct {
		name              string
		editHeader        func(*generated.ApiSshResponseFrameHeader)
		editPayload       func([]byte) []byte
		expectedRequestID string
		code              string
	}{
		{name: "declared length", editHeader: func(h *generated.ApiSshResponseFrameHeader) { h.DeclaredPayloadBytes++ }, code: generated.ErrorCodeInputInvalid},
		{name: "actual length", editHeader: func(h *generated.ApiSshResponseFrameHeader) { h.ActualPayloadBytes++ }, code: generated.ErrorCodeInputInvalid},
		{name: "version", editHeader: func(h *generated.ApiSshResponseFrameHeader) { h.Version = "2.0.0" }, code: generated.ErrorCodeSchemaUnsupported},
		{name: "frame correlation", editHeader: func(h *generated.ApiSshResponseFrameHeader) { h.RequestID = "request-ssh-other" }, expectedRequestID: envelope.RequestID, code: generated.ErrorCodeStateConflict},
		{name: "envelope correlation", editPayload: func([]byte) []byte {
			value := testEnvelope("request-ssh-other")
			changed, _ := json.Marshal(value)
			return append(changed, '\n')
		}, code: generated.ErrorCodeStateConflict},
		{name: "noncanonical envelope", editPayload: func(raw []byte) []byte { return append([]byte(" "), raw...) }, code: generated.ErrorCodeInputInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := valid
			body := append([]byte(nil), payload...)
			if test.editHeader != nil {
				test.editHeader(&header)
			}
			if test.editPayload != nil {
				body = test.editPayload(body)
				header.DeclaredPayloadBytes, header.ActualPayloadBytes = int64(len(body)), int64(len(body))
			}
			expected := test.expectedRequestID
			if expected == "" {
				expected = envelope.RequestID
			}
			_, err := ReadResponse(bytes.NewReader(rawFrame(t, header, body)), expected)
			if got := ErrorCode(err); got != test.code {
				t.Fatalf("ErrorCode(ReadResponse()) = %q, want %q (err %v)", got, test.code, err)
			}
		})
	}
}

func TestPhase03ConstrainedSSHCaseOwnership(t *testing.T) {
	fixture := loadPhase03Fixture(t)
	codecRequestCodes := map[string]string{
		"shell-text-denied":          generated.ErrorCodeInputInvalid,
		"path-denied":                generated.ErrorCodeInputInvalid,
		"direct-sqlite-denied":       generated.ErrorCodeAuthorizationDenied,
		"malformed-length-denied":    generated.ErrorCodeInputInvalid,
		"unsupported-version-denied": generated.ErrorCodeSchemaUnsupported,
	}
	codecResponseCodes := map[string]string{
		"response-length-denied":      generated.ErrorCodeInputInvalid,
		"response-version-denied":     generated.ErrorCodeSchemaUnsupported,
		"response-correlation-denied": generated.ErrorCodeStateConflict,
	}
	handlerOwned := map[string]bool{
		"unknown-operation-denied":        true,
		"client-asserted-identity-denied": true,
		"principal-device-mismatch":       true,
		"recovery-epoch-mismatch":         true,
	}
	accepted := map[string]bool{
		"read-request-accepted":           true,
		"plan-request-accepted":           true,
		"approved-apply-request-accepted": true,
		"disconnect-queries-durable-run":  true,
	}
	seen := make([]string, 0, len(fixture.Cases))
	for _, testCase := range fixture.Cases {
		seen = append(seen, testCase.ID)
		payload := bytes.Repeat([]byte{'p'}, int(testCase.Input.ActualPayloadBytes))
		header := generated.ApiSshRequestFrameHeader{
			Protocol: testCase.Input.Protocol, Version: testCase.Input.Version, RequestID: testCase.Input.RequestID,
			SSHPrincipalID: testCase.Input.SSHPrincipalID, DeviceID: testCase.Input.DeviceID, Operation: testCase.Input.Operation,
			Arguments: append([]string{}, testCase.Input.Arguments...), PayloadDigest: digest(payload),
			DeclaredPayloadBytes: testCase.Input.DeclaredPayloadBytes, ActualPayloadBytes: testCase.Input.ActualPayloadBytes, RecoveryEpoch: testCase.Input.RecoveryEpoch,
		}
		request, err := ReadRequest(bytes.NewReader(rawFrame(t, header, payload)))
		if code, ok := codecRequestCodes[testCase.ID]; ok {
			if got := ErrorCode(err); got != code {
				t.Fatalf("%s request code = %q, want %q (err %v)", testCase.ID, got, code, err)
			}
			continue
		}
		if accepted[testCase.ID] || handlerOwned[testCase.ID] || codecResponseCodes[testCase.ID] != "" {
			if err != nil {
				t.Fatalf("%s structural request error = %v", testCase.ID, err)
			}
			if request.Header.RequestID != testCase.Input.RequestID {
				t.Fatalf("%s request ID lost", testCase.ID)
			}
		}
		if code, ok := codecResponseCodes[testCase.ID]; ok {
			envelopeRequestID := testCase.Input.RequestID
			if testCase.ID == "response-correlation-denied" {
				envelopeRequestID = testCase.Input.ResponseFrame.RequestID
			}
			envelope := testEnvelope(envelopeRequestID)
			body, _ := json.Marshal(envelope)
			body = append(body, '\n')
			responseHeader := generated.ApiSshResponseFrameHeader{Protocol: testCase.Input.ResponseFrame.Protocol, Version: testCase.Input.ResponseFrame.Version, RequestID: testCase.Input.ResponseFrame.RequestID, DeclaredPayloadBytes: int64(len(body)), ActualPayloadBytes: int64(len(body))}
			if testCase.ID == "response-length-denied" {
				responseHeader.DeclaredPayloadBytes++
			}
			_, responseErr := ReadResponse(bytes.NewReader(rawFrame(t, responseHeader, body)), testCase.Input.RequestID)
			if got := ErrorCode(responseErr); got != code {
				t.Fatalf("%s response code = %q, want %q (err %v)", testCase.ID, got, code, responseErr)
			}
		}
	}
	want := []string{"approved-apply-request-accepted", "client-asserted-identity-denied", "direct-sqlite-denied", "disconnect-queries-durable-run", "malformed-length-denied", "path-denied", "plan-request-accepted", "principal-device-mismatch", "read-request-accepted", "recovery-epoch-mismatch", "response-correlation-denied", "response-length-denied", "response-version-denied", "shell-text-denied", "unknown-operation-denied", "unsupported-version-denied"}
	sort.Strings(seen)
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("fixture cases = %#v, want %#v", seen, want)
	}
}

func rawFrame(t *testing.T, header any, payload []byte) []byte {
	t.Helper()
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	return append(append(raw, '\n'), payload...)
}

func digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func testEnvelope(requestID string) generated.RunResult {
	return generated.RunResult{
		Schema: generated.SchemaIDRunResult, SchemaVersion: generated.RegistrySchemaVersion, ToolVersion: "vsk-labs-test", Command: "api-ssh", RequestID: requestID,
		Status: generated.RunStatusSucceeded, Changed: false, RecoveryEpoch: 3, StateRevision: 42, ReleaseBuildID: "release-test", Errors: []generated.ResultError{}, Data: json.RawMessage(`{}`),
	}
}

func loadPhase03Fixture(t *testing.T) phase03Fixture {
	t.Helper()
	path := filepath.Join("..", "..", "tooling", "testdata", "phase-0-3", "constrained-ssh.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture phase03Fixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
