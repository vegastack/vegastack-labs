//go:build linux

package qualification

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func refusalEnvelope(t *testing.T, status, command, code string) []byte {
	t.Helper()
	raw, err := json.Marshal(generated.RunResult{Schema: generated.SchemaIDRunResult, SchemaVersion: generated.RegistrySchemaVersion, ToolVersion: "test", Command: command, RequestID: "request-test", Status: status, ReleaseBuildID: "test", Errors: []generated.ResultError{{Code: code, Target: "private-target-never-exported", Retryable: false}}, Data: json.RawMessage("{}")})
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRunResult, raw, generated.ContractCompatibleRead) != nil {
		t.Fatal("invalid envelope fixture", err)
	}
	return append(raw, '\n')
}

func TestNativeConsoleRefusalStopsBeforeInteractiveEOF(t *testing.T) {
	for _, status := range []string{"failed", "blocked", "interrupted"} {
		t.Run(status, func(t *testing.T) {
			in := generated.NativeStepRequest{ScenarioID: "control-setup", Ordinal: 1, ScopeDigest: "scope-bound", Nonce: "nonce-bound"}
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			done := make(chan error, 1)
			go func() { _, err := readConsoleStep(in, reader); done <- err }()
			if _, err := writer.Write(refusalEnvelope(t, status, generated.CommandNameQualificationStep, generated.ErrorCodePrerequisiteBlocked)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, ErrUnavailable) {
					t.Fatal("refusal became a successful native result", err)
				}
			case <-time.After(time.Second):
				reader.Close()
				<-done
				t.Fatal("valid refusal waited for interactive console EOF/deadline")
			}
		})
	}
}

func TestNativeConsoleRefusalRejectsUnrelatedFrames(t *testing.T) {
	for name, raw := range map[string][]byte{
		"wrong-command": refusalEnvelope(t, "failed", generated.CommandNameServerStatus, generated.ErrorCodeIntegrityFailure),
		"unknown-code":  refusalEnvelope(t, "failed", generated.CommandNameQualificationStep, "UNKNOWN_SYNTHETIC_CODE"),
		"unknown-major": bytes.ReplaceAll(refusalEnvelope(t, "failed", generated.CommandNameQualificationStep, generated.ErrorCodeIntegrityFailure), []byte(`"schemaVersion":"`+generated.RegistrySchemaVersion+`"`), []byte(`"schemaVersion":"2.0.0"`)),
		"malformed":     []byte("{\"command\":\"qualification step\",\"status\":\"failed\"}\n"),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := readConsoleStep(generated.NativeStepRequest{ScenarioID: "control-setup", Ordinal: 1}, strings.NewReader(string(raw)))
			if err == nil || out.Status == "completed" {
				t.Fatal("unrelated frame became a result or trusted diagnostic")
			}
		})
	}
}

func TestNativeConsoleAcceptsCurrentCLIVersionAndExactBoundResult(t *testing.T) {
	scope := scopeFixture()
	in := generated.NativeStepRequest{Schema: generated.SchemaIDNativeStepRequest, SchemaVersion: "1.0.0", ScopeDigest: hostaction.Digest(scope), GuestID: scope.Guests[0].GuestID, ScenarioID: "control-setup", Ordinal: 1, ControllerInstanceID: scope.ControllerInstanceID, RecoveryEpoch: 0, Nonce: hostaction.Digest("synthetic-step-nonce"), Deadline: scope.ExpiresAt, Operation: "prepare"}
	expected := generated.NativeStepResult{Schema: generated.SchemaIDNativeStepResult, SchemaVersion: "1.0.0", Binding: in, Status: "completed", ObservationDigests: []string{}, ReceiptDigests: []string{}, ProducerRunIDs: []string{}}
	result, err := json.Marshal(expected)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativeStepResult, result, generated.ContractExact) != nil {
		t.Fatal("invalid bound result fixture", err)
	}
	var envelope generated.RunResult
	if json.Unmarshal(refusalEnvelope(t, "succeeded", generated.CommandNameQualificationStep, generated.ErrorCodeIntegrityFailure), &envelope) != nil {
		t.Fatal("fixture decode")
	}
	envelope.Errors = []generated.ResultError{}
	envelope.Data = result
	raw, _ := json.Marshal(envelope)
	out, err := readConsoleStep(in, strings.NewReader(string(raw)+"\n"))
	if err != nil || hostaction.Digest(out) != hostaction.Digest(expected) {
		t.Fatal("current CLI success envelope rejected", err)
	}
	expected.Binding.Nonce = hostaction.Digest("different-step-nonce")
	envelope.Data, _ = json.Marshal(expected)
	raw, _ = json.Marshal(envelope)
	if _, err = readConsoleStep(in, strings.NewReader(string(raw)+"\n")); err == nil {
		t.Fatal("foreign bound result accepted")
	}
	expected.Binding = in
	expected.SchemaVersion = "1.1.0"
	envelope.Data, _ = json.Marshal(expected)
	raw, _ = json.Marshal(envelope)
	if _, err = readConsoleStep(in, strings.NewReader(string(raw)+"\n")); err == nil {
		t.Fatal("non-exact native result accepted")
	}
}
