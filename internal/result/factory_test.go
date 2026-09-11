package result

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestFactoryBuildsOneGeneratedEnvelope(t *testing.T) {
	revision := "revision-test"
	factory := NewFactory(BuildInfo{ToolVersion: "0.2.0-test", ReleaseBuildID: "build-test", SourceRevision: &revision}, func() (string, error) {
		return "request-test", nil
	})
	result, err := factory.Success(generated.CommandNameServerStatus, 7, 42, generated.ServerStatusData{State: "ready", ReadAvailable: true, RecoveryEpoch: 7, StateRevision: 42, RemoteReadState: "disabled", RemoteReadReason: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Schema != generated.SchemaIDRunResult || result.SchemaVersion != generated.RegistrySchemaVersion || result.RequestID != "request-test" || result.RecoveryEpoch != 7 || result.StateRevision != 42 || len(result.Errors) != 0 {
		t.Fatalf("Success() = %#v", result)
	}
	var output bytes.Buffer
	if err := Encode(&output, result); err != nil {
		t.Fatal(err)
	}
	if bytes.Count(output.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("Encode() = %q", output.String())
	}
	var decoded generated.RunResult
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil || decoded.RequestID != result.RequestID {
		t.Fatalf("decoded = %#v, %v", decoded, err)
	}
}

func TestFactoryFailsClosedOnRequestIDOrUnknownError(t *testing.T) {
	factory := NewFactory(BuildInfo{}, func() (string, error) { return "", errors.New("private-canary") })
	if _, err := factory.Success("server status", 0, 0, struct{}{}); err == nil || err.Error() != "INTEGRITY_FAILURE: request-id" {
		t.Fatalf("Success() error = %v", err)
	}
	factory = NewFactory(BuildInfo{}, func() (string, error) { return "request-test", nil })
	if _, err := factory.Failure("server status", generated.RunStatusFailed, "PRIVATE_CODE", "target", false, 0, 0, struct{}{}); err == nil {
		t.Fatal("Failure() accepted an unregistered code")
	}
}
