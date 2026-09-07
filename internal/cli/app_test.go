package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

var testSourceRevision = "revision-test"

func TestEveryGeneratedCommandHasTruthfulRuntimeBehavior(t *testing.T) {
	t.Parallel()

	for _, command := range generated.Commands {
		command := command
		t.Run(strings.Join(command.Path, "_"), func(t *testing.T) {
			t.Parallel()
			code, stdout, stderr := runTestApp(t, context.Background(), command.Path, nil)
			if command.Availability == "planned" {
				if code != 6 || stdout != "" || stderr != "vsk-labs: PREREQUISITE_BLOCKED (command)\n" {
					t.Fatalf("planned command %v: code=%d stdout=%q stderr=%q", command.Path, code, stdout, stderr)
				}
				return
			}
			if code != 0 || stderr != "" || stdout == "" {
				t.Fatalf("available command %v: code=%d stdout=%q stderr=%q", command.Path, code, stdout, stderr)
			}
		})
	}
}

func TestHumanOutputMatchesGoldens(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "help-human.golden", args: []string{"help"}},
		{name: "version-human.golden", args: []string{"version"}},
	} {
		code, stdout, stderr := runTestApp(t, context.Background(), test.args, nil)
		if code != 0 || stderr != "" {
			t.Fatalf("%s: code=%d stderr=%q", test.name, code, stderr)
		}
		want, err := os.ReadFile(filepath.Join("testdata", test.name))
		if err != nil {
			t.Fatal(err)
		}
		if stdout != string(want) {
			t.Fatalf("%s mismatch\n--- got ---\n%s--- want ---\n%s", test.name, stdout, want)
		}
	}
}

func TestHelpJSONUsesGeneratedCommands(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runTestApp(t, context.Background(), []string{"help", "--output", "json"}, nil)
	result := decodeResult(t, code, stdout, stderr, 0)
	var data struct {
		Commands []generated.Command `json:"commands"`
	}
	if err := json.Unmarshal(result.Data, &data); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data.Commands, generated.Commands) {
		t.Fatal("help JSON did not use the generated command registry")
	}
	if !strings.Contains(stdout, `"errors":[]`) {
		t.Fatalf("successful errors must encode as []: %s", stdout)
	}
}

func TestVersionJSONHasEmptyDataObject(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runTestApp(t, context.Background(), []string{"version", "--output", "json", "--schema-version", "1"}, nil)
	result := decodeResult(t, code, stdout, stderr, 0)
	if string(result.Data) != "{}" || result.SchemaVersion != generated.RegistrySchemaVersion {
		t.Fatalf("version data=%s schemaVersion=%q", result.Data, result.SchemaVersion)
	}
}

func TestJSONFailureIsOneEnvelopeAndDoesNotEchoInput(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runTestApp(t, context.Background(), []string{"help", "--output", "json", "--unknown=private-canary"}, nil)
	if code != 2 || stderr != "" || bytes.Count([]byte(stdout), []byte("\n")) != 1 || strings.Contains(stdout, "private-canary") {
		t.Fatalf("unsafe JSON failure: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	assertResultError(t, decodeResult(t, code, stdout, stderr, 2), generated.ErrorCodeInputInvalid, "failed")
}

func TestUnsupportedSchemaMajor(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runTestApp(t, context.Background(), []string{"version", "--output", "json", "--schema-version", "2"}, nil)
	assertResultError(t, decodeResult(t, code, stdout, stderr, 2), generated.ErrorCodeSchemaUnsupported, "failed")
}

func TestMalformedInputFailsWithoutEcho(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		nil,
		{"unknown-private-canary"},
		{"help", "extra-private-canary"},
		{"help", "--output"},
		{"help", "--output", "json", "--output", "human"},
		{"help", "--schema-version"},
	} {
		code, stdout, stderr := runTestApp(t, context.Background(), args, nil)
		if code != 2 || strings.Contains(stdout+stderr, "private-canary") {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

func TestCancelledContextFailsBeforeDispatch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, stdout, stderr := runTestApp(t, ctx, []string{"help", "--output", "json"}, nil)
	assertResultError(t, decodeResult(t, code, stdout, stderr, 9), generated.ErrorCodeInterrupted, "cancelled")
}

func TestRequestIDFailureIsSanitized(t *testing.T) {
	t.Parallel()

	requestIDs := func() (string, error) { return "", errors.New("private-request-id-canary") }
	code, stdout, stderr := runTestApp(t, context.Background(), []string{"help", "--output", "json"}, requestIDs)
	result := decodeResult(t, code, stdout, stderr, 8)
	assertResultError(t, result, generated.ErrorCodeIntegrityFailure, "failed")
	if result.RequestID != "request-id-unavailable" || strings.Contains(stdout+stderr, "private-request-id-canary") {
		t.Fatalf("unsafe request ID failure: %#v stdout=%q stderr=%q", result, stdout, stderr)
	}
}

func runTestApp(t *testing.T, ctx context.Context, args []string, requestIDs RequestIDSource) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if requestIDs == nil {
		requestIDs = func() (string, error) { return "request-test-1", nil }
	}
	app := New(&stdout, &stderr, BuildInfo{
		ToolVersion:    "0.0.0-test",
		ReleaseBuildID: "build-test",
		SourceRevision: &testSourceRevision,
	}, requestIDs)
	code := app.Run(ctx, append([]string(nil), args...))
	return code, stdout.String(), stderr.String()
}

func decodeResult(t *testing.T, code int, stdout, stderr string, wantCode int) generated.RunResult {
	t.Helper()
	if code != wantCode || stderr != "" || bytes.Count([]byte(stdout), []byte("\n")) != 1 {
		t.Fatalf("code=%d stdout=%q stderr=%q, want code=%d and one JSON line", code, stdout, stderr, wantCode)
	}
	var result generated.RunResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("invalid result JSON: %v", err)
	}
	if result.Schema != "vegastack-labs.dev/run-result" || result.Changed || result.RecoveryEpoch != 0 || result.StateRevision != 0 || result.RunID != nil || result.SnapshotDigest != nil || result.PlanID != nil {
		t.Fatalf("invalid Phase 1 envelope: %#v", result)
	}
	return result
}

func assertResultError(t *testing.T, result generated.RunResult, code, status string) {
	t.Helper()
	if result.Status != status || len(result.Errors) != 1 || result.Errors[0].Code != code {
		t.Fatalf("result=%#v, want status=%q error=%q", result, status, code)
	}
}
