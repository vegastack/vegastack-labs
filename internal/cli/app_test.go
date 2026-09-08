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

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/release"
)

var testSourceRevision = "revision-test"

func TestEveryGeneratedCommandHasTruthfulRuntimeBehavior(t *testing.T) {
	t.Parallel()
	for _, command := range generated.Commands {
		command := command
		t.Run(strings.Join(command.Path, "_"), func(t *testing.T) {
			t.Parallel()
			operations := &stubReleaseOperations{
				inspectData: generated.ReleaseInspectData{ReleaseID: "v1.2.3", VerificationStatus: "not-verified"},
				verifyData: generated.ReleaseVerifyData{
					ReleaseID: "v1.2.3", VerificationStatus: "verified-against-supplied-policy",
					PolicySHA256: "sha256:" + strings.Repeat("a", 64),
				},
			}
			arguments := command.Path
			if command.Availability == generated.AvailabilityAvailable && len(command.Examples) != 0 {
				arguments = command.Examples[0].Arguments
			}
			serverOperations := &stubServerOperations{status: successfulServerResponse(t)}
			code, stdout, stderr := runTestAppWithOptions(t, context.Background(), arguments, nil, WithReleaseOperations(operations), WithServerOperations(serverOperations))
			if command.Availability == generated.AvailabilityPlanned {
				if code != 6 || stdout != "" || stderr != "vsk-labs: PREREQUISITE_BLOCKED (command)\n" {
					t.Fatalf("planned command %v: code=%d stdout=%q stderr=%q", command.Path, code, stdout, stderr)
				}
				return
			}
			if code != 0 || stderr != "" || (stdout == "" && commandName(command.Path) != generated.CommandNameServerRun) {
				t.Fatalf("available command %v: code=%d stdout=%q stderr=%q", command.Path, code, stdout, stderr)
			}
		})
	}
}

type stubServerOperations struct {
	status       localapi.Response
	err          error
	runConfig    string
	statusConfig string
}

func (stub *stubServerOperations) Run(_ context.Context, config string) error {
	stub.runConfig = config
	return stub.err
}

func (stub *stubServerOperations) Status(_ context.Context, config string) (localapi.Response, error) {
	stub.statusConfig = config
	return stub.status, stub.err
}

func successfulServerResponse(t *testing.T) localapi.Response {
	t.Helper()
	status := generated.ServerStatusData{State: "ready", ReadAvailable: true, RecoveryEpoch: 7, StateRevision: 42}
	result := generated.RunResult{
		Schema: generated.SchemaIDRunResult, SchemaVersion: generated.RegistrySchemaVersion,
		ToolVersion: "0.2.0-test", Command: generated.CommandNameServerStatus, RequestID: "request-server-1",
		Status: generated.RunStatusSucceeded, Changed: false, RecoveryEpoch: 7, StateRevision: 42,
		ReleaseBuildID: "build-server", Errors: []generated.ResultError{}, Data: mustJSON(t, status),
	}
	raw := append(mustJSON(t, result), '\n')
	return localapi.Response{Raw: raw, Result: result, Status: status, ExitCode: 0}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestServerStatusPreservesRemoteEnvelope(t *testing.T) {
	remote := successfulServerResponse(t)
	operations := &stubServerOperations{status: remote}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{
		"server", "status", "--config", "profile.json", "--output", "json",
	}, nil, WithServerOperations(operations))
	if code != 0 || stdout != string(remote.Raw) || stderr != "" || operations.statusConfig != "profile.json" {
		t.Fatalf("status = code %d stdout %q stderr %q", code, stdout, stderr)
	}
}

func TestServerStatusPreservesRemoteErrorEnvelope(t *testing.T) {
	remote := successfulServerResponse(t)
	remote.Result.Status = generated.RunStatusFailed
	remote.Result.Errors = []generated.ResultError{{Code: generated.ErrorCodeIntegrityFailure, Target: "application-health", Retryable: false}}
	remote.ExitCode = 8
	remote.Raw = append(mustJSON(t, remote.Result), '\n')
	operations := &stubServerOperations{status: remote}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{
		"server", "status", "--config", "profile.json", "--output", "json",
	}, nil, WithServerOperations(operations))
	if code != 8 || stdout != string(remote.Raw) || stderr != "" {
		t.Fatalf("status = code %d stdout %q stderr %q", code, stdout, stderr)
	}
}

func TestServerRunRoutesAndUnavailableStatusCreatesTypedEnvelope(t *testing.T) {
	operations := &stubServerOperations{}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{"server", "run", "--config", "profile.json"}, nil, WithServerOperations(operations))
	if code != 0 || stdout != "" || stderr != "" || operations.runConfig != "profile.json" {
		t.Fatalf("run = %d %q %q config=%q", code, stdout, stderr, operations.runConfig)
	}
	operations.err = failure.New(generated.ErrorCodeDependencyUnavailable, "control-service", true)
	code, stdout, stderr = runTestAppWithOptions(t, context.Background(), []string{"server", "status", "--config", "profile.json", "--output", "json"}, nil, WithServerOperations(operations))
	result := decodeResult(t, code, stdout, stderr, 6)
	var status generated.ServerStatusData
	if err := json.Unmarshal(result.Data, &status); err != nil || status.State != "unavailable" || status.ReadAvailable || status.MutationAvailable {
		t.Fatalf("unavailable = %#v, %v", status, err)
	}
}

func TestServerStatusHumanOutputIsSanitized(t *testing.T) {
	operations := &stubServerOperations{status: successfulServerResponse(t)}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{"server", "status", "--config", "private-canary.json"}, nil, WithServerOperations(operations))
	want, err := os.ReadFile(filepath.Join("testdata", "server-status-human.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || stderr != "" || strings.Contains(stdout, "private-canary") || stdout != string(want) {
		t.Fatalf("human status = %d %q %q", code, stdout, stderr)
	}
}

func TestReleaseVerifyRequiresExplicitSelection(t *testing.T) {
	t.Parallel()

	operations := &stubReleaseOperations{err: &release.Error{Code: generated.ErrorCodeInputInvalid, Target: "selection"}}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{
		"release", "verify", "--manifest", "private-canary.json", "--policy", "policy.json", "--output", "json",
	}, nil, WithReleaseOperations(operations))
	result := decodeResult(t, code, stdout, stderr, 2)
	assertResultError(t, result, generated.ErrorCodeInputInvalid, generated.RunStatusFailed)
	if strings.Contains(stdout+stderr, "private-canary") {
		t.Fatal("hostile path was echoed")
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

func TestReleaseHumanOutputMatchesGoldens(t *testing.T) {
	t.Parallel()

	operations := &stubReleaseOperations{
		inspectData: generated.ReleaseInspectData{
			ReleaseID: "v1.2.3", BuildID: "build-123", SourceRevision: strings.Repeat("a", 40),
			PlatformOS: "linux", PlatformArchitecture: "amd64", PlatformSchemaMajor: 1,
			CompatibleAssetIDs: []string{"linux-amd64"}, VerificationStatus: "not-verified",
		},
		verifyData: generated.ReleaseVerifyData{
			ReleaseID: "v1.2.3", BuildID: "build-123", SourceRevision: strings.Repeat("a", 40),
			ManifestStatus: "verified", VerificationStatus: "verified-against-supplied-policy",
			PolicySHA256: "sha256:" + strings.Repeat("b", 64), Assets: []generated.ReleaseAssetVerification{{
				AssetID: "linux-amd64", OS: "linux", Architecture: "amd64",
				Digest: "sha256:" + strings.Repeat("c", 64), Size: 1234, Status: "verified",
			}},
		},
	}
	tests := []struct {
		name string
		args []string
	}{
		{name: "release-inspect-human.golden", args: []string{"release", "inspect", "--manifest", "manifest.json"}},
		{name: "release-verify-human.golden", args: []string{"release", "verify", "--manifest", "manifest.json", "--policy", "policy.json", "--all"}},
	}
	for _, test := range tests {
		code, stdout, stderr := runTestAppWithOptions(t, context.Background(), test.args, nil, WithReleaseOperations(operations))
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
	assertResultError(t, decodeResult(t, code, stdout, stderr, 2), generated.ErrorCodeInputInvalid, generated.RunStatusFailed)
}

func TestUnsupportedSchemaMajor(t *testing.T) {
	t.Parallel()

	code, stdout, stderr := runTestApp(t, context.Background(), []string{"version", "--output", "json", "--schema-version", "2"}, nil)
	assertResultError(t, decodeResult(t, code, stdout, stderr, 2), generated.ErrorCodeSchemaUnsupported, generated.RunStatusFailed)
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
	assertResultError(t, decodeResult(t, code, stdout, stderr, 9), generated.ErrorCodeInterrupted, generated.RunStatusCancelled)
}

type stubReleaseOperations struct {
	inspectData generated.ReleaseInspectData
	verifyData  generated.ReleaseVerifyData
	err         error
	inspect     release.InspectRequest
	verify      release.VerifyRequest
}

func (stub *stubReleaseOperations) Inspect(_ context.Context, request release.InspectRequest) (generated.ReleaseInspectData, error) {
	stub.inspect = request
	return stub.inspectData, stub.err
}

func (stub *stubReleaseOperations) Verify(_ context.Context, request release.VerifyRequest) (generated.ReleaseVerifyData, error) {
	stub.verify = request
	return stub.verifyData, stub.err
}

func TestReleaseCommandsRouteThroughInjectedOperations(t *testing.T) {
	t.Parallel()

	operations := &stubReleaseOperations{
		inspectData: generated.ReleaseInspectData{ReleaseID: "v1.2.3", VerificationStatus: "not-verified"},
		verifyData: generated.ReleaseVerifyData{
			ReleaseID: "v1.2.3", ManifestStatus: "verified",
			VerificationStatus: "verified-against-supplied-policy", PolicySHA256: "sha256:" + strings.Repeat("a", 64),
		},
	}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{
		"release", "inspect", "--manifest", "manifest.json", "--output", "json",
	}, nil, WithReleaseOperations(operations))
	result := decodeResult(t, code, stdout, stderr, 0)
	var inspect generated.ReleaseInspectData
	if err := json.Unmarshal(result.Data, &inspect); err != nil || inspect.VerificationStatus != "not-verified" || operations.inspect.ManifestPath != "manifest.json" {
		t.Fatalf("inspect route = %#v request=%#v err=%v", inspect, operations.inspect, err)
	}

	code, stdout, stderr = runTestAppWithOptions(t, context.Background(), []string{
		"release", "verify", "--manifest", "manifest.json", "--policy", "policy.json", "--asset", "linux-amd64", "--output", "json",
	}, nil, WithReleaseOperations(operations))
	result = decodeResult(t, code, stdout, stderr, 0)
	var verified generated.ReleaseVerifyData
	if err := json.Unmarshal(result.Data, &verified); err != nil || verified.VerificationStatus != "verified-against-supplied-policy" {
		t.Fatalf("verify route = %#v err=%v", verified, err)
	}
	if operations.verify.ManifestPath != "manifest.json" || operations.verify.PolicyPath != "policy.json" || !reflect.DeepEqual(operations.verify.Selection.AssetIDs, []string{"linux-amd64"}) {
		t.Fatalf("verify request = %#v", operations.verify)
	}
}

func TestReleaseDomainErrorsAreMappedWithoutRawInput(t *testing.T) {
	t.Parallel()

	operations := &stubReleaseOperations{err: &release.Error{Code: generated.ErrorCodeEvidenceInvalid, Target: "manifest-signature"}}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{
		"release", "verify", "--manifest", "private-canary.json", "--policy", "policy.json", "--all", "--output", "json",
	}, nil, WithReleaseOperations(operations))
	result := decodeResult(t, code, stdout, stderr, 2)
	assertResultError(t, result, generated.ErrorCodeEvidenceInvalid, generated.RunStatusFailed)
	if strings.Contains(stdout+stderr, "private-canary") {
		t.Fatalf("release failure leaked input: %s%s", stdout, stderr)
	}
}

func TestReleaseDomainErrorBoundaryRejectsUnknownCodeAndTarget(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		&release.Error{Code: "PRIVATE_CODE", Target: "manifest-signature"},
		&release.Error{Code: generated.ErrorCodeEvidenceInvalid, Target: "private-target-canary"},
	} {
		operations := &stubReleaseOperations{err: err}
		code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{
			"release", "verify", "--manifest", "manifest.json", "--policy", "policy.json", "--all", "--output", "json",
		}, nil, WithReleaseOperations(operations))
		result := decodeResult(t, code, stdout, stderr, 8)
		assertResultError(t, result, generated.ErrorCodeIntegrityFailure, generated.RunStatusFailed)
		if strings.Contains(stdout+stderr, "PRIVATE_CODE") || strings.Contains(stdout+stderr, "private-target-canary") {
			t.Fatalf("unsafe release error escaped: %s%s", stdout, stderr)
		}
	}
}

func TestRequestIDFailureIsSanitized(t *testing.T) {
	t.Parallel()

	requestIDs := func() (string, error) { return "", errors.New("private-request-id-canary") }
	code, stdout, stderr := runTestApp(t, context.Background(), []string{"help", "--output", "json"}, requestIDs)
	result := decodeResult(t, code, stdout, stderr, 8)
	assertResultError(t, result, generated.ErrorCodeIntegrityFailure, generated.RunStatusFailed)
	if result.RequestID != "request-id-unavailable" || strings.Contains(stdout+stderr, "private-request-id-canary") {
		t.Fatalf("unsafe request ID failure: %#v stdout=%q stderr=%q", result, stdout, stderr)
	}
}

func runTestApp(t *testing.T, ctx context.Context, args []string, requestIDs RequestIDSource) (int, string, string) {
	return runTestAppWithOptions(t, ctx, args, requestIDs)
}

func runTestAppWithOptions(t *testing.T, ctx context.Context, args []string, requestIDs RequestIDSource, options ...Option) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if requestIDs == nil {
		requestIDs = func() (string, error) { return "request-test-1", nil }
	}
	app := New(&stdout, &stderr, BuildInfo{
		ToolVersion:    "0.0.0-test",
		ReleaseBuildID: "build-test",
		SourceRevision: &testSourceRevision,
	}, requestIDs, options...)
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
	if result.Schema != generated.SchemaIDRunResult || result.Changed || result.RecoveryEpoch != 0 || result.StateRevision != 0 || result.RunID != nil || result.SnapshotDigest != nil || result.PlanID != nil {
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
