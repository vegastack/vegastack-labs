package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type stubControlOperations struct {
	summaryResponse  localapi.TypedResponse[generated.ApiSummaryData]
	databaseResponse localapi.TypedResponse[generated.DatabaseStatusData]
	importResponse   localapi.TypedResponse[generated.InventoryImportData]
	diffResponse     localapi.TypedResponse[generated.InventoryDiffData]
	exportResponse   localapi.TypedResponse[generated.InventoryExportData]
	err              error
	calls            int
	config           string
	importRequest    generated.InventoryImportRequest
	diffRequest      generated.InventoryDiffRequest
	exportRequest    generated.InventoryExportRequest
}

func (stub *stubControlOperations) Summary(_ context.Context, config string) (localapi.TypedResponse[generated.ApiSummaryData], error) {
	stub.calls++
	stub.config = config
	return stub.summaryResponse, stub.err
}

func (stub *stubControlOperations) DatabaseStatus(_ context.Context, config string) (localapi.TypedResponse[generated.DatabaseStatusData], error) {
	stub.calls++
	stub.config = config
	return stub.databaseResponse, stub.err
}

func (stub *stubControlOperations) ImportInventory(_ context.Context, config string, request generated.InventoryImportRequest) (localapi.TypedResponse[generated.InventoryImportData], error) {
	stub.calls++
	stub.config, stub.importRequest = config, request
	return stub.importResponse, stub.err
}

func (stub *stubControlOperations) DiffInventory(_ context.Context, config string, request generated.InventoryDiffRequest) (localapi.TypedResponse[generated.InventoryDiffData], error) {
	stub.calls++
	stub.config, stub.diffRequest = config, request
	return stub.diffResponse, stub.err
}

func (stub *stubControlOperations) ExportInventory(_ context.Context, config string, request generated.InventoryExportRequest) (localapi.TypedResponse[generated.InventoryExportData], error) {
	stub.calls++
	stub.config, stub.exportRequest = config, request
	return stub.exportResponse, stub.err
}

type stubFileReader struct {
	content []byte
	err     error
	path    string
	limit   int64
	calls   int
}

func (stub *stubFileReader) Read(_ context.Context, path string, limit int64) ([]byte, error) {
	stub.calls++
	stub.path, stub.limit = path, limit
	return append([]byte(nil), stub.content...), stub.err
}

func successfulControlOperations(t *testing.T) *stubControlOperations {
	t.Helper()
	summary := generated.ApiSummaryData{DatabaseMode: "read-write", ReadAvailable: true, DraftCount: 2, ValidDraftCount: 1, BlockedDraftCount: 1, LastEventID: 9, StateRevision: 7, RecoveryEpoch: 2, SourceCounts: generated.ApiSourceCountsData{Total: 7, Healthy: 1, Stale: 1, Unknown: 1, Unavailable: 3, Failed: 1}, WorstSourceState: "failed"}
	database := generated.DatabaseStatusData{Mode: "read-write", SchemaVersion: 1, SQLiteVersion: "3.synthetic", IntegrityStatus: "ok"}
	imported := generated.InventoryImportData{DraftID: "draft-test", DraftRevision: 1, ValidationStatus: "valid", StateRevision: 8, RecoveryEpoch: 2, Created: true, Findings: []generated.InventoryFinding{}}
	diff := generated.InventoryDiffData{CandidateKind: "draft", CandidateDigest: "sha256:" + strings.Repeat("1", 64), BaselineKind: "draft", BaselineDraft: generated.InventoryDraftRef{DraftID: "draft-base", DraftRevision: 1}, StateRevision: 8, RecoveryEpoch: 2, Records: []generated.InventoryDiffRecord{}, Findings: []generated.InventoryFinding{}}
	exported := generated.InventoryExportData{ExportID: "sha256:" + strings.Repeat("2", 64), SubjectKind: "draft", Draft: generated.InventoryDraftRef{DraftID: "draft-test", DraftRevision: 1}, StateRevision: 9, RecoveryEpoch: 2, ContentDigest: "sha256:" + strings.Repeat("3", 64), Algorithm: "ed25519", KeyID: "synthetic-key", KeyFingerprint: "sha256:" + strings.Repeat("4", 64), VerificationStatus: "verified", PublicationStatus: "published", SignedBytesBase64: "e30K"}
	return &stubControlOperations{
		summaryResponse:  operationResponse(t, "api.v1.summary.get", false, 2, 7, summary),
		databaseResponse: operationResponse(t, "api.v1.database-status.get", false, 2, 7, database),
		importResponse:   operationResponse(t, "api.v1.inventory-drafts.import", true, 2, 8, imported),
		diffResponse:     operationResponse(t, "api.v1.inventory-diffs.create", false, 2, 8, diff),
		exportResponse:   operationResponse(t, "api.v1.inventory-exports.create", true, 2, 9, exported),
	}
}

func operationResponse[T any](t *testing.T, command string, changed bool, epoch, revision int64, data T) localapi.TypedResponse[T] {
	t.Helper()
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "synthetic-build"}, func() (string, error) { return "request-server-36", nil })
	envelope, err := factory.SuccessWithRequestID(command, "request-server-36", changed, epoch, revision, data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return localapi.TypedResponse[T]{Raw: append(raw, '\n'), Result: envelope, Data: data}
}

func TestInventoryImportJSONPreservesRemoteBytesAndExactFileContent(t *testing.T) {
	operations := successfulControlOperations(t)
	files := &stubFileReader{content: []byte("{\r\n  \"schema\": \"synthetic\"\r\n}\r\n")}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{
		"inventory", "import", "--config", "profile.json", "--file", "/tmp/inventory π.json", "--format", "typed-json", "--source-revision", "source-1", "--captured-at", "2026-09-08T06:00:00Z", "--idempotency-key", "opaque-1", "--output", "json",
	}, nil, WithControlOperations(operations, files))
	if code != 0 || stdout != string(operations.importResponse.Raw) || stderr != "" || operations.importRequest.Content != string(files.content) || files.calls != 1 {
		t.Fatalf("result = %d %q %q request=%#v", code, stdout, stderr, operations.importRequest)
	}
}

func TestDiffSelectorAndFileFailuresMakeNoRequest(t *testing.T) {
	for _, args := range [][]string{
		{"inventory", "diff", "--config", "profile.json"},
		{"inventory", "diff", "--config", "profile.json", "--draft-id", "d", "--draft-revision", "1", "--file", "/tmp/x"},
		{"inventory", "diff", "--config", "profile.json", "--file", "/tmp/x", "--format", "typed-json", "--source-revision", "s", "--captured-at", "not-a-time"},
	} {
		operations := successfulControlOperations(t)
		code, stdout, stderr := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(operations, &stubFileReader{content: []byte("{}")}))
		if code != 2 || operations.calls != 0 || strings.Contains(stdout+stderr, "/tmp/x") {
			t.Fatalf("unsafe selector result: %d %q %q calls=%d", code, stdout, stderr, operations.calls)
		}
	}
	operations := successfulControlOperations(t)
	files := &stubFileReader{err: errors.New("private-path-canary")}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{"inventory", "diff", "--config", "profile.json", "--file", "/tmp/private-path-canary", "--format", "typed-json", "--source-revision", "s", "--captured-at", "2026-09-08T06:00:00Z", "--output", "json"}, nil, WithControlOperations(operations, files))
	if code != 8 || operations.calls != 0 || bytes.Contains([]byte(stdout+stderr), []byte("private-path-canary")) {
		t.Fatalf("unsafe file failure = %d %q %q", code, stdout, stderr)
	}
}

func TestInventoryDraftSelectorsAndExpectedRevisionAreTyped(t *testing.T) {
	operations := successfulControlOperations(t)
	files := &stubFileReader{content: []byte("{}")}
	code, _, stderr := runTestAppWithOptions(t, context.Background(), []string{"inventory", "diff", "--config", "profile.json", "--draft-id", "draft-next", "--draft-revision", "2", "--output", "json"}, nil, WithControlOperations(operations, files))
	if code != 0 || stderr != "" || operations.diffRequest.Draft == nil || operations.diffRequest.Draft.DraftRevision != 2 || files.calls != 0 {
		t.Fatalf("diff route = %d %#v files=%d", code, operations.diffRequest, files.calls)
	}
	operations = successfulControlOperations(t)
	code, _, stderr = runTestAppWithOptions(t, context.Background(), []string{"inventory", "import", "--config", "profile.json", "--file", "/tmp/input", "--format", "typed-json", "--source-revision", "source-1", "--captured-at", "2026-09-08T06:00:00Z", "--idempotency-key", "opaque", "--expected-state-revision", "0", "--output", "json"}, nil, WithControlOperations(operations, files))
	if code != 0 || stderr != "" || operations.importRequest.ExpectedStateRevision == nil || *operations.importRequest.ExpectedStateRevision != 0 {
		t.Fatalf("import revision = %d %#v", code, operations.importRequest)
	}
}

func TestControlHumanOutputsMatchGoldens(t *testing.T) {
	operations := successfulControlOperations(t)
	files := &stubFileReader{content: []byte("{}")}
	tests := []struct {
		golden string
		args   []string
	}{
		{"status-human.golden", []string{"status", "--config", "profile.json"}},
		{"database-status-human.golden", []string{"database", "status", "--config", "profile.json"}},
		{"inventory-import-human.golden", []string{"inventory", "import", "--config", "profile.json", "--file", "/tmp/input", "--format", "typed-json", "--source-revision", "source-1", "--captured-at", "2026-09-08T06:00:00Z", "--idempotency-key", "opaque"}},
		{"inventory-diff-human.golden", []string{"inventory", "diff", "--config", "profile.json", "--draft-id", "draft-test", "--draft-revision", "1"}},
		{"inventory-export-human.golden", []string{"inventory", "export", "--config", "profile.json", "--draft-id", "draft-test", "--draft-revision", "1"}},
	}
	for _, test := range tests {
		code, stdout, stderr := runTestAppWithOptions(t, context.Background(), test.args, nil, WithControlOperations(operations, files))
		want, err := os.ReadFile(filepath.Join("testdata", test.golden))
		if err != nil {
			t.Fatal(err)
		}
		if code != 0 || stderr != "" || stdout != string(want) {
			t.Fatalf("%s = code %d stdout %q stderr %q want %q", test.golden, code, stdout, stderr, want)
		}
	}
}
