package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type capturedRequest struct {
	method, path, contentType string
	body                      []byte
}

func TestInventoryClientUsesFixedRoutesAndRetainsExactEnvelopes(t *testing.T) {
	client := NewClient(clientTestFactory())
	summary := generated.ApiSummaryData{DatabaseMode: "read-write", ReadAvailable: true, RecoveryEpoch: 2, StateRevision: 7}
	raw, profile, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, generated.CommandNameStatus, false, 2, 7, summary))
	response, err := client.Summary(context.Background(), profile)
	if err != nil || !bytes.Equal(response.Raw, raw) || (<-captured).path != "/api/v1/summary" {
		t.Fatalf("summary response = %#v err=%v", response, err)
	}

	database := generated.DatabaseStatusData{Mode: "read-write", SchemaVersion: 1, SQLiteVersion: "3.synthetic", IntegrityStatus: "ok"}
	raw, profile, captured = serveFixedResponse(t, http.StatusOK, operationEnvelope(t, generated.CommandNameDatabaseStatus, false, 2, 7, database))
	databaseResponse, err := client.DatabaseStatus(context.Background(), profile)
	if err != nil || !bytes.Equal(databaseResponse.Raw, raw) || (<-captured).path != "/api/v1/database/status" {
		t.Fatalf("database response = %#v err=%v", databaseResponse, err)
	}

	importRequest := generated.InventoryImportRequest{Format: "typed-json", SourceRevision: "source-1", CapturedAt: "2026-09-08T06:00:00Z", IdempotencyKey: "opaque-1", Content: "{}"}
	importData := generated.InventoryImportData{DraftID: "draft-test", DraftRevision: 1, StateRevision: 8, RecoveryEpoch: 2, Created: true}
	raw, profile, captured = serveFixedResponse(t, http.StatusOK, operationEnvelope(t, generated.CommandNameInventoryImport, true, 2, 8, importData))
	importResponse, err := client.ImportInventory(context.Background(), profile, importRequest)
	gotImport := <-captured
	if err != nil || !bytes.Equal(importResponse.Raw, raw) || gotImport.method != http.MethodPost || gotImport.path != "/api/v1/inventory-drafts/import" || gotImport.contentType != "application/json" {
		t.Fatalf("import response/request = %#v/%#v err=%v", importResponse, gotImport, err)
	}
	var decodedImport generated.InventoryImportRequest
	if json.Unmarshal(gotImport.body, &decodedImport) != nil || !reflect.DeepEqual(decodedImport, importRequest) {
		t.Fatalf("import body = %s", gotImport.body)
	}

	draft := &generated.InventoryDraftRef{DraftID: "draft-next", DraftRevision: 2}
	diffRequest := generated.InventoryDiffRequest{CandidateKind: "draft", Draft: draft}
	diffData := generated.InventoryDiffData{CandidateKind: "draft", BaselineKind: "draft", BaselineDraft: generated.InventoryDraftRef{DraftID: "draft-base", DraftRevision: 1}, StateRevision: 8, RecoveryEpoch: 2}
	raw, profile, captured = serveFixedResponse(t, http.StatusOK, operationEnvelope(t, generated.CommandNameInventoryDiff, false, 2, 8, diffData))
	diffResponse, err := client.DiffInventory(context.Background(), profile, diffRequest)
	gotDiff := <-captured
	if err != nil || !bytes.Equal(diffResponse.Raw, raw) || gotDiff.path != "/api/v1/inventory-diffs" || !bytes.Contains(gotDiff.body, []byte(`"candidateKind":"draft"`)) {
		t.Fatalf("diff response/request = %#v/%#v err=%v", diffResponse, gotDiff, err)
	}

	exportRequest := generated.InventoryExportRequest{Draft: *draft}
	exportData := generated.InventoryExportData{ExportID: "sha256:" + strings.Repeat("1", 64), SubjectKind: "draft", Draft: *draft, StateRevision: 9, RecoveryEpoch: 2}
	raw, profile, captured = serveFixedResponse(t, http.StatusOK, operationEnvelope(t, generated.CommandNameInventoryExport, true, 2, 9, exportData))
	exportResponse, err := client.ExportInventory(context.Background(), profile, exportRequest)
	gotExport := <-captured
	if err != nil || !bytes.Equal(exportResponse.Raw, raw) || gotExport.path != "/api/v1/inventory-exports" || bytes.Contains(gotExport.body, []byte("file")) {
		t.Fatalf("export response/request = %#v/%#v err=%v", exportResponse, gotExport, err)
	}
}

func TestTypedClientRejectsCommandStatusAndDataDisagreement(t *testing.T) {
	validData := generated.ApiSummaryData{DatabaseMode: "read-write", ReadAvailable: true, RecoveryEpoch: 2, StateRevision: 7}
	valid := operationEnvelope(t, generated.CommandNameStatus, false, 2, 7, validData)
	fixtures := []struct {
		status int
		raw    []byte
	}{
		{http.StatusCreated, valid},
		{http.StatusOK, []byte(strings.Replace(string(valid), `"command":"status"`, `"command":"help"`, 1))},
		{http.StatusOK, []byte(strings.Replace(string(valid), `"databaseMode":"read-write"`, `"databaseMode":""`, 1))},
		{http.StatusOK, append(append([]byte(nil), valid...), []byte("{}\n")...)},
	}
	for _, fixture := range fixtures {
		_, profile, captured := serveFixedResponse(t, fixture.status, fixture.raw)
		_, err := NewClient(clientTestFactory()).Summary(context.Background(), profile)
		<-captured
		stable, ok := failure.As(err)
		if !ok || stable.Code != generated.ErrorCodeIntegrityFailure || strings.Contains(err.Error(), string(fixture.raw)) {
			t.Fatalf("unsafe error = %v", err)
		}
	}
}

func TestTypedClientNeverFollowsRedirect(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "vsk-client-redirect-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		http.Redirect(writer, request, "/private-canary", http.StatusFound)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close(); _ = os.RemoveAll(directory) })
	_, err = NewClient(clientTestFactory()).Summary(context.Background(), serverconfig.Profile{SocketPath: path})
	if err == nil || calls.Load() != 1 {
		t.Fatalf("redirect result = %v calls=%d", err, calls.Load())
	}
}

func operationEnvelope[T any](t *testing.T, command string, changed bool, epoch, revision int64, data T) []byte {
	t.Helper()
	envelope, err := clientTestFactory().SuccessWithRequestID(command, "request-remote", changed, epoch, revision, data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func serveFixedResponse(t *testing.T, status int, raw []byte) ([]byte, serverconfig.Profile, <-chan capturedRequest) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "vsk-client-fixed-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	captured := make(chan capturedRequest, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		captured <- capturedRequest{method: request.Method, path: request.URL.Path, contentType: request.Header.Get("Content-Type"), body: body}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = writer.Write(raw)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close(); _ = os.RemoveAll(directory) })
	return raw, serverconfig.Profile{SocketPath: path}, captured
}
