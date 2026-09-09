package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/inventoryops"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

type countingBody struct {
	data  *bytes.Reader
	reads int
}

func (body *countingBody) Read(target []byte) (int, error) {
	body.reads++
	return body.data.Read(target)
}
func (*countingBody) Close() error { return nil }

type importServiceFunc func(context.Context, inventory.ImportRequest) (inventory.ImportResult, error)

func (function importServiceFunc) ValidateAndStore(ctx context.Context, request inventory.ImportRequest) (inventory.ImportResult, error) {
	return function(ctx, request)
}

type exportServiceFunc func(context.Context, stateexport.Request) (stateexport.Result, error)

func (function exportServiceFunc) Export(ctx context.Context, request stateexport.Request) (stateexport.Result, error) {
	return function(ctx, request)
}

type decoderFunc func(context.Context, inventoryops.DecoderRequest) (inventory.DecodedCandidate, error)

func (function decoderFunc) Decode(ctx context.Context, request inventoryops.DecoderRequest) (inventory.DecodedCandidate, error) {
	return function(ctx, request)
}

func TestInventoryImportAuthorizesBeforeReadingBody(t *testing.T) {
	body := &countingBody{data: bytes.NewReader([]byte(`{"content":"private-canary"}`))}
	app := newOperationTestApplication(t, authorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
		return authorization.ReadScope{}, failure.New(generated.ErrorCodeAuthorizationDenied, "read", false)
	}), importServiceFunc(func(context.Context, inventory.ImportRequest) (inventory.ImportResult, error) {
		t.Fatal("import called")
		return inventory.ImportResult{}, nil
	}), nil)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/inventory-drafts/import", nil)
	request.Body = body
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || body.reads != 0 || strings.Contains(response.Body.String(), "private-canary") {
		t.Fatalf("response/reads = %d/%d %s", response.Code, body.reads, response.Body.String())
	}
}

func TestInventoryRoutesPreserveDraftSemanticsAndExportDelegation(t *testing.T) {
	var importCorrelation, exportCorrelation string
	imports := importServiceFunc(func(_ context.Context, request inventory.ImportRequest) (inventory.ImportResult, error) {
		importCorrelation = request.CorrelationID
		return inventory.ImportResult{DraftID: "draft-test-1", DraftRevision: 1, ValidationStatus: inventory.DraftValid, SourceDigest: "sha256:" + strings.Repeat("1", 64), ContentDigest: "sha256:" + strings.Repeat("2", 64), StateRevision: 4, RecoveryEpoch: 1, Created: true, Counts: inventory.DraftCounts{}}, nil
	})
	exports := exportServiceFunc(func(_ context.Context, request stateexport.Request) (stateexport.Result, error) {
		exportCorrelation = request.CorrelationID
		return stateexport.Result{ExportID: "sha256:" + strings.Repeat("3", 64), SubjectKind: "draft", Draft: request.Draft, StateRevision: 5, RecoveryEpoch: 1, ContentDigest: "sha256:" + strings.Repeat("3", 64), Algorithm: "ed25519", KeyID: "dev-key", KeyFingerprint: "sha256:" + strings.Repeat("4", 64), VerificationStatus: "verified", PublicationStatus: "published", CanonicalBytes: []byte("signed-public-fixture\n"), Created: true}, nil
	})
	app := newOperationTestApplication(t, allowOperationAuthorizer(), imports, exports)
	importBody := map[string]any{"format": "typed-json", "sourceRevision": "source-1", "capturedAt": "2026-09-08T06:00:00Z", "idempotencyKey": "opaque-1", "expectedStateRevision": nil, "content": minimalTypedInventory(t)}
	imported := serveOperationJSON(t, app, "/api/v1/inventory-drafts/import", importBody)
	exported := serveOperationJSON(t, app, "/api/v1/inventory-exports", map[string]any{"draft": map[string]any{"draftId": "draft-test-1", "draftRevision": 1}})
	var importResult, exportResult generated.RunResult
	if json.Unmarshal(imported.Body.Bytes(), &importResult) != nil || json.Unmarshal(exported.Body.Bytes(), &exportResult) != nil {
		t.Fatal("invalid envelopes")
	}
	if imported.Code != http.StatusOK || exported.Code != http.StatusOK || !importResult.Changed || !exportResult.Changed || importCorrelation == "" || exportCorrelation == "" {
		t.Fatalf("results = %d/%d %#v %#v", imported.Code, exported.Code, importResult, exportResult)
	}
	if bytes.Contains(exported.Body.Bytes(), []byte("serverPath")) || bytes.Contains(exported.Body.Bytes(), []byte("declared")) {
		t.Fatalf("authority/path leak: %s", exported.Body.String())
	}
}

func TestInventoryMalformedRequestsNeverReachDomainServices(t *testing.T) {
	calls := 0
	imports := importServiceFunc(func(context.Context, inventory.ImportRequest) (inventory.ImportResult, error) {
		calls++
		return inventory.ImportResult{}, nil
	})
	app := newOperationTestApplication(t, allowOperationAuthorizer(), imports, nil)
	for _, body := range []string{
		``,
		`{"format":"typed-json"}`,
		`{"format":"typed-json","format":"labs-sheet1-csv","sourceRevision":"source-1","capturedAt":"2026-09-08T06:00:00Z","idempotencyKey":"opaque-1","expectedStateRevision":null,"content":"{}"}`,
		`{"format":"typed-json","sourceRevision":"source-1","capturedAt":"2026-09-08T06:00:00Z","idempotencyKey":"opaque-1","expectedStateRevision":null,"content":"{}","unknown":true}`,
		`{"format":"typed-json","sourceRevision":"source-1","capturedAt":"2026-09-08T06:00:00Z","idempotencyKey":"opaque-1","expectedStateRevision":null,"content":"{}"}{}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/inventory-drafts/import", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body %q status = %d", body, response.Code)
		}
	}
	if calls != 0 {
		t.Fatalf("domain calls = %d", calls)
	}
}

func TestInventoryExportRequiresExactDraftAuthorization(t *testing.T) {
	var targets []authorization.ReadTarget
	authorizer := authorizerFunc(func(_ context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
		targets = append(targets, target)
		if target.ResourceID != "" {
			return authorization.ReadScope{}, failure.New(generated.ErrorCodeAuthorizationDenied, "read", false)
		}
		return authorization.ReadScope{PrincipalID: principal.ID, Capability: target.Capability, ResourceKind: target.ResourceKind, GrantRevision: 1, ScopeDigest: "sha256:" + strings.Repeat("5", 64)}, nil
	})
	publisherCalls := 0
	app := newOperationTestApplication(t, authorizer, importServiceFunc(func(context.Context, inventory.ImportRequest) (inventory.ImportResult, error) {
		return inventory.ImportResult{}, nil
	}), exportServiceFunc(func(context.Context, stateexport.Request) (stateexport.Result, error) {
		publisherCalls++
		return stateexport.Result{}, nil
	}))
	response := serveOperationJSON(t, app, "/api/v1/inventory-exports", map[string]any{"draft": map[string]any{"draftId": "draft-private", "draftRevision": 1}})
	if response.Code != http.StatusForbidden || publisherCalls != 0 || len(targets) != 2 || targets[1].ResourceID != "draft-private:1" {
		t.Fatalf("status/calls/targets = %d/%d/%#v", response.Code, publisherCalls, targets)
	}
}

func TestInventoryDiffWithoutAuthorizedBaselineIsBlocked(t *testing.T) {
	app := newOperationTestApplication(t, allowOperationAuthorizer(), importServiceFunc(func(context.Context, inventory.ImportRequest) (inventory.ImportResult, error) {
		return inventory.ImportResult{}, nil
	}), nil)
	response := serveOperationJSON(t, app, "/api/v1/inventory-diffs", map[string]any{
		"candidateKind": "draft", "draft": map[string]any{"draftId": "draft-only", "draftRevision": 1},
		"format": nil, "sourceRevision": nil, "capturedAt": nil, "content": nil,
	})
	if response.Code != http.StatusPreconditionFailed || !strings.Contains(response.Body.String(), generated.ErrorCodePrerequisiteBlocked) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
}

func newOperationTestApplication(t *testing.T, authorizer authorization.ReadAuthorizer, imports inventory.ImportService, exports ExportService) *Application {
	t.Helper()
	if exports == nil {
		exports = exportServiceFunc(func(context.Context, stateexport.Request) (stateexport.Result, error) {
			t.Fatal("export called")
			return stateexport.Result{}, nil
		})
	}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-operation-test", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: authorizer, Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	diff, err := inventoryops.NewDiffService(&operationDiffRepository{}, operationDecoder{})
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterInventoryOperations(app, InventoryOperationConfig{Decoders: operationDecoder{}, Imports: imports, Diffs: diff, Exports: exports, Results: factory, MaxBodyBytes: MaxOperationRequestBytes}); err != nil {
		t.Fatal(err)
	}
	return app
}

type operationDecoder struct{}

func (operationDecoder) Decode(context.Context, inventoryops.DecoderRequest) (inventory.DecodedCandidate, error) {
	return inventory.DecodedCandidate{}, nil
}

type operationDiffRepository struct{}

func (*operationDiffRepository) ResolveDiffSnapshot(context.Context, inventoryops.DiffSnapshotRequest) (inventoryops.ResolvedDiffSnapshot, error) {
	return inventoryops.ResolvedDiffSnapshot{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "inventory-diff-baseline", false)
}

func allowOperationAuthorizer() authorization.ReadAuthorizer {
	return authorizerFunc(func(_ context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
		return authorization.ReadScope{PrincipalID: principal.ID, Capability: target.Capability, ResourceKind: target.ResourceKind, GrantRevision: 1, ScopeDigest: "sha256:" + strings.Repeat("5", 64)}, nil
	})
}

func serveOperationJSON(t *testing.T, app *Application, path string, value any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	return response
}

func minimalTypedInventory(t *testing.T) string {
	t.Helper()
	value := generated.InventoryDraftInput{Schema: generated.SchemaIDInventoryDraftInput, SchemaVersion: "1.0.0", Source: generated.InventoryDraftSource{Kind: "fixture", AdapterKind: "typed-json", AdapterVersion: "1.0.0", SourceRevision: "source-1", CapturedAt: "2026-09-08T06:00:00Z"}, Assets: []generated.InventoryDraftAsset{}, Nodes: []generated.InventoryDraftNode{}, Aliases: []generated.InventoryDraftAlias{}, Addresses: []generated.InventoryDraftAddress{}, Observations: []generated.InventoryDraftObservation{}, Provenance: []generated.InventoryFieldProvenance{}}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

var _ io.ReadCloser = (*countingBody)(nil)
