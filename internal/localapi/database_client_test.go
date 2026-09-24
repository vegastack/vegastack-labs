package localapi

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestDatabaseExportClientUsesOperatorOnlyDraftRoute(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	input := generated.DatabaseExportRequest{Schema: generated.SchemaIDDatabaseExportRequest, SchemaVersion: "1.0.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "export-key", ExportID: "export-a", Kind: "sanitized-control"}
	data := generated.DatabaseExportDraftSubmission{Schema: generated.SchemaIDDatabaseExportDraftSubmission, SchemaVersion: "1.0.0", DraftID: "export-a", ChangeID: digest, ExportID: "export-a", Kind: "sanitized-control", Status: "draft", SafeNextAction: "create and authorize an exact export plan", StateRevision: 8, RecoveryEpoch: 2}
	raw, profile, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.database-exports.create", true, 2, 8, data))
	response, err := NewClient(clientTestFactory()).DraftDatabaseExport(context.Background(), profile, input)
	request := <-captured
	if err != nil || !bytes.Equal(response.Raw, raw) || request.method != http.MethodPost || request.path != "/api/v1/database/exports" || !bytes.Contains(request.body, []byte(`"exportId":"export-a"`)) {
		t.Fatalf("response/request=%#v/%#v err=%v", response, request, err)
	}
	if bytes.Contains(response.Raw, []byte("contentDigest")) || bytes.Contains(response.Raw, []byte("published")) || bytes.Contains(response.Raw, []byte("verified")) {
		t.Fatalf("draft response overclaims artifact: %s", response.Raw)
	}
}

func TestDatabaseExportClientRejectsArtifactLikeOrMalformedDraftResponse(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	input := generated.DatabaseExportRequest{Schema: generated.SchemaIDDatabaseExportRequest, SchemaVersion: "1.0.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "export-key", ExportID: "export-a", Kind: "sanitized-control"}
	malformed := generated.DatabaseExportDraftSubmission{Schema: generated.SchemaIDDatabaseExportDraftSubmission, SchemaVersion: "1.0.0", DraftID: "export-a", ChangeID: digest, ExportID: "export-a", Kind: "sanitized-control", Status: "draft", SafeNextAction: "create and authorize an exact export plan", StateRevision: 99, RecoveryEpoch: 2}
	_, profile, captured := serveFixedResponse(t, http.StatusOK, operationEnvelope(t, "api.v1.database-exports.create", true, 2, 8, malformed))
	_, err := NewClient(clientTestFactory()).DraftDatabaseExport(context.Background(), profile, input)
	<-captured
	if err == nil {
		t.Fatal("client accepted draft whose state revision disagreed with the signed result envelope")
	}
}
