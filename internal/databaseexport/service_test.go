package databaseexport

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type revisionStub struct{ token store.RevisionToken }

func (stub revisionStub) CurrentRevision(context.Context) (store.RevisionToken, error) {
	return stub.token, nil
}

type declarationStub struct {
	calls   int
	request generated.DeclarationRevisionRequest
}

func (stub *declarationStub) Revise(_ context.Context, _ change.AuthorScope, request generated.DeclarationRevisionRequest) (change.Result, error) {
	stub.calls++
	stub.request = request
	return change.Result{Changed: true, Document: generated.DeclarationRevision{DeclarationID: request.DeclarationID, ContentDigest: "sha256:" + strings.Repeat("b", 64), CreatedAt: "2026-09-24T06:00:00Z", StateRevision: request.ExpectedStateRevision + 1, RecoveryEpoch: request.RecoveryEpoch}}, nil
}

func TestDraftPersistsOnlyInertDeclarationMetadata(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	declarations := &declarationStub{}
	service, err := NewService(revisionStub{store.RevisionToken{StateRevision: 7, RecoveryEpoch: 2}}, declarations)
	if err != nil {
		t.Fatal(err)
	}
	input := generated.DatabaseExportRequest{Schema: generated.SchemaIDDatabaseExportRequest, SchemaVersion: "1.0.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "export-key", ExportID: "export-a", Kind: "sanitized-control"}
	result, changed, err := service.Draft(context.Background(), input, change.AuthorScope{PrincipalID: "human-a", PrincipalMethod: "local-os-peer", AgentSessionID: "request-a"})
	if err != nil || !changed || declarations.calls != 1 {
		t.Fatalf("result=%#v changed=%v calls=%d err=%v", result, changed, declarations.calls, err)
	}
	if result.Status != "draft" || result.SafeNextAction != "create and authorize an exact export plan" || result.ChangeID == "" || declarations.request.Operations[0].AdapterID != "core.database" || declarations.request.Operations[0].TargetID != "database" {
		t.Fatalf("result/request = %#v / %#v", result, declarations.request)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "contentDigest") || strings.Contains(string(raw), "published") || strings.Contains(string(raw), "verified") {
		t.Fatalf("draft overclaims exported artifact: %s", raw)
	}
}

func TestDraftRejectsStaleRevisionBeforePersistence(t *testing.T) {
	declarations := &declarationStub{}
	service, _ := NewService(revisionStub{store.RevisionToken{StateRevision: 8, RecoveryEpoch: 2}}, declarations)
	digest := "sha256:" + strings.Repeat("a", 64)
	input := generated.DatabaseExportRequest{Schema: generated.SchemaIDDatabaseExportRequest, SchemaVersion: "1.0.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: digest, IdempotencyKey: "export-key", ExportID: "export-a", Kind: "sanitized-control"}
	if _, _, err := service.Draft(context.Background(), input, change.AuthorScope{PrincipalID: "human-a", PrincipalMethod: "local-os-peer", AgentSessionID: "request-a"}); err == nil || declarations.calls != 0 {
		t.Fatalf("err=%v calls=%d", err, declarations.calls)
	}
}
