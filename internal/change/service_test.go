package change

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestReviseNormalizesSetFieldsAndPreservesDeclaredOperationSequence(t *testing.T) {
	repository := &fakeRepository{}
	service, err := NewService(repository, func() time.Time { return time.Date(2026, 9, 12, 19, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	request := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: "declaration-test-1", DeclarationType: "node.configuration", ExpectedRevision: 1, ExpectedStateRevision: 4, RecoveryEpoch: 2, Operations: []generated.DeclarationOperation{{Sequence: 2, OperationID: "operation-b", OperationType: "configuration.update", AdapterID: "adapter-test", TargetID: "node-b", InputDigest: testDigestString("b"), ArtifactDigest: testDigestString("c"), Idempotent: true}, {Sequence: 1, OperationID: "operation-a", OperationType: "configuration.update", AdapterID: "adapter-test", TargetID: "node-a", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("b"), Idempotent: true}}, ReasonDigest: testDigestString("d"), Extensions: []generated.ContractExtension{{Name: "x-z", ValueDigest: testDigestString("e")}, {Name: "x-a", ValueDigest: testDigestString("f")}}}
	result, err := service.Revise(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer", AgentSessionID: "session-test"}, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Document.Operations[0].Sequence != 1 || result.Document.Extensions[0].Name != "x-a" || repository.request.Document.ContentDigest == "" {
		t.Fatalf("revision was not canonical: %#v", result.Document)
	}
}

type fakeRepository struct {
	request store.DeclarationRevisionRequest
}

func (repository *fakeRepository) CreateRevision(_ context.Context, request store.DeclarationRevisionRequest) (store.DeclarationRevisionResult, error) {
	repository.request = request
	return store.DeclarationRevisionResult{Document: request.Document, Commit: store.Commit{Changed: true, StateRevision: request.Document.StateRevision, RecoveryEpoch: request.Document.RecoveryEpoch}, Created: true}, nil
}
func (repository *fakeRepository) GetRevision(context.Context, string, int64) (generated.DeclarationRevision, error) {
	return repository.request.Document, nil
}

func testDigestString(fill string) string {
	value := ""
	for len(value) < 64 {
		value += fill
	}
	return "sha256:" + value[:64]
}
