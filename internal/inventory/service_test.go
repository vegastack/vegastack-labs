package inventory

import (
	"context"
	"strings"
	"testing"
)

func TestServicePersistsSemanticConflictButNotFatalInput(t *testing.T) {
	t.Parallel()
	repository := &spyRepository{}
	service, err := NewService(repository, fixedID("draft_public_test_1"))
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := service.ValidateAndStore(context.Background(), ImportRequest{IdempotencyKey: "request-1", Decoded: DecodedCandidate{Candidate: conflictCandidateFixture()}})
	if err != nil {
		t.Fatal(err)
	}
	if blocked.ValidationStatus != DraftBlocked || repository.puts != 1 || repository.last.Draft.ValidationStatus != DraftBlocked {
		t.Fatalf("blocked import = %#v, puts=%d", blocked, repository.puts)
	}
	fatal := minimalCandidate()
	fatal.Assets[0].Identities[0].Value = "-----BEGIN PRIVATE KEY----- public-test-canary"
	if _, err := service.ValidateAndStore(context.Background(), ImportRequest{IdempotencyKey: "request-2", Decoded: DecodedCandidate{Candidate: fatal}}); err == nil {
		t.Fatal("secret-shaped candidate accepted")
	}
	if repository.puts != 1 {
		t.Fatalf("fatal candidate reached persistence: puts=%d", repository.puts)
	}
}

func TestServiceHashesOpaqueIdempotencyKeyAndRejectsInvalidKeys(t *testing.T) {
	t.Parallel()
	repository := &spyRepository{}
	service, err := NewService(repository, fixedID("draft_public_test_2"))
	if err != nil {
		t.Fatal(err)
	}
	key := "opaque-public-request"
	if _, err := service.ValidateAndStore(context.Background(), ImportRequest{IdempotencyKey: key, Decoded: DecodedCandidate{Candidate: minimalCandidate()}}); err != nil {
		t.Fatal(err)
	}
	if repository.last.IdempotencyKeyDigest == key || !strings.HasPrefix(repository.last.IdempotencyKeyDigest, "sha256:") {
		t.Fatalf("stored idempotency value = %q", repository.last.IdempotencyKeyDigest)
	}
	for _, invalid := range []string{"", strings.Repeat("x", MaxIdempotencyBytes+1), string([]byte{0xff})} {
		if _, err := service.ValidateAndStore(context.Background(), ImportRequest{IdempotencyKey: invalid, Decoded: DecodedCandidate{Candidate: minimalCandidate()}}); err == nil {
			t.Fatalf("invalid key accepted")
		}
	}
	if repository.puts != 1 {
		t.Fatalf("invalid keys reached repository: %d", repository.puts)
	}
}

type spyRepository struct {
	puts   int
	last   PutDraftRequest
	result PutDraftResult
	err    error
}

func (repository *spyRepository) Put(_ context.Context, request PutDraftRequest) (PutDraftResult, error) {
	repository.puts++
	repository.last = request
	result := repository.result
	if result.Ref.ID == "" {
		result = PutDraftResult{Ref: DraftRef{ID: request.DraftID, Revision: 1}, Created: true, CommitStateRevision: 1}
	}
	return result, repository.err
}
func (*spyRepository) Get(context.Context, DraftRef) (PersistedDraft, error) {
	return PersistedDraft{}, nil
}
func (*spyRepository) ListDrafts(context.Context, DraftListQuery) ([]DraftSummary, error) {
	return nil, nil
}
func (*spyRepository) ListRecords(context.Context, DraftRef, RecordListQuery) ([]DraftRecord, error) {
	return nil, nil
}
func fixedID(id DraftID) IDGenerator { return func() (DraftID, error) { return id, nil } }
