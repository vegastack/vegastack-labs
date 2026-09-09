package inventory

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestServiceRequiresVerifiedPrincipalAndBuildsTrustedAuditDraft(t *testing.T) {
	t.Parallel()
	repository := &spyRepository{}
	destinations := []audit.OutboxRequirement{{Destination: "audit-primary", Enabled: true}}
	service, err := NewService(repository, fixedID("draft_public_audit"), destinations)
	if err != nil {
		t.Fatal(err)
	}
	destinations[0].Destination = "mutated-after-construction"
	request := ImportRequest{IdempotencyKey: "request-audit", CorrelationID: "request-test-1", Decoded: DecodedCandidate{Candidate: minimalCandidate()}}
	if _, err := service.ValidateAndStore(context.Background(), request); inventoryErrorCode(err) != generated.ErrorCodeAuthenticationRequired {
		t.Fatalf("missing principal = %v", err)
	}
	ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod})
	result, err := service.ValidateAndStore(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.EventID != 1 || repository.last.Event.Type != "inventory.draft.persisted" || repository.last.Event.Attribution.AuthenticatedPrincipalID != "principal-test-1" || repository.last.Event.Target.ID != string(result.DraftID) || repository.last.Event.After == nil || string(*repository.last.Event.After) != result.ContentDigest {
		t.Fatalf("result/request = %#v / %#v", result, repository.last)
	}
	if len(repository.last.Destinations) != 1 || repository.last.Destinations[0].Destination != "audit-primary" {
		t.Fatalf("destination policy was not copied: %#v", repository.last.Destinations)
	}
	canary := "github_pat_public-test-canary"
	forged := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: canary, Method: identity.LocalOSPeerMethod})
	if _, err := service.ValidateAndStore(forged, request); err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("unsafe forged context principal = %v", err)
	}
}

func inventoryErrorCode(err error) string {
	if typed, ok := err.(*Error); ok {
		return typed.Code
	}
	return ""
}

func TestServicePersistsSemanticConflictButNotFatalInput(t *testing.T) {
	t.Parallel()
	repository := &spyRepository{}
	service, err := NewService(repository, fixedID("draft_public_test_1"), oneDestination())
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := service.ValidateAndStore(verifiedContext(), ImportRequest{IdempotencyKey: "request-1", CorrelationID: "request-1", Decoded: DecodedCandidate{Candidate: conflictCandidateFixture()}})
	if err != nil {
		t.Fatal(err)
	}
	if blocked.ValidationStatus != DraftBlocked || repository.puts != 1 || repository.last.Draft.ValidationStatus != DraftBlocked {
		t.Fatalf("blocked import = %#v, puts=%d", blocked, repository.puts)
	}
	fatal := minimalCandidate()
	fatal.Assets[0].Identities[0].Value = strings.Join([]string{"-----BEGIN", "PRIVATE KEY----- public-test-canary"}, " ")
	if _, err := service.ValidateAndStore(verifiedContext(), ImportRequest{IdempotencyKey: "request-2", CorrelationID: "request-2", Decoded: DecodedCandidate{Candidate: fatal}}); err == nil {
		t.Fatal("secret-shaped candidate accepted")
	}
	if repository.puts != 1 {
		t.Fatalf("fatal candidate reached persistence: puts=%d", repository.puts)
	}
}

func TestServiceHashesOpaqueIdempotencyKeyAndRejectsInvalidKeys(t *testing.T) {
	t.Parallel()
	repository := &spyRepository{}
	service, err := NewService(repository, fixedID("draft_public_test_2"), oneDestination())
	if err != nil {
		t.Fatal(err)
	}
	key := "opaque-public-request"
	if _, err := service.ValidateAndStore(verifiedContext(), ImportRequest{IdempotencyKey: key, CorrelationID: "request-key", Decoded: DecodedCandidate{Candidate: minimalCandidate()}}); err != nil {
		t.Fatal(err)
	}
	if repository.last.IdempotencyKeyDigest == key || !strings.HasPrefix(repository.last.IdempotencyKeyDigest, "sha256:") {
		t.Fatalf("stored idempotency value = %q", repository.last.IdempotencyKeyDigest)
	}
	for _, invalid := range []string{"", strings.Repeat("x", MaxIdempotencyBytes+1), string([]byte{0xff})} {
		if _, err := service.ValidateAndStore(verifiedContext(), ImportRequest{IdempotencyKey: invalid, CorrelationID: "request-invalid", Decoded: DecodedCandidate{Candidate: minimalCandidate()}}); err == nil {
			t.Fatalf("invalid key accepted")
		}
	}
	if repository.puts != 1 {
		t.Fatalf("invalid keys reached repository: %d", repository.puts)
	}
}

func TestStructuralAndCancellationFailuresNeverCallRepository(t *testing.T) {
	t.Parallel()
	repository := &spyRepository{}
	service, err := NewService(repository, fixedID("draft_public_test_3"), oneDestination())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.ValidateAndStore(ctx, ImportRequest{IdempotencyKey: "cancelled", CorrelationID: "request-cancelled", Decoded: DecodedCandidate{Candidate: minimalCandidate()}}); err == nil {
		t.Fatal("cancelled import succeeded")
	}
	overLimit := minimalCandidate()
	overLimit.Assets = make([]DraftAsset, MaxPrimaryRecords+1)
	if _, err := service.ValidateAndStore(verifiedContext(), ImportRequest{IdempotencyKey: "too-many", CorrelationID: "request-too-many", Decoded: DecodedCandidate{Candidate: overLimit}}); err == nil {
		t.Fatal("over-limit import succeeded")
	}
	if repository.puts != 0 {
		t.Fatalf("repository puts = %d", repository.puts)
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
		result = PutDraftResult{Ref: DraftRef{ID: request.DraftID, Revision: 1}, Created: true, CommitStateRevision: 1, EventID: 1}
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

func verifiedContext() context.Context {
	return identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod})
}

func oneDestination() []audit.OutboxRequirement {
	return []audit.OutboxRequirement{{Destination: "audit-primary", Enabled: true}}
}
