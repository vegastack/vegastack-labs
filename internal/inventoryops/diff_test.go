package inventoryops

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/inventory"
)

type fakeDiffRepository struct {
	stateRevision int64
	recoveryEpoch int64
	candidate     inventory.CanonicalDraftSnapshot
	baseline      inventory.CanonicalDraftSnapshot
	baselineErr   error
	queries       []DiffSnapshotRequest
}

func (repo *fakeDiffRepository) ResolveDiffSnapshot(_ context.Context, query DiffSnapshotRequest) (ResolvedDiffSnapshot, error) {
	repo.queries = append(repo.queries, query)
	if repo.baselineErr != nil {
		return ResolvedDiffSnapshot{}, repo.baselineErr
	}
	var candidate *inventory.CanonicalDraftSnapshot
	if query.Candidate != nil {
		value := repo.candidate
		candidate = &value
	}
	return ResolvedDiffSnapshot{Candidate: candidate, Baseline: repo.baseline, StateRevision: repo.stateRevision, RecoveryEpoch: repo.recoveryEpoch}, nil
}

type fakeRegistry struct{ decoded inventory.DecodedCandidate }

func (registry fakeRegistry) Decode(context.Context, DecoderRequest) (inventory.DecodedCandidate, error) {
	return registry.decoded, nil
}

func TestDiffUsesLatestCompatibleAuthorizedDraftAndNeverPersistsFile(t *testing.T) {
	captured := time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC)
	candidate := inventory.DraftCandidate{Source: inventory.SourceDescriptor{Kind: "fixture", AdapterKind: "typed-json", AdapterVersion: "1.0.0", SourceRevision: "s2", Digest: "sha256:" + repeatHex('a'), CapturedAt: captured}}
	normalized, err := inventory.NormalizeAndValidate(context.Background(), inventory.DecodedCandidate{Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	baseline := snapshot("baseline", 3, normalized)
	repo := &fakeDiffRepository{stateRevision: 9, recoveryEpoch: 2, baseline: baseline}
	service, err := NewDiffService(repo, fakeRegistry{decoded: inventory.DecodedCandidate{Candidate: candidate}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.Diff(context.Background(), DiffRequest{Scope: testScope(), Candidate: Candidate{Kind: "file", File: &DecoderRequest{Format: "typed-json", SourceRevision: "s2", CapturedAt: captured, Content: []byte("fixture")}}})
	if err != nil {
		t.Fatal(err)
	}
	if got.BaselineKind != "draft" || got.BaselineDraft.ID != "baseline" || got.StateRevision != 9 || got.RecoveryEpoch != 2 || len(repo.queries) != 1 {
		t.Fatalf("result = %#v queries=%#v", got, repo.queries)
	}
}

func TestDiffIsDeterministicAndBlocksWithoutBaseline(t *testing.T) {
	normalized := normalizedFixture(t)
	candidate := snapshot("candidate", 1, normalized)
	baseline := snapshot("baseline", 1, normalized)
	repo := &fakeDiffRepository{stateRevision: 2, candidate: candidate, baseline: baseline}
	service, _ := NewDiffService(repo, fakeRegistry{})
	request := DiffRequest{Scope: testScope(), Candidate: Candidate{Kind: "draft", Draft: &candidate.Ref}}
	first, err := service.Diff(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Diff(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("nondeterministic diff: %#v %#v", first, second)
	}
	repo.baselineErr = failure.New(generated.ErrorCodePrerequisiteBlocked, "inventory-diff-baseline", false)
	if _, err := service.Diff(context.Background(), request); code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("code = %q error=%v", code(err), err)
	}
}

func TestDiffReportsAddedRemovedAndCanonicalScalarChanges(t *testing.T) {
	base := normalizedFixture(t)
	base.Candidate.Assets = []inventory.DraftAsset{
		{ID: "asset-a", Kind: inventory.AssetOther, Lifecycle: inventory.LifecycleCandidate},
		{ID: "asset-c", Kind: inventory.AssetOther, Lifecycle: inventory.LifecycleAvailable},
	}
	base, _ = inventory.NormalizeAndValidate(context.Background(), inventory.DecodedCandidate{Candidate: base.Candidate})
	nextCandidate := base.Candidate
	nextCandidate.Assets = []inventory.DraftAsset{
		{ID: "asset-a", Kind: inventory.AssetOther, Lifecycle: inventory.LifecycleRetired},
		{ID: "asset-b", Kind: inventory.AssetOther, Lifecycle: inventory.LifecycleAvailable},
	}
	next, err := inventory.NormalizeAndValidate(context.Background(), inventory.DecodedCandidate{Candidate: nextCandidate})
	if err != nil {
		t.Fatal(err)
	}
	candidate, baseline := snapshot("candidate", 1, next), snapshot("baseline", 1, base)
	repo := &fakeDiffRepository{stateRevision: 3, candidate: candidate, baseline: baseline}
	service, _ := NewDiffService(repo, fakeRegistry{})
	got, err := service.Diff(context.Background(), DiffRequest{Scope: testScope(), Candidate: Candidate{Kind: "draft", Draft: &candidate.Ref}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Counts.Added != 1 || got.Counts.Removed != 1 || got.Counts.Changed != 1 || got.Counts.Unchanged != 0 {
		t.Fatalf("counts = %#v records=%#v", got.Counts, got.Records)
	}
	if got.Records[0].Change != "changed" || got.Records[0].Fields[0].Path != "lifecycle" || *got.Records[0].Fields[0].Before != `"candidate"` || *got.Records[0].Fields[0].After != `"retired"` {
		t.Fatalf("canonical change = %#v", got.Records[0])
	}
}

func normalizedFixture(t *testing.T) inventory.NormalizedDraft {
	t.Helper()
	candidate := inventory.DraftCandidate{Source: inventory.SourceDescriptor{Kind: "fixture", AdapterKind: "typed-json", AdapterVersion: "1.0.0", SourceRevision: "s", Digest: "sha256:" + repeatHex('a'), CapturedAt: time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC)}}
	result, err := inventory.NormalizeAndValidate(context.Background(), inventory.DecodedCandidate{Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func snapshot(id string, revision int64, value inventory.NormalizedDraft) inventory.CanonicalDraftSnapshot {
	return inventory.CanonicalDraftSnapshot{Kind: "draft", Ref: inventory.DraftRef{ID: inventory.DraftID(id), Revision: revision}, ValidationStatus: value.ValidationStatus, Source: value.Candidate.Source, Assets: value.Candidate.Assets, Nodes: value.Candidate.Nodes, Aliases: value.Candidate.Aliases, Addresses: value.Candidate.Addresses, Observations: value.Candidate.Observations, Provenance: value.Candidate.Provenance, Findings: value.Findings, ContentDigest: value.ContentDigest}
}
func testScope() authorization.ReadScope {
	return authorization.ReadScope{PrincipalID: "principal-test", Capability: "inventory.draft.diff", ResourceKind: "inventory-draft", GrantRevision: 1, ScopeDigest: "sha256:" + repeatHex('b')}
}
func repeatHex(value byte) string {
	result := make([]byte, 64)
	for i := range result {
		result[i] = value
	}
	return string(result)
}
func code(err error) string {
	if got, ok := failure.As(err); ok {
		return got.Code
	}
	return ""
}
