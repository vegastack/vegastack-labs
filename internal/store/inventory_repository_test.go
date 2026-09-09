//go:build linux

package store

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

func TestInventoryRepositoryPersistsBlockedDraftAtomicallyAndImmutably(t *testing.T) {
	store := newInventoryTestStore(t)
	repository := NewInventoryDraftRepository(store)
	request := inventoryPutRequest("sha256:"+strings.Repeat("1", 64), inventory.DraftBlocked)
	request.Draft.Candidate.Assets = append(request.Draft.Candidate.Assets, request.Draft.Candidate.Assets[0])
	request.Draft.Counts.Assets = 2
	request.Draft.Findings = []inventory.Finding{{Code: "MISSING_REFERENCE", Severity: "error", Blocking: true, RecordKind: "node", RecordID: "node-a", FieldPath: "assetId", Location: "records/node-a/assetId"}}
	request.Draft.Counts.Findings = 1
	result, err := repository.Put(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || result.CommitStateRevision != 1 {
		t.Fatalf("put result = %#v", result)
	}
	persisted, err := repository.Get(context.Background(), result.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.ValidationStatus != inventory.DraftBlocked || len(persisted.Assets) != len(request.Draft.Candidate.Assets) || len(persisted.Findings) == 0 {
		t.Fatalf("blocked draft was partial: %#v", persisted)
	}
	if _, err := store.conn.ExecContext(context.Background(), `UPDATE inventory_drafts SET validation_status='valid' WHERE draft_id=? AND draft_revision=?`, result.Ref.ID, result.Ref.Revision); err == nil {
		t.Fatal("immutable draft UPDATE succeeded")
	}
}

func TestInventoryRepositoryRollsBackEveryRowOnChildFailure(t *testing.T) {
	store := newInventoryTestStore(t)
	repository := NewInventoryDraftRepository(store)
	request := inventoryPutRequest("sha256:"+strings.Repeat("2", 64), inventory.DraftValid)
	request.Draft.Candidate.Provenance[0].RecordID = inventory.LocalID("missing-record")
	if _, err := repository.Put(context.Background(), request); err == nil {
		t.Fatal("invalid provenance reference was persisted")
	}
	for _, table := range inventoryDraftTables {
		if got := countRows(t, store, table); got != 0 {
			t.Errorf("%s rows = %d", table, got)
		}
	}
	if got := readStateRevision(t, store); got != 0 {
		t.Fatalf("state revision = %d", got)
	}
}

func TestFreshInitializationAppliesWholeCheckedCatalogWithoutRecovery(t *testing.T) {
	store := newInventoryTestStore(t)
	if store.health.SchemaVersion != 3 || !tableExistsForTest(t, store, "inventory_drafts") || !tableExistsForTest(t, store, "audit_events") {
		t.Fatalf("fresh store health = %#v", store.health)
	}
}

func TestInventoryImportIdempotencyAndSourceRevisionConflicts(t *testing.T) {
	store := newInventoryTestStore(t)
	repository := NewInventoryDraftRepository(store)
	request := inventoryPutRequest("sha256:"+strings.Repeat("3", 64), inventory.DraftValid)
	first, err := repository.Put(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := repository.Put(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || retry.Created || first.Ref != retry.Ref || first.CommitStateRevision != retry.CommitStateRevision {
		t.Fatalf("first/retry = %#v / %#v", first, retry)
	}
	changed := request
	changed.CandidateDigest = "sha256:" + strings.Repeat("c", 64)
	changed.Draft.ContentDigest = changed.CandidateDigest
	if _, err := repository.Put(context.Background(), changed); Code(err) != "STATE_CONFLICT" {
		t.Fatalf("changed key code = %q", Code(err))
	}
	sourceConflict := request
	sourceConflict.IdempotencyKeyDigest = "sha256:" + strings.Repeat("4", 64)
	sourceConflict.Draft.Candidate.Source.Digest = "sha256:" + strings.Repeat("f", 64)
	if _, err := repository.Put(context.Background(), sourceConflict); Code(err) != "STATE_CONFLICT" {
		t.Fatalf("source conflict code = %q", Code(err))
	}
	if got := readStateRevision(t, store); got != first.CommitStateRevision {
		t.Fatalf("state revision after conflicts = %d", got)
	}
}

func TestInventoryRepositoryListsAndSnapshotsCanonicalDrafts(t *testing.T) {
	store := newInventoryTestStore(t)
	repository := NewInventoryDraftRepository(store)
	second := inventoryPutRequest("sha256:"+strings.Repeat("6", 64), inventory.DraftValid)
	second.DraftID = "draft-public-b"
	second.CandidateDigest = "sha256:" + strings.Repeat("d", 64)
	second.Draft.ContentDigest = second.CandidateDigest
	first := inventoryPutRequest("sha256:"+strings.Repeat("5", 64), inventory.DraftValid)
	first.DraftID = "draft-public-a"
	first.CandidateDigest = "sha256:" + strings.Repeat("c", 64)
	first.Draft.ContentDigest = first.CandidateDigest
	if _, err := repository.Put(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	created, err := repository.Put(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	listed, err := repository.ListDrafts(context.Background(), inventory.DraftListQuery{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Ref.ID != "draft-public-a" {
		t.Fatalf("listed = %#v", listed)
	}
	next, err := repository.ListDrafts(context.Background(), inventory.DraftListQuery{AfterCreatedAt: listed[0].CreatedAt, AfterDraftID: listed[0].Ref.ID, AfterRevision: listed[0].Ref.Revision, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(next) != 1 || next[0].Ref.ID != "draft-public-b" {
		t.Fatalf("next = %#v", next)
	}
	records, err := repository.ListRecords(context.Background(), created.Ref, inventory.RecordListQuery{Limit: 256})
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index < len(records); index++ {
		if records[index-1].Kind+"\x00"+string(records[index-1].LocalID) > records[index].Kind+"\x00"+string(records[index].LocalID) {
			t.Fatalf("records unordered: %#v", records)
		}
	}
	projection, err := repository.SnapshotDraft(context.Background(), created.Ref)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if projection.Kind != "draft" || projection.ContentDigest != first.Draft.ContentDigest {
		t.Fatalf("projection identity = %#v", projection)
	}
	if regexp.MustCompile(`(?i)(declared|effective|admitted|qualified|rawSource|idempotencyKey|provider|sheetColumn|BEGIN PRIVATE KEY)`).Match(raw) {
		t.Fatalf("unsafe draft projection: %s", raw)
	}
	for _, limit := range []int{0, 257} {
		if _, err := repository.ListDrafts(context.Background(), inventory.DraftListQuery{Limit: limit}); err == nil {
			t.Fatalf("draft limit %d accepted", limit)
		}
		if _, err := repository.ListRecords(context.Background(), created.Ref, inventory.RecordListQuery{Limit: limit}); err == nil {
			t.Fatalf("record limit %d accepted", limit)
		}
	}
}

func TestInventoryRepositoryFaultAndCancellationRollBack(t *testing.T) {
	store := newInventoryTestStore(t)
	repository := NewInventoryDraftRepository(store)
	repository.beforeChildWrite = func() error { return errors.New("injected child failure") }
	if _, err := repository.Put(context.Background(), inventoryPutRequest("sha256:"+strings.Repeat("7", 64), inventory.DraftValid)); Code(err) != "INTEGRITY_FAILURE" {
		t.Fatalf("fault code = %q", Code(err))
	}
	for _, table := range inventoryDraftTables {
		if got := countRows(t, store, table); got != 0 {
			t.Errorf("%s rows = %d", table, got)
		}
	}
	if got := readStateRevision(t, store); got != 0 {
		t.Fatalf("fault state revision = %d", got)
	}
	repository.beforeChildWrite = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := repository.Put(ctx, inventoryPutRequest("sha256:"+strings.Repeat("8", 64), inventory.DraftValid)); Code(err) != "INTERRUPTED" {
		t.Fatalf("cancel code = %q", Code(err))
	}
	if got := readStateRevision(t, store); got != 0 {
		t.Fatalf("cancel state revision = %d", got)
	}
}

var inventoryDraftTables = []string{"inventory_import_keys", "inventory_source_bindings", "inventory_drafts", "inventory_draft_assets", "inventory_draft_identities", "inventory_draft_nodes", "inventory_draft_aliases", "inventory_draft_addresses", "inventory_draft_observations", "inventory_draft_hardware_facts", "inventory_draft_provenance", "inventory_draft_findings"}

func newInventoryTestStore(t *testing.T) *Store {
	t.Helper()
	config := testConfig(t)
	config.Clock = func() time.Time { return time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC) }
	store, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func inventoryPutRequest(key string, status inventory.DraftValidationStatus) inventory.PutDraftRequest {
	capacity := int64(1024)
	candidate := inventory.DraftCandidate{
		Source:       inventory.SourceDescriptor{Kind: "operator-file", AdapterKind: "strict-json", AdapterVersion: "1.0.0", SourceRevision: "source-1", Digest: "sha256:" + strings.Repeat("a", 64), CapturedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)},
		Assets:       []inventory.DraftAsset{{ID: "asset-a", Kind: inventory.AssetPhysical, Lifecycle: inventory.LifecycleCandidate, Identities: []inventory.DraftIdentity{{Kind: "hardware-serial", Value: "PUBLIC-001"}}, HardwareFacts: []inventory.DraftHardwareFact{{ID: "memory", Kind: "memory-capacity", IntegerValue: &capacity, Unit: "bytes"}}}},
		Nodes:        []inventory.DraftNode{{ID: "node-a", AssetID: "asset-a"}},
		Aliases:      []inventory.DraftAlias{{ID: "alias-a", TargetID: "node-a", Value: "example-node"}},
		Addresses:    []inventory.DraftAddress{{ID: "address-a", NodeID: "node-a", Value: "192.0.2.1"}},
		Observations: []inventory.DraftObservation{{ID: "observation-a", SubjectID: "asset-a", Kind: "link-state", Value: "up", ObservedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}},
		Provenance:   []inventory.FieldProvenance{{RecordKind: "asset", RecordID: "asset-a", FieldPath: "kind", Locator: "records/1/kind", CapturedAt: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC), AdapterVersion: "1.0.0", ValueStatus: "observed"}},
	}
	counts := inventory.DraftCounts{Assets: 1, Nodes: 1, Aliases: 1, Addresses: 1, Observations: 1, HardwareFacts: 1, Provenance: 1}
	return inventory.PutDraftRequest{IdempotencyKeyDigest: key, CandidateDigest: "sha256:" + strings.Repeat("b", 64), DraftID: "draft-public-1", Draft: inventory.NormalizedDraft{Candidate: candidate, ValidationStatus: status, ContentDigest: "sha256:" + strings.Repeat("b", 64), Counts: counts}}
}

func countRows(t *testing.T, store *Store, table string) int {
	t.Helper()
	var count int
	if err := store.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM `+table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func readStateRevision(t *testing.T, store *Store) int64 {
	t.Helper()
	var revision int64
	if err := store.conn.QueryRowContext(context.Background(), `SELECT state_revision FROM system_meta WHERE id=1`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}
