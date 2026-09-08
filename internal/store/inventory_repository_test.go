//go:build linux

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/inventory"
)

func TestInventoryRepositoryPersistsBlockedDraftAtomicallyAndImmutably(t *testing.T) {
	store := newInventoryTestStore(t)
	repository := NewInventoryDraftRepository(store)
	request := inventoryPutRequest("sha256:"+strings.Repeat("1", 64), inventory.DraftBlocked)
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
	if store.health.SchemaVersion != 2 || !tableExistsForTest(t, store, "inventory_drafts") {
		t.Fatalf("fresh store health = %#v", store.health)
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
