package store

import (
	"context"
	"crypto/sha256"
	"testing"
	"testing/fstest"
)

type recoveryContractFake struct{}

func (recoveryContractFake) Prepare(context.Context, MigrationSource, MigrationRequest) (VerifiedSnapshot, error) {
	return VerifiedSnapshot{}, nil
}

func (recoveryContractFake) VerifyRestorable(context.Context, MigrationSource, VerifiedSnapshot) (RestoreEvidence, error) {
	return RestoreEvidence{}, nil
}

type migrationSourceContractFake struct{}

func (migrationSourceContractFake) OnlineBackup(context.Context, string, BackupStepPolicy) error {
	return nil
}

func (migrationSourceContractFake) InspectSnapshot(context.Context, string, SnapshotExpectation) (SnapshotInspection, error) {
	return SnapshotInspection{}, nil
}

func (migrationSourceContractFake) RestoreSnapshot(context.Context, string, string) error {
	return nil
}

var _ MigrationRecovery = recoveryContractFake{}
var _ MigrationSource = migrationSourceContractFake{}

func TestCatalogRejectsGapAndChecksumDrift(t *testing.T) {
	t.Parallel()

	body := []byte("SELECT 1;\n")
	sum := sha256.Sum256(body)
	files := fstest.MapFS{"migrations/0001_store_foundation.sql": {Data: body}}
	got, err := catalogFromFS(files, []migrationManifestEntry{{ID: 1, Name: "0001_store_foundation", SHA256: sum}})
	if err != nil || len(got) != 1 || got[0].SHA256 != sum {
		t.Fatalf("catalog = %#v, %v", got, err)
	}

	_, err = catalogFromFS(files, []migrationManifestEntry{{ID: 2, Name: "0002_inventory_drafts", SHA256: sum}})
	if Code(err) != "MIGRATION_BLOCKED" {
		t.Fatalf("gap code = %q", Code(err))
	}
	bad := sum
	bad[0] ^= 0xff
	_, err = catalogFromFS(files, []migrationManifestEntry{{ID: 1, Name: "0001_store_foundation", SHA256: bad}})
	if Code(err) != "MIGRATION_BLOCKED" {
		t.Fatalf("checksum code = %q", Code(err))
	}
}

func TestCatalogRejectsDuplicateEmptyAndFilenameMismatch(t *testing.T) {
	t.Parallel()

	body := []byte("SELECT 1;\n")
	sum := sha256.Sum256(body)
	files := fstest.MapFS{
		"migrations/0001_store_foundation.sql": {Data: body},
		"migrations/0002_inventory_drafts.sql": {Data: nil},
	}
	cases := [][]migrationManifestEntry{
		{{ID: 1, Name: "0001_store_foundation", SHA256: sum}, {ID: 1, Name: "0001_store_foundation", SHA256: sum}},
		{{ID: 1, Name: "0001_wrong", SHA256: sum}},
		{{ID: 1, Name: "0001_store_foundation", SHA256: sum}, {ID: 2, Name: "0002_inventory_drafts", SHA256: sha256.Sum256(nil)}},
	}
	for _, manifest := range cases {
		if _, err := catalogFromFS(files, manifest); Code(err) != "MIGRATION_BLOCKED" {
			t.Fatalf("catalogFromFS(%#v) code = %q", manifest, Code(err))
		}
	}
}

func TestFoundationMigrationOwnsOnlySystemTables(t *testing.T) {
	t.Parallel()

	catalog, err := Catalog()
	if err != nil || len(catalog) < 1 {
		t.Fatalf("Catalog() = %#v, %v", catalog, err)
	}
	if catalog[0].ID != 1 || catalog[0].Name != "0001_store_foundation" {
		t.Fatalf("foundation migration = %#v", catalog[0])
	}
	for _, required := range []string{"system_meta", "schema_migrations", "state_revision", "recovery_epoch", "RAISE(ABORT"} {
		if !containsFold(catalog[0].SQL, required) {
			t.Errorf("foundation SQL is missing %q", required)
		}
	}
	for _, forbidden := range []string{"principals", "grants", "inventory", "audit_events", "outbox", "snapshot", "export"} {
		if containsFold(catalog[0].SQL, forbidden) {
			t.Errorf("foundation SQL contains out-of-scope table %q", forbidden)
		}
	}
}

func TestCatalogReservesSecondMigrationForInventoryDrafts(t *testing.T) {
	t.Parallel()
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) < 2 || catalog[1].ID != 2 || catalog[1].Name != "0002_inventory_drafts" {
		t.Fatalf("second migration = %#v", catalog)
	}
	if sha256.Sum256([]byte(catalog[1].SQL)) != catalog[1].SHA256 {
		t.Fatal("inventory migration checksum does not match embedded SQL")
	}
	for _, required := range []string{"inventory_drafts", "inventory_draft_assets", "inventory_draft_provenance", "inventory_import_keys", "no_update", "no_delete"} {
		if !containsFold(catalog[1].SQL, required) {
			t.Errorf("inventory migration is missing %q", required)
		}
	}
}

func TestCatalogDigestIsStableAcrossInputOrder(t *testing.T) {
	t.Parallel()

	one := Migration{ID: 1, Name: "0001_store_foundation", SHA256: sha256.Sum256([]byte("one"))}
	two := Migration{ID: 2, Name: "0002_inventory_drafts", SHA256: sha256.Sum256([]byte("two"))}
	if catalogSHA256([]Migration{one, two}) != catalogSHA256([]Migration{two, one}) {
		t.Fatal("catalog digest depends on input ordering")
	}
}
