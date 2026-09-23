package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func openCredentialMigrationFixture(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential-migration.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open(sqliteDriverName, sqliteURI(path))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestCredentialEvidenceMigrationPreservesRowsAndAppendOnlyChecks(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	db := openCredentialMigrationFixture(t)
	for _, migration := range catalog[14:16] {
		if _, err := db.Exec(migration.SQL); err != nil {
			t.Fatalf("apply %s: %v", migration.Name, err)
		}
		if migration.ID == 15 {
			good := "sha256:" + hexRepeatForMigration("a", 64)
			if _, err := db.Exec(`INSERT INTO credential_consumer_verifications VALUES('v1','r','version-a','consumer-a','profile-a','role-a','material-a',?,?,1,'verified','loaded',0,'now')`, good, good); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO credential_recovery_records VALUES('r1','r','version-a','draft-a',?,?,0,1,?,'now')`, good, good, good); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, table := range []string{"credential_consumer_verifications", "credential_recovery_records"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s rows not preserved: count=%d err=%v", table, count, err)
		}
		if _, err := db.Exec("DELETE FROM " + table); err == nil {
			t.Fatalf("%s lost its append-only trigger", table)
		}
	}
	good := "sha256:" + hexRepeatForMigration("a", 64)
	bad := "sha256:" + hexRepeatForMigration("z", 64)
	if _, err := db.Exec(`INSERT INTO credential_consumer_verifications VALUES('v2','r','version-b','consumer-a','profile-a','role-a','material-a',?,?,1,'verified','loaded',0,'now')`, good, bad); err == nil {
		t.Fatal("migrated table accepted nonhex evidence")
	}
	if _, err := db.Exec(`INSERT INTO credential_consumer_verifications VALUES('v3','r','version-c','consumer-a','profile-a','role-a','material-a',?,?,1,'verified','Bad Reason',0,'now')`, good, good); err == nil {
		t.Fatal("migrated table accepted invalid reason")
	}
	if _, err := db.Exec(`INSERT INTO credential_recovery_records VALUES('r2','r','version-b','draft-a',?,?,0,1,?,'now')`, bad, good, good); err == nil {
		t.Fatal("migrated recovery table accepted nonhex custody digest")
	}
}

func TestNativeReaderMapMigrationExpandsBindingAndPreservesAppendOnlyRows(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	db := openCredentialMigrationFixture(t)
	for _, migration := range catalog[14:16] {
		if _, err := db.Exec(migration.SQL); err != nil {
			t.Fatalf("apply %s: %v", migration.Name, err)
		}
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	insert := `INSERT INTO credential_lifecycle_bindings(binding_id,declaration_id,declaration_revision,operation_id,action,reference_id,binding_digest,binding_bytes,recovery_epoch,created_at) VALUES(?,?,1,?,'credential.stage',?,?,?,0,'now')`
	if _, err := db.Exec(insert, "old", "declaration-a", "operation-a", "reference-a", digest, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(insert, "too-large-before", "declaration-b", "operation-b", "reference-b", digest, []byte(strings.Repeat("x", 4097))); err == nil {
		t.Fatal("old 4 KiB bound unexpectedly accepted expanded map")
	}
	if _, err := db.Exec(catalog[17].SQL); err != nil {
		t.Fatalf("expand binding table: %v", err)
	}
	var old []byte
	if err := db.QueryRow(`SELECT binding_bytes FROM credential_lifecycle_bindings WHERE binding_id='old'`).Scan(&old); err != nil || string(old) != "{}" {
		t.Fatalf("old sealed row lost: %q %v", old, err)
	}
	if _, err := db.Exec(insert, "expanded", "declaration-b", "operation-b", "reference-b", digest, []byte(strings.Repeat("x", 65537))); err != nil {
		t.Fatalf("expanded map rejected: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM credential_lifecycle_bindings WHERE binding_id='old'`); err == nil {
		t.Fatal("migrated binding table lost append-only trigger")
	}
	if _, err := db.Exec(insert, "too-large-after", "declaration-c", "operation-c", "reference-c", digest, []byte(strings.Repeat("x", 262145))); err == nil {
		t.Fatal("expanded bound accepted oversized map")
	}
}

func TestCredentialEvidenceMigrationFailsClosedOnRetainedInvalidRow(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	db := openCredentialMigrationFixture(t)
	if _, err := db.Exec(catalog[14].SQL); err != nil {
		t.Fatal(err)
	}
	good := "sha256:" + hexRepeatForMigration("a", 64)
	bad := "sha256:" + hexRepeatForMigration("z", 64)
	if _, err := db.Exec(`INSERT INTO credential_consumer_verifications VALUES('v1','r','version-a','consumer-a','profile-a','role-a','material-a',?,?,1,'verified','loaded',0,'now')`, good, bad); err != nil {
		t.Fatalf("older schema must accept the adversarial retained row: %v", err)
	}
	transaction, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(catalog[15].SQL); err == nil {
		_ = transaction.Rollback()
		t.Fatal("migration silently accepted retained nonhex evidence")
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM credential_consumer_verifications WHERE verification_id='v1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed migration did not preserve old evidence: count=%d err=%v", count, err)
	}
	if _, err := db.Exec(`DELETE FROM credential_consumer_verifications`); err == nil {
		t.Fatal("failed migration lost old append-only trigger")
	}
}

func hexRepeatForMigration(char string, count int) string {
	result := make([]byte, count)
	for i := range result {
		result[i] = char[0]
	}
	return string(result)
}

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

func TestCatalogAddsAuditOutboxAsExactlyMigrationThree(t *testing.T) {
	t.Parallel()
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog) != 23 || catalog[2].ID != 3 || catalog[2].Name != "0003_audit_outbox" || catalog[3].ID != 4 || catalog[3].Name != "0004_read_authorization" || catalog[4].ID != 5 || catalog[4].Name != "0005_browser_sessions" || catalog[5].ID != 6 || catalog[5].Name != "0006_declarations_and_plans" || catalog[6].ID != 7 || catalog[6].Name != "0007_effective_authorization" || catalog[7].ID != 8 || catalog[7].Name != "0008_acknowledgements" || catalog[8].ID != 9 || catalog[8].Name != "0009_runs" || catalog[9].ID != 10 || catalog[9].Name != "0010_external_executor_leases" || catalog[10].ID != 11 || catalog[10].Name != "0011_gate_evidence" || catalog[11].ID != 12 || catalog[11].Name != "0012_credential_refs" || catalog[12].ID != 13 || catalog[12].Name != "0013_credential_import_drafts" || catalog[13].ID != 14 || catalog[13].Name != "0014_audit_chain" || catalog[14].ID != 15 || catalog[14].Name != "0015_credential_lifecycle" || catalog[15].ID != 16 || catalog[15].Name != "0016_credential_evidence_hardening" || catalog[16].ID != 17 || catalog[16].Name != "0017_backup_creation" || catalog[17].ID != 18 || catalog[17].Name != "0018_native_credential_reader_maps" || catalog[18].ID != 19 || catalog[18].Name != "0019_backup_verification" || catalog[19].ID != 20 || catalog[19].Name != "0020_backup_custody" || catalog[20].ID != 21 || catalog[20].Name != "0021_backup_trust_sources" || catalog[21].ID != 22 || catalog[21].Name != "0022_local_retirements" || catalog[22].ID != 23 || catalog[22].Name != "0023_offsite_generations" {
		t.Fatalf("third migration = %#v", catalog)
	}
	for _, required := range []string{"backup_offsite_run_specs", "backup_offsite_generations", "backup_offsite_retention_rules", "backup_offsite_objects", "backup_offsite_session_expiries", "backup_offsite_proofs", "backup_offsite_last_good_history", "no_update", "no_delete"} {
		if !containsFold(catalog[22].SQL, required) {
			t.Errorf("offsite generation migration is missing %q", required)
		}
	}
	for _, required := range []string{"backup_retention_lock_catalog_activations", "source_coverage_digest", "lock_catalog_sequence", "backup_retirement_intents", "backup_retirement_mutation_attempts", "backup_retirement_mutation_outcomes", "backup_retirement_receipts", "backup_retirement_successor_generations", "backup_retirement_finalizations", "backup_retirement_custody_attempts", "backup_retirement_custody_outcomes", "no_update", "no_delete"} {
		if !containsFold(catalog[21].SQL, required) {
			t.Errorf("local retirement migration is missing %q", required)
		}
	}
	for _, required := range []string{"backup_trust_source_drafts", "backup_trust_source_bindings", "backup_dependency_trust_evidence", "no_update", "no_delete"} {
		if !containsFold(catalog[20].SQL, required) {
			t.Errorf("backup trust migration is missing %q", required)
		}
	}
	for _, required := range []string{"backup_policy_drafts", "backup_jobs", "recovery_points", "backup_expected_objects", "backup_writer_leases", "no_update", "no_delete"} {
		if !containsFold(catalog[16].SQL, required) {
			t.Errorf("backup creation migration is missing %q", required)
		}
	}
	for _, required := range []string{"audit_instances", "audit_epoch_genesis", "audit_chain_links", "audit_checkpoints", "audit_checkpoint_outbox", "no_update", "no_delete"} {
		if !containsFold(catalog[13].SQL, required) {
			t.Errorf("audit chain migration is missing %q", required)
		}
	}
	if sha256.Sum256([]byte(catalog[3].SQL)) != catalog[3].SHA256 {
		t.Fatal("migration 0004 checksum mismatch")
	}
	for _, required := range []string{"remote_identity_bindings", "browser_sessions", "session_digest", "recovery_epoch", "no_delete", "monotonic"} {
		if !containsFold(catalog[4].SQL, required) {
			t.Errorf("session migration is missing %q", required)
		}
	}
	if sha256.Sum256([]byte(catalog[2].SQL)) != catalog[2].SHA256 {
		t.Fatal("migration 0003 checksum mismatch")
	}
	for _, required := range []string{"audit_sequence", "audit_events", "intent_keys", "outbox", "canonical_payload", "payload_sha256", "dedupe_sha256", "retry_wait", "dead_letter", "no_update", "no_delete"} {
		if !containsFold(catalog[2].SQL, required) {
			t.Errorf("audit migration is missing %q", required)
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
