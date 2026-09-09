//go:build linux

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func TestExistingMigrationCannotRunWithoutVerifiedSnapshot(t *testing.T) {
	store := openTestStore(t)
	base := mustCatalog(t)
	pending := append(base, nextTestMigration(base, "fixture", `CREATE TABLE must_not_exist(id INTEGER);`))
	err := store.migrate(context.Background(), pending)
	if Code(err) != "MIGRATION_BLOCKED" {
		t.Fatalf("code = %q", Code(err))
	}
	if tableExistsForTest(t, store, "must_not_exist") {
		t.Fatal("migration SQL ran before snapshot verification")
	}
}

func TestMigrationFailureVerifiesOnlyIsolatedRestore(t *testing.T) {
	recovery := &recordingRecovery{}
	store := openTestStoreWithRecovery(t, recovery)
	base := mustCatalog(t)
	recovery.snapshot = VerifiedSnapshot{
		SnapshotID:    "fixture",
		SchemaVersion: uint64(len(base)),
		Revision:      RevisionToken{},
	}
	err := store.migrate(context.Background(), append(base, nextTestMigration(base, "bad", `CREATE TABLE broken(`)))
	if err == nil || recovery.prepareCalls != 1 || recovery.verifyCalls != 1 {
		t.Fatalf("err/calls = %v/%d/%d", err, recovery.prepareCalls, recovery.verifyCalls)
	}
	if tableExistsForTest(t, store, "broken") {
		t.Fatal("failed migration changed authority")
	}
	health, _ := store.Health(context.Background())
	if health.Mode != DatabaseSafeMode || health.MutationEnabled {
		t.Fatalf("health = %#v", health)
	}
}

func TestMigrationAppliesExactLedgerAfterRecoveryGate(t *testing.T) {
	recovery := &recordingRecovery{}
	store := openTestStoreWithRecovery(t, recovery)
	base := mustCatalog(t)
	recovery.snapshot = VerifiedSnapshot{SnapshotID: "fixture", SchemaVersion: uint64(len(base)), Revision: RevisionToken{}}
	err := store.migrate(context.Background(), append(base, nextTestMigration(base, "fixture", `CREATE TABLE migrated(id INTEGER PRIMARY KEY) STRICT;`)))
	if err != nil {
		t.Fatal(err)
	}
	if !tableExistsForTest(t, store, "migrated") || store.health.SchemaVersion != uint64(len(base)+1) || recovery.verifyCalls != 0 {
		t.Fatalf("migration result health=%#v verify=%d", store.health, recovery.verifyCalls)
	}
}

func TestMigrationRejectsUnknownNewerAndChangedLedger(t *testing.T) {
	t.Run("newer schema", func(t *testing.T) {
		store := openTestStore(t)
		if _, err := store.conn.ExecContext(context.Background(), `UPDATE system_meta SET schema_version = 99 WHERE id = 1`); err != nil {
			t.Fatal(err)
		}
		if err := store.migrate(context.Background(), mustCatalog(t)); Code(err) != "VERSION_INCOMPATIBLE" {
			t.Fatalf("code = %q", Code(err))
		}
	})
	t.Run("unknown ledger row", func(t *testing.T) {
		store := openTestStore(t)
		base := mustCatalog(t)
		unknown := nextTestMigration(base, "unknown", "unknown")
		checksum := sha256.Sum256([]byte("unknown"))
		if _, err := store.conn.ExecContext(context.Background(), `INSERT INTO schema_migrations(id,name,sha256,applied_at,tool_version,build_version) VALUES (?,?,?,'now','test','test')`, unknown.ID, unknown.Name, checksum[:]); err != nil {
			t.Fatal(err)
		}
		if err := store.migrate(context.Background(), mustCatalog(t)); Code(err) != "MIGRATION_BLOCKED" {
			t.Fatalf("code = %q", Code(err))
		}
	})
	t.Run("changed checksum", func(t *testing.T) {
		store := openTestStore(t)
		if _, err := store.conn.ExecContext(context.Background(), `DROP TRIGGER schema_migrations_no_update`); err != nil {
			t.Fatal(err)
		}
		checksum := sha256.Sum256([]byte("changed"))
		if _, err := store.conn.ExecContext(context.Background(), `UPDATE schema_migrations SET sha256 = ? WHERE id = 1`, checksum[:]); err != nil {
			t.Fatal(err)
		}
		if err := store.migrate(context.Background(), mustCatalog(t)); Code(err) != "MIGRATION_BLOCKED" {
			t.Fatalf("code = %q", Code(err))
		}
	})
}

func TestRecoverySourceCreatesAndVerifiesIsolatedCopies(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.conn.ExecContext(context.Background(), `CREATE TABLE recovery_sentinel(value TEXT NOT NULL) STRICT; INSERT INTO recovery_sentinel(value) VALUES ('before-migration')`); err != nil {
		t.Fatal(err)
	}
	beforeHealth, err := store.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(store.config.DatabasePath)
	catalog := mustCatalog(t)
	source := &recoverySource{store: store, catalog: catalog}
	snapshot := filepath.Join(directory, "snapshot.db")
	if err := source.OnlineBackup(context.Background(), snapshot, BackupStepPolicy{PagesPerStep: 1}); err != nil {
		t.Fatal(err)
	}
	expectation := SnapshotExpectation{SchemaVersion: uint64(len(catalog)), Revision: RevisionToken{}, CatalogSHA256: catalogSHA256(catalog)}
	inspection, err := source.InspectSnapshot(context.Background(), snapshot, expectation)
	if err != nil || inspection.IntegrityStatus != IntegrityVerified {
		t.Fatalf("inspection = %#v, %v", inspection, err)
	}
	restored := filepath.Join(directory, "isolated-restore.db")
	if err := source.RestoreSnapshot(context.Background(), snapshot, restored); err != nil {
		t.Fatal(err)
	}
	if _, err := source.InspectSnapshot(context.Background(), restored, expectation); err != nil {
		t.Fatal(err)
	}
	restoredDatabase, err := sql.Open(sqliteDriverName, fileURI(restored, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer restoredDatabase.Close()
	var sentinel string
	if err := restoredDatabase.QueryRowContext(context.Background(), `SELECT value FROM recovery_sentinel`).Scan(&sentinel); err != nil || sentinel != "before-migration" {
		t.Fatalf("restored sentinel = %q, %v", sentinel, err)
	}
	afterHealth, err := store.Health(context.Background())
	if err != nil || afterHealth.Revision != beforeHealth.Revision || afterHealth.Mode != beforeHealth.Mode {
		t.Fatalf("authority health changed: before=%#v after=%#v err=%v", beforeHealth, afterHealth, err)
	}
	contenderConfig := store.config
	contenderConfig.Mode = OpenExisting
	if _, err := Open(context.Background(), contenderConfig); Code(err) != "STATE_CONFLICT" {
		t.Fatalf("writer lock was not retained: %v", err)
	}
	wrongCatalog := expectation
	wrongCatalog.CatalogSHA256 = sha256.Sum256([]byte("wrong catalog"))
	if _, err := source.InspectSnapshot(context.Background(), restored, wrongCatalog); Code(err) != "MIGRATION_BLOCKED" {
		t.Fatalf("wrong catalog code = %q", Code(err))
	}
	if err := source.RestoreSnapshot(context.Background(), snapshot, store.config.DatabasePath); Code(err) != "INPUT_INVALID" {
		t.Fatalf("authority replacement code = %q", Code(err))
	}
}

func TestMigrationFailureKeepsStableSafeModeWhenVerificationFails(t *testing.T) {
	base := mustCatalog(t)
	recovery := &recordingRecovery{snapshot: VerifiedSnapshot{SnapshotID: "fixture", SchemaVersion: uint64(len(base))}, verifyErr: errors.New("injected verification failure")}
	store := openTestStoreWithRecovery(t, recovery)
	err := store.migrate(context.Background(), append(base, nextTestMigration(base, "bad", `CREATE TABLE broken(`)))
	if Code(err) != "MIGRATION_BLOCKED" {
		t.Fatalf("code = %q", Code(err))
	}
	if store.health.SafeModeReason != "migration-failure" || !store.health.RecoveryPending {
		t.Fatalf("health = %#v", store.health)
	}
	if err := store.Read(context.Background(), func(ReadTx) error { return nil }); err != nil {
		t.Fatalf("safe-mode read failed: %v", err)
	}
	if _, err := store.WriteIntent(context.Background(), nil, func(IntentTx) error { return nil }); Code(err) != "PREREQUISITE_BLOCKED" {
		t.Fatalf("safe-mode write code = %q", Code(err))
	}
}

func TestMigrationBackupFailureBlocksBeforeSQL(t *testing.T) {
	recovery := &recordingRecovery{prepareErr: errors.New("injected backup disk full")}
	store := openTestStoreWithRecovery(t, recovery)
	base := mustCatalog(t)
	err := store.migrate(context.Background(), append(base, nextTestMigration(base, "never_runs", `CREATE TABLE backup_gate_failed(id INTEGER) STRICT;`)))
	if Code(err) != "MIGRATION_BLOCKED" || tableExistsForTest(t, store, "backup_gate_failed") || recovery.prepareCalls != 1 || recovery.verifyCalls != 0 {
		t.Fatalf("err/table/calls = %v/%t/%d/%d", err, tableExistsForTest(t, store, "backup_gate_failed"), recovery.prepareCalls, recovery.verifyCalls)
	}
	if store.health.Mode != DatabaseSafeMode || store.health.MutationEnabled {
		t.Fatalf("health = %#v", store.health)
	}
}

func TestMigrationPostCheckFailureRollsBackBeforeVerification(t *testing.T) {
	base := mustCatalog(t)
	recovery := &recordingRecovery{snapshot: VerifiedSnapshot{SnapshotID: "fixture", SchemaVersion: uint64(len(base))}}
	store := openTestStoreWithRecovery(t, recovery)
	body := `
CREATE TABLE postcheck_parent(id INTEGER PRIMARY KEY) STRICT;
CREATE TABLE postcheck_child(
  id INTEGER PRIMARY KEY,
  parent_id INTEGER NOT NULL,
  FOREIGN KEY(parent_id) REFERENCES postcheck_parent(id) DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO postcheck_child(id, parent_id) VALUES (1, 999);`
	err := store.migrate(context.Background(), append(base, nextTestMigration(base, "postcheck", body)))
	if Code(err) != "INTEGRITY_FAILURE" || tableExistsForTest(t, store, "postcheck_child") || recovery.verifyCalls != 1 {
		t.Fatalf("err/table/verify = %v/%t/%d", err, tableExistsForTest(t, store, "postcheck_child"), recovery.verifyCalls)
	}
}

func TestMigrationSyncFailurePreservesCommittedAuthorityInSafeMode(t *testing.T) {
	base := mustCatalog(t)
	recovery := &recordingRecovery{snapshot: VerifiedSnapshot{SnapshotID: "fixture", SchemaVersion: uint64(len(base))}}
	store := openTestStoreWithRecovery(t, recovery)
	store.filesystem = syncFailFilesystem{linuxFilesystem: linuxFilesystem{}}
	err := store.migrate(context.Background(), append(base, nextTestMigration(base, "committed", `CREATE TABLE committed_before_sync_failure(id INTEGER) STRICT;`)))
	if Code(err) != "INTEGRITY_FAILURE" || !tableExistsForTest(t, store, "committed_before_sync_failure") || recovery.verifyCalls != 1 {
		t.Fatalf("err/table/verify = %v/%t/%d", err, tableExistsForTest(t, store, "committed_before_sync_failure"), recovery.verifyCalls)
	}
}

type syncFailFilesystem struct{ linuxFilesystem }

func (syncFailFilesystem) SyncDatabase(context.Context, string, FileIdentity) error {
	return filesystemError(errors.New("injected sync failure"))
}

type recordingRecovery struct {
	snapshot     VerifiedSnapshot
	prepareErr   error
	verifyErr    error
	prepareCalls int
	verifyCalls  int
}

func (recovery *recordingRecovery) Prepare(_ context.Context, _ MigrationSource, request MigrationRequest) (VerifiedSnapshot, error) {
	recovery.prepareCalls++
	if recovery.snapshot.CatalogSHA256 == ([32]byte{}) {
		recovery.snapshot.CatalogSHA256 = request.CatalogSHA256
	}
	return recovery.snapshot, recovery.prepareErr
}

func (recovery *recordingRecovery) VerifyRestorable(context.Context, MigrationSource, VerifiedSnapshot) (RestoreEvidence, error) {
	recovery.verifyCalls++
	return RestoreEvidence{SnapshotID: recovery.snapshot.SnapshotID, Status: "verified"}, recovery.verifyErr
}

func openTestStoreWithRecovery(t *testing.T, recovery MigrationRecovery) *Store {
	t.Helper()
	config := testConfig(t)
	config.Recovery = recovery
	store, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func mustCatalog(t *testing.T) []Migration {
	t.Helper()
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func testMigration(id uint64, name, body string) Migration {
	return Migration{ID: id, Name: name, SQL: body, SHA256: sha256.Sum256([]byte(body))}
}

func nextTestMigration(catalog []Migration, suffix, body string) Migration {
	id := uint64(len(catalog) + 1)
	return testMigration(id, fmt.Sprintf("%04d_%s", id, suffix), body)
}

func tableExistsForTest(t *testing.T, store *Store, name string) bool {
	t.Helper()
	var count int
	err := store.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = ?`, name).Scan(&count)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	return count == 1
}
