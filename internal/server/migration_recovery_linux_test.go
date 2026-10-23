//go:build linux

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestMigrationRecoveryUpgradesExistingSchema34(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	catalog, err := store.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := sql.Open("sqlite3", (&url.URL{Scheme: "file", Path: path}).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.Close() })
	transaction, err := fixture.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	for _, migration := range catalog[:34] {
		if _, err := transaction.ExecContext(ctx, migration.SQL); err != nil {
			t.Fatalf("fixture migration %d: %v", migration.ID, err)
		}
		if _, err := transaction.ExecContext(ctx,
			`INSERT INTO schema_migrations(id,name,sha256,applied_at,tool_version,build_version) VALUES (?,?,?,?,?,?)`,
			migration.ID, migration.Name, migration.SHA256[:], time.Now().UTC().Format(time.RFC3339Nano), "test-tool", "test-build"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE system_meta SET schema_version = 34 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	recoveryRoot := filepath.Join(directory, "migration-recovery")
	if err := os.Mkdir(recoveryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	authority, err := store.Open(ctx, store.Config{
		DatabasePath: path, Mode: store.OpenExisting, ExpectedUID: uid,
		ToolVersion: "test-tool", BuildVersion: "test-build", BusyTimeout: time.Second,
		Recovery: migrationRecoveryFor(path, uid),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	health, err := authority.Health(ctx)
	if err != nil || health.SchemaVersion != 35 || health.Mode != store.DatabaseReady {
		t.Fatalf("upgraded health = %#v, %v", health, err)
	}
	generations, err := os.ReadDir(recoveryRoot)
	if err != nil || len(generations) != 1 || !generations[0].IsDir() {
		t.Fatalf("snapshot generations = %v, %v", generations, err)
	}
	generation := filepath.Join(recoveryRoot, generations[0].Name())
	body, err := os.ReadFile(filepath.Join(generation, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest backup.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.DatabaseSchemaVersion != 34 || manifest.Verification != backup.VerificationPassed || manifest.SnapshotID != generations[0].Name() {
		t.Fatalf("pre-migration snapshot manifest = %#v", manifest)
	}
	snapshot, err := sql.Open("sqlite3", (&url.URL{Scheme: "file", Path: filepath.Join(generation, "database.sqlite"), RawQuery: "mode=ro"}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	var schema, ledger, deliveries int
	if err := snapshot.QueryRowContext(ctx, `SELECT schema_version, (SELECT count(*) FROM schema_migrations), (SELECT count(*) FROM sqlite_schema WHERE name = 'acknowledgement_deliveries') FROM system_meta WHERE id = 1`).Scan(&schema, &ledger, &deliveries); err != nil {
		t.Fatal(err)
	}
	if schema != 34 || ledger != 34 || deliveries != 0 {
		t.Fatalf("snapshot schema/ledger/deliveries = %d/%d/%d", schema, ledger, deliveries)
	}
}
