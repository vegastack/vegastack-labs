//go:build linux

package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestMigrationProcess(t *testing.T) {
	if os.Getenv("VSK_STORE_PROCESS_HELPER") == "1" {
		runMigrationProcessHelper()
		return
	}
	for _, stage := range []string{"before", "during", "after"} {
		t.Run(stage, func(t *testing.T) {
			config := testConfig(t)
			store, err := Open(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.conn.ExecContext(context.Background(), `CREATE TABLE process_sentinel(id INTEGER PRIMARY KEY) STRICT; INSERT INTO process_sentinel(id) VALUES (1);`); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestMigrationProcess$")
			command.Env = append(os.Environ(), "VSK_STORE_PROCESS_HELPER=1", "VSK_STORE_PROCESS_STAGE="+stage, "VSK_STORE_PROCESS_DATABASE="+config.DatabasePath)
			if err := command.Run(); err == nil {
				t.Fatal("abrupt helper unexpectedly exited successfully")
			}
			config.Mode = OpenExisting
			reopened, err := Open(context.Background(), config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			var count int
			if err := reopened.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM process_sentinel`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 1
			if stage == "after" {
				want = 2
			}
			if count != want {
				t.Fatalf("sentinel rows = %d, want %d", count, want)
			}
		})
	}
}

func TestMigrationProcessRecoveryGateBlocksSQL(t *testing.T) {
	if os.Getenv("VSK_STORE_PROCESS_HELPER") == "1" {
		runMigrationProcessHelper()
		return
	}
	config := testConfig(t)
	store, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestMigrationProcessRecoveryGateBlocksSQL$")
	command.Env = append(os.Environ(),
		"VSK_STORE_PROCESS_HELPER=1",
		"VSK_STORE_PROCESS_STAGE=recovery-block",
		"VSK_STORE_PROCESS_DATABASE="+config.DatabasePath,
	)
	if err := command.Run(); err == nil {
		t.Fatal("recovery-gate helper returned success")
	}
	database, err := sql.Open(sqliteDriverName, fileURI(config.DatabasePath, "ro"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='must_not_run'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("migration SQL ran despite failed recovery preparation")
	}
}

func runMigrationProcessHelper() {
	if os.Getenv("VSK_STORE_PROCESS_STAGE") == "recovery-block" {
		runRecoveryGateProcessHelper()
		return
	}
	if os.Getenv("VSK_STORE_PROCESS_STAGE") == "before" {
		os.Exit(42)
	}
	database, err := sql.Open(sqliteDriverName, sqliteURI(os.Getenv("VSK_STORE_PROCESS_DATABASE")))
	if err != nil {
		os.Exit(43)
	}
	database.SetMaxOpenConns(1)
	transaction, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		os.Exit(44)
	}
	if _, err := transaction.ExecContext(context.Background(), `INSERT INTO process_sentinel(id) VALUES (2)`); err != nil {
		os.Exit(45)
	}
	if os.Getenv("VSK_STORE_PROCESS_STAGE") == "during" {
		os.Exit(42)
	}
	if err := transaction.Commit(); err != nil {
		os.Exit(46)
	}
	os.Exit(42)
}

func runRecoveryGateProcessHelper() {
	path := os.Getenv("VSK_STORE_PROCESS_DATABASE")
	config := Config{
		DatabasePath: path,
		Mode:         OpenExisting,
		BusyTimeout:  25 * time.Millisecond,
		ExpectedUID:  uint32(os.Geteuid()),
		ToolVersion:  "test",
		BuildVersion: "test",
		Recovery:     &recordingRecovery{prepareErr: errors.New("injected recovery failure")},
	}
	store, err := Open(context.Background(), config)
	if err != nil {
		os.Exit(51)
	}
	pending := append(mustCatalogForProcess(), testMigration(4, "0004_must_not_run", `CREATE TABLE must_not_run(id INTEGER PRIMARY KEY) STRICT;`))
	if err := store.migrate(context.Background(), pending); Code(err) != "MIGRATION_BLOCKED" {
		os.Exit(52)
	}
	if tableExistsForProcess(store, "must_not_run") {
		os.Exit(53)
	}
	_ = store.Close()
	os.Exit(90)
}

func mustCatalogForProcess() []Migration {
	catalog, err := Catalog()
	if err != nil {
		os.Exit(54)
	}
	return catalog
}

func tableExistsForProcess(store *Store, name string) bool {
	var count int
	return store.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?`, name).Scan(&count) == nil && count == 1
}
