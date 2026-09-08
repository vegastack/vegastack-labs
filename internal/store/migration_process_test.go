//go:build linux

package store

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"testing"
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

func runMigrationProcessHelper() {
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
