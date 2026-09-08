package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return Config{
		DatabasePath: filepath.Join(directory, "control.db"),
		Mode:         InitializeNew,
		BusyTimeout:  25 * time.Millisecond,
		ExpectedUID:  uint32(os.Geteuid()),
		ToolVersion:  "test-tool",
		BuildVersion: "test-build",
	}
}

func containsFold(value, fragment string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(fragment))
}

type sqliteSettings struct {
	JournalMode   string
	Synchronous   int
	ForeignKeys   int
	BusyTimeoutMS int
}

func readSettingsForTest(t *testing.T, store *Store) sqliteSettings {
	t.Helper()
	var settings sqliteSettings
	queries := []struct {
		query string
		dest  any
	}{
		{"PRAGMA journal_mode", &settings.JournalMode},
		{"PRAGMA synchronous", &settings.Synchronous},
		{"PRAGMA foreign_keys", &settings.ForeignKeys},
		{"PRAGMA busy_timeout", &settings.BusyTimeoutMS},
	}
	for _, query := range queries {
		if err := store.conn.QueryRowContext(context.Background(), query.query).Scan(query.dest); err != nil {
			t.Fatal(err)
		}
	}
	return settings
}
