//go:build linux

package localbackup

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestReplacementWatermarkReadsActualSnapshotOrdinal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		schema int
		table  bool
		want   int64
		fail   bool
	}{{"legacy", 32, false, 0, false}, {"missing", 33, false, 0, true}, {"present", 33, true, 7, false}, {"unexpected", 32, true, 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "snapshot.db")
			db, e := sql.Open("sqlite3", path)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec(`CREATE TABLE schema_migrations(id INTEGER PRIMARY KEY)`); e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec(`INSERT INTO schema_migrations(id) VALUES(?)`, tc.schema); e != nil {
				t.Fatal(e)
			}
			if tc.table {
				if _, e = db.Exec(`CREATE TABLE host_alias_history(event_ordinal INTEGER PRIMARY KEY); INSERT INTO host_alias_history VALUES(7)`); e != nil {
					t.Fatal(e)
				}
			}
			if e = db.Close(); e != nil {
				t.Fatal(e)
			}
			got, e := readRestoredAliasWatermark(context.Background(), path)
			if (e != nil) != tc.fail || !tc.fail && got != tc.want {
				t.Fatalf("%d %v", got, e)
			}
		})
	}
}
