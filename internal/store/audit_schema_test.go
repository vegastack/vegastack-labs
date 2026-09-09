//go:build linux

package store

import (
	"context"
	"slices"
	"testing"
)

func TestAuditRowsAreAppendOnlyAndOutboxShapeIsClosed(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	if _, err := store.conn.ExecContext(ctx, `UPDATE system_meta SET audit_sequence=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.conn.ExecContext(ctx, `INSERT INTO audit_events(event_id,occurred_at,recovery_epoch,state_revision,event_type,correlation_id,principal_id,principal_method,target_kind,target_id,canonical_payload,payload_sha256) VALUES(1,'2026-09-08T00:00:00Z',0,0,'test.event','request-test-1','principal-test-1','local-os-peer','test-target','target-test-1',x'7b7d','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.conn.ExecContext(ctx, `INSERT INTO intent_keys(scope,key_digest,request_digest,event_id,state_revision,recovery_epoch,created_at) VALUES('test-scope','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',1,0,0,'2026-09-08T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.conn.ExecContext(ctx, `UPDATE audit_events SET event_type='changed.event' WHERE event_id=1`); err == nil {
		t.Fatal("audit event update succeeded")
	}
	if _, err := store.conn.ExecContext(ctx, `DELETE FROM intent_keys WHERE scope='test-scope'`); err == nil {
		t.Fatal("intent binding delete succeeded")
	}
	columns := tableColumns(t, store, "outbox")
	for _, forbidden := range []string{"last_error", "provider_response", "path", "raw_error"} {
		if slices.Contains(columns, forbidden) {
			t.Fatalf("unsafe outbox column %q in %v", forbidden, columns)
		}
	}
}

func tableColumns(t *testing.T, store *Store, table string) []string {
	t.Helper()
	rows, err := store.conn.QueryContext(context.Background(), `SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return columns
}
