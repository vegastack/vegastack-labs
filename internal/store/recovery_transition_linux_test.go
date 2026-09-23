//go:build linux

package store

import (
	"context"
	"database/sql"
	"testing"
)

func TestRecoveryRequiredReopenRemainsReadOnlyAndRetainsDistinctInstances(t *testing.T) {
	cfg := testConfig(t)
	authority, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var former string
	if err := authority.conn.QueryRowContext(context.Background(), `SELECT instance_id FROM system_meta WHERE id=1`).Scan(&former); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(context.Background(), `INSERT INTO audit_instances(instance_id,created_at) VALUES('instance-replacement-a','2026-09-24T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(context.Background(), `UPDATE system_meta SET instance_id='instance-replacement-a',recovery_epoch=1,authority_mode='recovery-required' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Mode = OpenExisting
	reopened, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	health, err := reopened.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !health.RecoveryPending || health.MutationEnabled || health.SafeModeReason != "recovery-required" || health.Revision.RecoveryEpoch != 1 {
		t.Fatalf("health=%#v", health)
	}
	if _, err := reopened.WriteIntent(context.Background(), nil, func(IntentTx) error { return nil }); Code(err) != "PREREQUISITE_BLOCKED" {
		t.Fatalf("write code=%s", Code(err))
	}
	prior := RevisionToken{StateRevision: health.Revision.StateRevision, RecoveryEpoch: 0}
	if _, err := reopened.WriteIntent(context.Background(), &prior, func(IntentTx) error { return nil }); Code(err) != "RECOVERY_EPOCH_MISMATCH" {
		t.Fatalf("old epoch write code=%s", Code(err))
	}
	request := publicIntentRequest(t, "9", nil)
	request.Expected = &prior
	if _, err := reopened.writeIntent(context.Background(), request, func(context.Context, *sql.Tx) error { return nil }); Code(err) != "RECOVERY_EPOCH_MISMATCH" {
		t.Fatalf("old epoch audited write code=%s", Code(err))
	}
	var count int
	if err := reopened.conn.QueryRowContext(context.Background(), `SELECT COUNT(1) FROM audit_instances WHERE instance_id IN (?,?)`, former, "instance-replacement-a").Scan(&count); err != nil || count != 2 {
		t.Fatalf("instances=%d err=%v", count, err)
	}
}
