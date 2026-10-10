//go:build linux

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"
)

func TestNativeSetupAuthorityUsesActualInitializerAudit(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	now := time.Now().UTC().Truncate(time.Second)
	cfg.Clock = func() time.Time { return now }
	setup := setupFixture(t, cfg.DatabasePath, cfg.ExpectedUID, now)
	var review InitialSetupReview
	if json.Unmarshal(setup.ReviewJSON, &review) != nil {
		t.Fatal("invalid setup fixture")
	}
	review.Acknowledgement.Method = "slack-socket-mode"
	setup.ReviewJSON, _ = json.Marshal(review)
	setup.ReviewDigest = initialSetupDigest(setup.ReviewJSON)
	setup.Approval.Method = "slack-socket-mode"
	setup.Approval.ReviewDigest = setup.ReviewDigest
	cfg.InitialSetup = &setup
	s, e := Open(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	tx, e := s.conn.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	q := nativeQuery{tx: ReadTx{handle: tx}, row: func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }, rows: func(q string, a ...any) (*sql.Rows, error) { return tx.QueryContext(ctx, q, a...) }}
	v, e := readNativeControlSetupAuthority(ctx, q, 0)
	if e != nil || v == nil || v.SetupID != setup.SetupID || v.ReviewDigest != setup.ReviewDigest || v.RequestDigest != setup.RequestDigest || v.HumanID != setup.HumanID || v.InitialEventID <= 0 || v.InitialChainDigest == "" {
		t.Fatalf("actual initializer lineage: %+v %v", v, e)
	}
	if _, e = readNativeControlSetupAuthority(ctx, q, 1); e == nil {
		t.Fatal("stale producer epoch accepted")
	}
	if _, e = tx.ExecContext(ctx, `UPDATE system_meta SET recovery_epoch=1,instance_id='instance-unverified' WHERE id=1`); e != nil {
		t.Fatal(e)
	}
	if _, e = readNativeControlSetupAuthority(ctx, q, 1); e == nil {
		t.Fatal("unverified instance substitution accepted")
	}
}
