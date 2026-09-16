//go:build linux

package store

import (
	"context"
	"database/sql"
	"testing"
)

func TestAuditVerificationDegradesWithoutIndependentReaderAndFailsClosedOnTamper(t *testing.T) {
	authority := openAuditTestStore(t)
	if _, err := authority.writeIntent(context.Background(), chainTestIntent(t, 0), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES('verify-business')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	verification, err := authority.VerifyAuditHistory(context.Background(), nil)
	if err != nil || verification.Status != "degraded" || verification.ReasonCode != "no-independent-anchor" {
		t.Fatalf("valid unanchored verification = %#v, %v", verification, err)
	}
	health, err := authority.Health(context.Background())
	if err != nil || !health.MutationEnabled {
		t.Fatalf("unavailable independent reader disabled mutations: %#v, %v", health, err)
	}
	if _, err := authority.conn.ExecContext(context.Background(), `DROP TRIGGER audit_chain_links_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(context.Background(), `UPDATE audit_chain_links SET link_digest=? WHERE event_id=1`, fingerprint("f")); err != nil {
		t.Fatal(err)
	}
	verification, err = authority.VerifyAuditHistory(context.Background(), nil)
	if err == nil || verification.Status != "incident" {
		t.Fatalf("tampered verification = %#v, %v", verification, err)
	}
	health, _ = authority.Health(context.Background())
	if health.Mode != DatabaseSafeMode || health.MutationEnabled || health.SafeModeReason != "audit-incident" {
		t.Fatalf("tamper did not fail closed: %#v", health)
	}
}
