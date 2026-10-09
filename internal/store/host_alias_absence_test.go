package store

import (
	"context"
	"testing"
)

func TestReplacementEmptyHistoryCannotStandForRecoveredAuthority(t *testing.T) {
	for _, mode := range []string{"original", "recovery-required", "recovered-ready", "orphan-freeze"} {
		t.Run(mode, func(t *testing.T) {
			s := portableDiscoveryStore(t)
			ctx := context.Background()
			switch mode {
			case "recovery-required":
				if _, err := s.conn.ExecContext(ctx, `UPDATE system_meta SET recovery_epoch=1,authority_mode='recovery-required' WHERE id=1`); err != nil {
					t.Fatal(err)
				}
			case "recovered-ready":
				if _, err := s.conn.ExecContext(ctx, `UPDATE system_meta SET recovery_epoch=1 WHERE id=1`); err != nil {
					t.Fatal(err)
				}
			case "orphan-freeze":
				c := testHostReplacementContinuity(t)
				tx, err := s.conn.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = insertReplacementEvent(ctx, tx, c.Events[0]); err != nil {
					tx.Rollback()
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			n, err := s.HostAliasHighWatermark(ctx)
			if err != nil || n != 0 {
				t.Fatalf("watermark %d %v", n, err)
			}
			err = s.VerifyOriginalEmptyHostAuthority(ctx)
			if (err == nil) != (mode == "original") {
				t.Fatalf("mode %s absence result %v", mode, err)
			}
		})
	}
}
