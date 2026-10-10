package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func TestNativeRecoveryRejectsFrozenOrUnrestoredReplacement(t *testing.T) {
	for _, mode := range []string{"frozen", "unrestored", "wrong-execution"} {
		t.Run(mode, func(t *testing.T) {
			s := portableDiscoveryStore(t)
			ctx := context.Background()
			tx, err := s.conn.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			c := testHostReplacementContinuity(t)
			if err := mergeReplacementContinuity(ctx, tx, c); err != nil {
				t.Fatal(err)
			}
			event := c.Events[0]
			request := c.Drafts[0].Request
			request.Operation = "commit"
			e := NativeProducerExecution{Reference: generated.NativeProducerReference{HostID: request.NewHostID, RunID: event.Execution.RunID, StepID: event.Execution.StepID, LeaseID: event.Execution.LeaseID}, Plan: generated.Plan{PlanID: event.Execution.PlanID, PlanDigest: event.Execution.PlanDigest, HostReplacement: &request}, Receipt: generated.ExecutionReceipt{Status: "succeeded"}}
			if mode != "frozen" {
				event.Sequence++
				event.Type = "committed"
				event.State.Status = "committed"
				id := "absent-restore-plan"
				event.State.RestorePlanID = &id
				if mode == "wrong-execution" {
					event.Execution.RunID = "other-run"
				}
				raw, _ := json.Marshal(event)
				_, err = tx.ExecContext(ctx, `INSERT INTO host_replacement_events VALUES(?,?,?,?,?,?,?,?,?,?,?)`, event.ReplacementID, event.Sequence, event.Type, request.OldHostID, request.OldIdentityDigest, request.NewHostID, request.NewIdentityDigest, hostaction.Digest(event), raw, 0, 0)
				if err != nil {
					t.Fatal(err)
				}
			}
			q := nativeQuery{tx: ReadTx{handle: tx}, row: func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }, rows: func(q string, a ...any) (*sql.Rows, error) { return tx.QueryContext(ctx, q, a...) }}
			if proof, err := NewGateRepository(s).nativeReplacementRecoveryEvidence(ctx, q, e); err == nil || proof != nil {
				t.Fatalf("incomplete stored recovery qualified: %+v %v", proof, err)
			}
		})
	}
}
