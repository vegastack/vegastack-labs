//go:build linux

package run

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

var phase5DurableOperations = []phase5OperationBinding{
	{name: "credential-lifecycle", operationType: "phase5.credential-lifecycle"},
	{name: "backup-create", operationType: "phase5.backup-create"},
	{name: "backup-verify", operationType: "phase5.backup-verify"},
	{name: "local-retire", operationType: "phase5.local-retire"},
	{name: "offsite-copy", operationType: "phase5.offsite-copy"},
	{name: "offsite-retire", operationType: "phase5.offsite-retire"},
	{name: "audit-checkpoint", operationType: "phase5.audit-checkpoint"},
	{name: "restore-promote", operationType: "phase5.restore-promote"},
	{name: "schedule-occurrence", operationType: "phase5.schedule-occurrence"},
}

var phase5FaultBoundaries = []struct {
	name   string
	engine Boundary
}{
	{name: "before-intent", engine: BoundaryLeaseAcquired},
	{name: "after-intent", engine: BoundaryIntentRecorded},
	{name: "after-effect", engine: BoundaryEffectReturned},
	{name: "after-receipt", engine: BoundaryReceiptRecorded},
	{name: "before-settlement", engine: BoundaryVerified},
}

// TestPhase5AcceptanceDurableFaultMatrix composes the real plan/run engine,
// SQLite authority, durable intent/receipt tables and adapter boundary for each
// Phase 5 effect family. Reopening the database is part of every case; an
// in-memory result cannot satisfy this selector.
func TestPhase5AcceptanceDurableFaultMatrix(t *testing.T) {
	for _, operation := range phase5DurableOperations {
		operation := operation
		for _, boundary := range phase5FaultBoundaries {
			boundary := boundary
			t.Run(operation.name+"/"+boundary.name, func(t *testing.T) {
				fixture := newSQLiteRestartFixtureForOperation(t, string(authorization.BranchPreauthorized), operation)
				fixture.engine.testAfterBoundary = func(got Boundary) error {
					if got == boundary.engine {
						return errors.New("phase5 injected process stop")
					}
					return nil
				}
				if _, err := fixture.engine.Submit(context.Background(), fixture.request); err == nil {
					t.Fatalf("%s crossed injected %s boundary", operation.name, boundary.name)
				}

				restarted := fixture.restart(t)
				if err := restarted.Startup(context.Background()); err != nil {
					t.Fatal(err)
				}
				current, err := restarted.Get(context.Background(), fixture.runID())
				if err != nil {
					t.Fatal(err)
				}
				switch boundary.name {
				case "before-intent":
					if current.Status != "interrupted" {
						t.Fatalf("pre-intent status=%q", current.Status)
					}
					current, err = restarted.Resume(context.Background(), current.RunID)
				case "after-intent", "after-effect", "after-receipt":
					if current.Status != "partial" {
						t.Fatalf("ambiguous status=%q", current.Status)
					}
					calls := fixture.adapter.callCount()
					if _, resumeErr := restarted.Resume(context.Background(), current.RunID); Code(resumeErr) != generated.ErrorCodeRecoveryRequired {
						t.Fatalf("ambiguous resume code=%q err=%v", Code(resumeErr), resumeErr)
					}
					if fixture.adapter.callCount() != calls {
						t.Fatal("ambiguous recovery repeated an external effect")
					}
				case "before-settlement":
					if current.Status != "succeeded" || current.VerificationStatus != "verified" {
						t.Fatalf("verified state was not recovered: %#v", current)
					}
				}
				if err != nil {
					t.Fatal(err)
				}

				assertPhase5AuthoritativeRunState(t, fixture, operation, boundary.name, current)
				before := fixture.adapter.callCount()
				replayed, replayErr := restarted.Submit(context.Background(), fixture.request)
				if replayErr != nil || replayed.RunID != current.RunID || fixture.adapter.callCount() != before {
					t.Fatalf("exact replay changed durable result: run=%s calls=%d->%d err=%v", replayed.RunID, before, fixture.adapter.callCount(), replayErr)
				}
			})
		}
	}
}

func assertPhase5AuthoritativeRunState(t *testing.T, fixture *sqliteRestartFixture, operation phase5OperationBinding, boundary string, current generated.Run) {
	t.Helper()
	database, err := sql.Open("sqlite3", fixture.config.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var runs, steps, receipts int
	var storedOperation, storedStatus, effectState string
	if err := database.QueryRow(`SELECT COUNT(*), MIN(status) FROM plan_runs WHERE run_id=?`, current.RunID).Scan(&runs, &storedStatus); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*), MIN(operation_type), MIN(effect_state) FROM plan_run_steps WHERE run_id=?`, current.RunID).Scan(&steps, &storedOperation, &effectState); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM execution_receipts WHERE run_id=?`, current.RunID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || steps != 1 || storedOperation != operation.operationType || storedStatus != current.Status || effectState != current.Steps[0].EffectState {
		t.Fatalf("authority mismatch at %s: runs=%d steps=%d operation=%q status=%q effect=%q", boundary, runs, steps, storedOperation, storedStatus, effectState)
	}
	wantReceipts := 0
	if boundary == "before-intent" || boundary == "after-receipt" || boundary == "before-settlement" || boundary == "concurrent" {
		wantReceipts = 1
	}
	if receipts != wantReceipts {
		t.Fatalf("receipt count at %s=%d, want %d", boundary, receipts, wantReceipts)
	}
	wantEffects := 1
	if boundary == "after-intent" {
		wantEffects = 0
	}
	if fixture.adapter.callCount() != wantEffects {
		t.Fatalf("effect count at %s=%d, want %d", boundary, fixture.adapter.callCount(), wantEffects)
	}
}
