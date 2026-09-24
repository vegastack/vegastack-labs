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
	{name: "credential-lifecycle", declarationType: "credential.lifecycle", operationType: "credential.rotate", adapterID: "core.credential", branch: string(authorization.BranchHuman), idempotent: false, sameDigest: true, extensions: []string{"x-credential-lifecycle"}},
	{name: "backup-create", declarationType: "backup.creation", operationType: "backup.local.create", adapterID: "local.backup", branch: string(authorization.BranchPreauthorized), idempotent: true},
	{name: "backup-verify", declarationType: "backup.verification", operationType: "backup.local.verify", adapterID: "local.backup", branch: string(authorization.BranchPreauthorized), idempotent: true},
	{name: "local-retire", declarationType: "backup.retirement", operationType: "backup.local.retire", adapterID: "local.retention", branch: string(authorization.BranchHuman), idempotent: false, extensions: []string{"x-backup-local-retirement", "x-credential-bindings"}},
	{name: "offsite-copy", declarationType: "backup.offsite", operationType: "backup.offsite.copy", adapterID: "labs.r2-offsite", branch: string(authorization.BranchHuman), idempotent: false, extensions: []string{"x-credential-bindings", "x-offsite-generation"}},
	{name: "offsite-retire", declarationType: "backup.offsite-retirement", operationType: "backup.retire.offsite", adapterID: "r2.retention", branch: string(authorization.BranchHuman), idempotent: false, extensions: []string{"x-backup-offsite-retirement", "x-credential-bindings"}},
	{name: "audit-checkpoint", declarationType: "audit.checkpoint", operationType: "audit.checkpoint.anchor", adapterID: "core.audit", branch: string(authorization.BranchHuman), idempotent: false, sameDigest: true},
	// restore-promote exercises the first executable post-promotion authority
	// seam. recovery.restore.cutover is deliberately not an Engine core effect.
	{name: "restore-promote", declarationType: "recovery.canary", operationType: "recovery.canary.noop", adapterID: "core.recovery", branch: string(authorization.BranchHuman), idempotent: true, sameDigest: true},
	{name: "schedule-occurrence", declarationType: "schedule.observation", operationType: "schedule.observation.refresh", adapterID: "core.schedule-observe", branch: string(authorization.BranchPreauthorized), idempotent: true, sameDigest: true},
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
				fixture := newSQLiteRestartFixtureForOperation(t, operation.branch, operation)
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
					if operation.branch == string(authorization.BranchHuman) {
						current, err = restarted.Submit(context.Background(), fixture.request)
					} else {
						current, err = restarted.Resume(context.Background(), current.RunID)
					}
				case "after-intent", "after-effect", "after-receipt":
					if current.Status != "partial" {
						t.Fatalf("ambiguous status=%q", current.Status)
					}
					calls := fixture.effectCount()
					if _, resumeErr := restarted.Resume(context.Background(), current.RunID); Code(resumeErr) != generated.ErrorCodeRecoveryRequired {
						t.Fatalf("ambiguous resume code=%q err=%v", Code(resumeErr), resumeErr)
					}
					if fixture.effectCount() != calls {
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
				before := fixture.effectCount()
				replayed, replayErr := restarted.Submit(context.Background(), fixture.request)
				if replayErr != nil || replayed.RunID != current.RunID || fixture.effectCount() != before {
					t.Fatalf("exact replay changed durable result: run=%s calls=%d->%d err=%v", replayed.RunID, before, fixture.effectCount(), replayErr)
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
	var storedOperation, storedAdapter, storedStatus, effectState, declarationType string
	if err := database.QueryRow(`SELECT COUNT(*), MIN(status) FROM plan_runs WHERE run_id=?`, current.RunID).Scan(&runs, &storedStatus); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*), MIN(operation_type), MIN(adapter_id), MIN(effect_state) FROM plan_run_steps WHERE run_id=?`, current.RunID).Scan(&steps, &storedOperation, &storedAdapter, &effectState); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT declaration_type FROM declaration_revisions WHERE declaration_id=? AND status='committed'`, fixture.plan.DeclarationID).Scan(&declarationType); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM execution_receipts WHERE run_id=?`, current.RunID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || steps != 1 || storedOperation != operation.operationType || storedAdapter != operation.adapterID || declarationType != operation.declarationType || storedStatus != current.Status || effectState != current.Steps[0].EffectState {
		t.Fatalf("authority mismatch at %s: runs=%d steps=%d declaration=%q operation=%q adapter=%q status=%q effect=%q", boundary, runs, steps, declarationType, storedOperation, storedAdapter, storedStatus, effectState)
	}
	wantReceipts := 0
	if boundary == "before-intent" || boundary == "after-receipt" || boundary == "before-settlement" || boundary == "concurrent" {
		wantReceipts = 1
	}
	if boundary == "before-intent" && operation.branch == string(authorization.BranchHuman) {
		// Human acknowledgement was consumed before the injected pre-intent
		// stop, so restart preserves interruption instead of reusing the proof.
		wantReceipts = 0
	}
	if receipts != wantReceipts {
		t.Fatalf("receipt count at %s=%d, want %d", boundary, receipts, wantReceipts)
	}
	wantEffects := 1
	if boundary == "after-intent" {
		wantEffects = 0
	}
	if boundary == "before-intent" && operation.branch == string(authorization.BranchHuman) {
		wantEffects = 0
	}
	if fixture.effectCount() != wantEffects {
		t.Fatalf("effect count at %s=%d, want %d", boundary, fixture.effectCount(), wantEffects)
	}
}
