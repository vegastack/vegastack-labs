//go:build linux

package run

import (
	"context"
	"errors"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestPhase4AcceptanceAuthorizationBranchesAndAmbiguousRestart(t *testing.T) {
	t.Run("human proof is single-use and exact replay is inert", func(t *testing.T) {
		fixture := newSQLiteRestartFixture(t, string(authorization.BranchHuman))
		completed, err := fixture.engine.Submit(context.Background(), fixture.request)
		if err != nil || completed.Status != generated.RunStatusSucceeded || fixture.adapter.callCount() != 1 {
			t.Fatalf("human run = %#v, calls=%d, err=%v", completed, fixture.adapter.callCount(), err)
		}
		replayed, err := fixture.engine.Submit(context.Background(), fixture.request)
		if err != nil || replayed.RunID != completed.RunID || fixture.adapter.callCount() != 1 {
			t.Fatalf("human replay = %#v, calls=%d, err=%v", replayed, fixture.adapter.callCount(), err)
		}
		second := fixture.request
		second.Reference.IdempotencyKey = "acceptance-second-human-run"
		if _, err := fixture.engine.Submit(context.Background(), second); err == nil || fixture.adapter.callCount() != 1 {
			t.Fatalf("single-use proof admitted second run: calls=%d, err=%v", fixture.adapter.callCount(), err)
		}
	})

	t.Run("ambiguous effect restart never repeats work", func(t *testing.T) {
		fixture := newSQLiteRestartFixture(t, string(authorization.BranchPreauthorized))
		fixture.engine.testAfterBoundary = func(boundary Boundary) error {
			if boundary == BoundaryEffectReturned {
				return errors.New("injected acceptance crash")
			}
			return nil
		}
		if _, err := fixture.engine.Submit(context.Background(), fixture.request); err == nil {
			t.Fatal("injected ambiguous boundary succeeded")
		}
		restarted := fixture.restart(t)
		if err := restarted.Startup(context.Background()); err != nil {
			t.Fatal(err)
		}
		partial, err := restarted.Get(context.Background(), fixture.runID())
		if err != nil || partial.Status != generated.RunStatusPartial || partial.VerificationStatus != "incomplete" || fixture.adapter.callCount() != 1 {
			t.Fatalf("ambiguous restart = %#v, calls=%d, err=%v", partial, fixture.adapter.callCount(), err)
		}
		if _, err := restarted.Resume(context.Background(), partial.RunID); Code(err) != generated.ErrorCodeRecoveryRequired || fixture.adapter.callCount() != 1 {
			t.Fatalf("ambiguous resume repeated effect: calls=%d, err=%v", fixture.adapter.callCount(), err)
		}
	})
}
