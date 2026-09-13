//go:build linux

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestPhase4AcceptancePlanTransactionCrashAndRestart(t *testing.T) {
	config := testConfig(t)
	config.Clock = func() time.Time { return time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC) }
	authority, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	declarations := NewDeclarationRepository(authority)
	draft, err := declarations.CreateRevision(context.Background(), validDeclarationStoreRequest())
	if err != nil {
		t.Fatal(err)
	}
	request := validPlanStoreRequest(draft.Document)
	plans := NewPlanRepository(authority)
	plans.testFailBeforePlanInsert = func() error { return errors.New("injected acceptance crash") }
	if _, err := plans.CommitDeclarationAndPlan(context.Background(), request); err == nil {
		t.Fatal("injected plan transaction crash succeeded")
	}
	if _, err := plans.GetPlan(context.Background(), request.Plan.PlanID); Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("crashed plan remained visible: %v", err)
	}
	if _, err := declarations.GetRevision(context.Background(), draft.Document.DeclarationID, draft.Document.Revision+1); Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("crashed desired declaration remained visible: %v", err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}

	config.Mode = OpenExisting
	authority, err = Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	plans = NewPlanRepository(authority)
	created, err := plans.CommitDeclarationAndPlan(context.Background(), request)
	if err != nil || !created.Created {
		t.Fatalf("clean restart plan commit = %#v, %v", created, err)
	}
	replayed, err := plans.CommitDeclarationAndPlan(context.Background(), request)
	if err != nil || replayed.Created || string(replayed.Canonical) != string(created.Canonical) {
		t.Fatalf("exact plan replay = %#v, %v", replayed, err)
	}
}
