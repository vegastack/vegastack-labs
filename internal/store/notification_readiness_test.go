package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"testing"
)

func TestNotificationReadinessDeniesMissingExecutionApprovalAndReceipts(t *testing.T) {
	s := portableDiscoveryStore(t)
	ctx := context.Background()
	repo := NewNotificationReadinessRepository(s, generated.NotificationReadinessPolicy{TargetID: "route-test"}, generated.OperationsGithubDestination{})
	if _, _, e := repo.Current(ctx, adapter.Operation{}, adapter.ExactExecutionBinding{}); e == nil {
		t.Fatal("missing exact approved execution accepted")
	}
	if _, e := repo.Receipts(ctx, "run-unproven", 0); e == nil {
		t.Fatal("missing provider receipts accepted")
	}
	if _, e := repo.ForEvidence(ctx, "uploaded-unproven", 0); e == nil {
		t.Fatal("missing server evidence accepted")
	}
	var count int
	if e := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_readiness_receipts`).Scan(&count); e != nil || count != 0 {
		t.Fatal(count, e)
	}
	p := generated.Plan{Operations: []generated.PlanOperation{{OperationType: operations.ReadinessOperation, AdapterID: operations.ReadinessAdapter}}}
	if !IsNotificationReadiness(p) {
		t.Fatal("fixed operation not recognized")
	}
	p.Operations = append(p.Operations, p.Operations[0])
	if IsNotificationReadiness(p) {
		t.Fatal("mixed canary recognized")
	}
}

func TestNotificationReadinessRequiresCurrentlyActiveNamedHumans(t *testing.T) {
	s := portableDiscoveryStore(t)
	ctx := context.Background()
	p := generated.NotificationReadinessPolicy{PrimaryHumanID: "primary", SecondaryHumanID: "secondary", PrimaryCredentialOwnerID: "owner-a", SecondaryCredentialOwnerID: "owner-b"}
	repo := NewNotificationReadinessRepository(s, p, generated.OperationsGithubDestination{})
	if e := repo.CheckPolicy(ctx); e == nil {
		t.Fatal("unselected human identities passed")
	}
	for _, id := range []string{"primary", "secondary", "owner-a", "owner-b"} {
		if _, e := s.conn.ExecContext(ctx, `INSERT INTO effective_authorization_principals(principal_id,principal_kind,status,grant_revision,created_at,updated_at) VALUES(?,'human','active',1,'2026-10-28T00:00:00Z','2026-10-28T00:00:00Z')`, id); e != nil {
			t.Fatal(e)
		}
	}
	if e := repo.CheckPolicy(ctx); e != nil {
		t.Fatal("current named humans rejected", e)
	}
	if _, e := s.conn.ExecContext(ctx, `UPDATE effective_authorization_principals SET status='revoked',grant_revision=2 WHERE principal_id='secondary'`); e != nil {
		t.Fatal(e)
	}
	if e := repo.CheckPolicy(ctx); e == nil {
		t.Fatal("revoked recipient retained readiness")
	}
}
