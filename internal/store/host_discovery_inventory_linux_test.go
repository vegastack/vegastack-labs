//go:build linux

package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"slices"
	"testing"
)

func TestDiscoveryInventoryMismatchAndScope(t *testing.T) {
	s := newInventoryTestStore(t)
	repo, request := seedAppliedDiscoveryFixture(t, s)
	ctx := discoveryPrincipalContext()
	inventoryReq := inventoryPutRequest(hostdiscovery.Digest("inventory"), inventory.DraftValid)
	saved, err := NewInventoryDraftRepository(s).Put(context.Background(), inventoryReq)
	if err != nil {
		t.Fatal(err)
	}
	target := discoveryFixtureTarget(t)
	target.Revision = 2
	target.InventoryDraftID = new(string(saved.Ref.ID))
	target.InventoryDraftRevision = int64(saved.Ref.Revision)
	target.AssetID = new("asset-a")
	draftReq := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", ExpectedTargetRevision: 1, ExpectedStateRevision: 1, IdempotencyKey: "linked-draft"}
	if _, err := repo.StageDraft(ctx, draftReq, request.Attribution); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("unreadable inventory reference accepted: %v", err)
	}
	var denied int
	if err := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events WHERE event_type='host.discovery.failed'`).Scan(&denied); err != nil || denied != 1 {
		t.Fatalf("missing inventory denial audit: %d %v", denied, err)
	}
	seedReadGrant(t, s, "operator-a", "inventory.draft.read", "inventory-draft", string(saved.Ref.ID)+":1", 1, "active")
	draft, err := repo.StageDraft(ctx, draftReq, request.Attribution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(ctx, `INSERT INTO host_discovery_targets VALUES('candidate-a',2,?,'active','fixture-plan',0)`, draft.ID); err != nil {
		t.Fatal(err)
	}
	request.Request.TargetRevision = 2
	request.Request.ExpectedStateRevision = 1
	attempt, err := repo.Begin(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	fact := hostdiscovery.Fact("product-serial", "different-serial", "product-serial")
	fact.CapturedAt = "2026-09-08T12:00:00Z"
	observed, err := repo.Complete(ctx, hostdiscovery.CompleteRequest{Attempt: attempt, Attribution: request.Attribution, Collection: hostdiscovery.Collection{Facts: hostdiscovery.Facts{fact}}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(observed.Blockers, "inventory-identity-mismatch") {
		t.Fatal("linked inventory mismatch ignored")
	}
}
