//go:build linux

package store

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
)

func TestPendingRecoveryPointProjectionRetainsAuthoritativeBinding(t *testing.T) {
	r, point, _ := seededVerificationPoint(t)
	seedReadGrant(t, r.store, "point-reader", "backup.read", "recovery-point", "points", 1, "active")
	scope, err := NewReadAuthorizer(r.store).AuthorizeRead(context.Background(), identity.Principal{ID: "point-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "backup.read", ResourceKind: "recovery-point", ResourceID: "points"})
	if err != nil {
		t.Fatal(err)
	}
	items, _, err := r.ListRecoveryPoints(context.Background(), scope, "", 2)
	if err != nil || len(items) != 1 {
		t.Fatal("scoped pending point unavailable", err)
	}
	item := items[0]
	if item.PointID != point.PointID || item.PolicyID != point.PolicyID || item.RepositoryID != point.RepositoryID || item.InventoryDigest != point.InventoryDigest || item.VerificationStatus != "pending" {
		t.Fatal("actual point binding omitted or substituted", item)
	}
	scope.ScopeDigest = "foreign"
	if _, _, err = r.ListRecoveryPoints(context.Background(), scope, "", 2); err == nil {
		t.Fatal("projection weakened existing read scope")
	}
}
