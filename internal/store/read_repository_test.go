//go:build linux

package store

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
)

func TestScopedDraftPageCannotLeakAnotherGrantAndIsStableAcrossInsert(t *testing.T) {
	s := newInventoryTestStore(t)
	repo := NewInventoryDraftRepository(s)
	firstRequest := inventoryPutRequest("sha256:"+strings.Repeat("1", 64), inventory.DraftValid)
	firstRequest.DraftID = "draft-allowed-a"
	firstRequest.Event.Target.ID = string(firstRequest.DraftID)
	first, err := repo.Put(context.Background(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	deniedRequest := inventoryPutRequest("sha256:"+strings.Repeat("2", 64), inventory.DraftValid)
	deniedRequest.DraftID = "draft-denied"
	deniedRequest.Event.Target.ID = string(deniedRequest.DraftID)
	deniedRequest.Draft.Candidate.Source.SourceRevision = "source-denied"
	if _, err := repo.Put(context.Background(), deniedRequest); err != nil {
		t.Fatal(err)
	}
	seedReadGrant(t, s, "principal-reader", "inventory.draft.read", "inventory-draft", authorization.ResourceID(first.Ref), 1, "active")
	scope, err := NewReadAuthorizer(s).AuthorizeRead(context.Background(), identity.Principal{ID: "principal-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "inventory.draft.read", ResourceKind: "inventory-draft"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := s.health.Revision
	reads := NewReadRepository(s)
	page, err := reads.ListDrafts(context.Background(), scope, inventory.DraftListQuery{Limit: 1}, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	concurrent := inventoryPutRequest("sha256:"+strings.Repeat("3", 64), inventory.DraftValid)
	concurrent.DraftID = "draft-concurrent"
	concurrent.Event.Target.ID = string(concurrent.DraftID)
	concurrent.Draft.Candidate.Source.SourceRevision = "source-concurrent"
	if _, err := repo.Put(context.Background(), concurrent); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Ref != first.Ref || page.HasMore {
		t.Fatalf("scoped page = %#v", page)
	}
}

func TestReadRepositoryRejectsAlteredScopeBeforeRows(t *testing.T) {
	s := newInventoryTestStore(t)
	reads := NewReadRepository(s)
	_, err := reads.Summary(context.Background(), authorization.ReadScope{PrincipalID: "principal-reader", Capability: "platform.summary.read", ResourceKind: "platform-summary", GrantRevision: 1, ScopeDigest: "sha256:tampered"})
	if Code(err) != "AUTHORIZATION_DENIED" {
		t.Fatalf("error = %v", err)
	}
}
