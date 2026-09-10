//go:build linux

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
)

func TestSourceRepositoryProjectsLocalStateAndIsolatesOptionalFailure(t *testing.T) {
	s := newInventoryTestStore(t)
	draftRepository := NewInventoryDraftRepository(s)
	request := inventoryPutRequest("sha256:"+strings.Repeat("9", 64), "valid")
	request.DraftID = "draft-source-isolation"
	request.Event.Target.ID = string(request.DraftID)
	draft, err := draftRepository.Put(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range readmodel.SourceIDValues() {
		seedReadGrant(t, s, "principal-source-reader", "platform.source.read", "platform-source", string(id), 1, "active")
	}
	seedReadGrant(t, s, "principal-source-reader", "inventory.draft.read", "inventory-draft", authorization.ResourceID(draft.Ref), 1, "active")
	scope, err := NewReadAuthorizer(s).AuthorizeRead(context.Background(), identity.Principal{ID: "principal-source-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "platform.source.read", ResourceKind: "platform-source"})
	if err != nil {
		t.Fatal(err)
	}
	repository := newSourceRepositoryWithFixtures(s, map[readmodel.SourceID]readmodel.SourceObservation{
		readmodel.SourceBackups: {Available: true, FailureCode: "PROVIDER_RESPONSE_super-secret"},
	})
	page, err := repository.ListSources(context.Background(), scope, readmodel.SourceListQuery{Limit: 7, Sort: "id-asc"}, s.health.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 7 || page.Items[0].ID != readmodel.SourceBackups || page.Items[1].ID != readmodel.SourceDatabase {
		t.Fatalf("sources = %#v", page.Items)
	}
	if sourceStatusByID(t, page.Items, readmodel.SourceDatabase).State == readmodel.SourceUnavailable {
		t.Fatal("database source became unavailable")
	}
	if sourceStatusByID(t, page.Items, readmodel.SourceBackups).State != readmodel.SourceFailed {
		t.Fatalf("backup source = %#v", sourceStatusByID(t, page.Items, readmodel.SourceBackups))
	}
	if encoded := strings.Join(sourceReasons(page.Items), " "); strings.Contains(encoded, "super-secret") || strings.Contains(encoded, "provider response") {
		t.Fatalf("raw source error escaped: %q", encoded)
	}
	inventoryScope, err := NewReadAuthorizer(s).AuthorizeRead(context.Background(), identity.Principal{ID: "principal-source-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "inventory.draft.read", ResourceKind: "inventory-draft"})
	if err != nil {
		t.Fatal(err)
	}
	drafts, err := NewReadRepository(s).ListDrafts(context.Background(), inventoryScope, inventory.DraftListQuery{Limit: 1}, s.health.Revision)
	if err != nil || len(drafts.Items) != 1 || drafts.Items[0].Ref != draft.Ref {
		t.Fatalf("inventory read after optional failure = %#v, %v", drafts, err)
	}
}

func TestSourceRepositoryEnforcesResourceScopeAndPagination(t *testing.T) {
	s := newInventoryTestStore(t)
	seedReadGrant(t, s, "principal-source-reader", "platform.source.read", "platform-source", "database", 2, "active")
	seedReadGrant(t, s, "principal-source-reader", "platform.source.read", "platform-source", "nodes", 2, "active")
	scope, err := NewReadAuthorizer(s).AuthorizeRead(context.Background(), identity.Principal{ID: "principal-source-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "platform.source.read", ResourceKind: "platform-source"})
	if err != nil {
		t.Fatal(err)
	}
	repository := NewSourceRepository(s)
	page, err := repository.ListSources(context.Background(), scope, readmodel.SourceListQuery{Limit: 1, Sort: "id-asc"}, s.health.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != readmodel.SourceDatabase || !page.HasMore || page.Last != readmodel.SourceDatabase {
		t.Fatalf("first page = %#v", page)
	}
	page, err = repository.ListSources(context.Background(), scope, readmodel.SourceListQuery{Limit: 1, Sort: "id-asc", AfterID: page.Last}, s.health.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != readmodel.SourceNodes || page.HasMore {
		t.Fatalf("second page = %#v", page)
	}
	if _, err := repository.ListSources(context.Background(), scope, readmodel.SourceListQuery{Limit: 1, Sort: "id-asc", AfterID: "not-a-source"}, s.health.Revision); Code(err) != generated.ErrorCodeInputInvalid {
		t.Fatalf("invalid cursor source error = %v", err)
	}
}

func TestSourceRepositoryKeepsNodeHealthBoundToTheRequestedSnapshot(t *testing.T) {
	s := newInventoryTestStore(t)
	drafts := NewInventoryDraftRepository(s)
	first := inventoryPutRequest("sha256:"+strings.Repeat("7", 64), "valid")
	first.DraftID = "draft-source-snapshot-one"
	syncInventoryAuditRequest(&first)
	if _, err := drafts.Put(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	snapshot := s.health.Revision

	second := inventoryPutRequest("sha256:"+strings.Repeat("8", 64), "valid")
	second.DraftID = "draft-source-snapshot-two"
	second.Draft.Candidate.Observations[0].ObservedAt = time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	syncInventoryAuditRequest(&second)
	if _, err := drafts.Put(context.Background(), second); err != nil {
		t.Fatal(err)
	}

	seedReadGrant(t, s, "principal-source-snapshot", "platform.source.read", "platform-source", "nodes", 1, "active")
	scope, err := NewReadAuthorizer(s).AuthorizeRead(context.Background(), identity.Principal{ID: "principal-source-snapshot", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "platform.source.read", ResourceKind: "platform-source"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := NewSourceRepository(s).ListSources(context.Background(), scope, readmodel.SourceListQuery{Limit: 1, Sort: "id-asc"}, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	nodes := sourceStatusByID(t, page.Items, readmodel.SourceNodes)
	want := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	if nodes.LastSuccessAt == nil || !nodes.LastSuccessAt.Equal(want) {
		t.Fatalf("snapshot node success = %v, want %v", nodes.LastSuccessAt, want)
	}
}

func sourceStatusByID(t *testing.T, items []readmodel.SourceStatus, id readmodel.SourceID) readmodel.SourceStatus {
	t.Helper()
	for _, item := range items {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("source %q absent", id)
	return readmodel.SourceStatus{}
}

func sourceReasons(items []readmodel.SourceStatus) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.Reason)
	}
	return result
}
