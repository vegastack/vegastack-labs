//go:build linux

package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
)

type failingSourceObserver struct{}

func (failingSourceObserver) Observe(context.Context, readmodel.SourceID) (readmodel.SourceObservation, error) {
	return readmodel.SourceObservation{}, errors.New("provider response super-secret")
}

func TestSourceRepositoryProjectsLocalStateAndIsolatesOptionalFailure(t *testing.T) {
	s := newInventoryTestStore(t)
	seedReadGrant(t, s, "principal-source-reader", "platform.source.read", "platform-source", "", 1, "active")
	scope, err := NewReadAuthorizer(s).AuthorizeRead(context.Background(), identity.Principal{ID: "principal-source-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "platform.source.read", ResourceKind: "platform-source"})
	if err != nil {
		t.Fatal(err)
	}
	repository := NewSourceRepository(s, failingSourceObserver{})
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
}

func TestSourceRepositoryEnforcesResourceScopeAndPagination(t *testing.T) {
	s := newInventoryTestStore(t)
	seedReadGrant(t, s, "principal-source-reader", "platform.source.read", "platform-source", "database", 2, "active")
	seedReadGrant(t, s, "principal-source-reader", "platform.source.read", "platform-source", "nodes", 2, "active")
	scope, err := NewReadAuthorizer(s).AuthorizeRead(context.Background(), identity.Principal{ID: "principal-source-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "platform.source.read", ResourceKind: "platform-source"})
	if err != nil {
		t.Fatal(err)
	}
	repository := NewSourceRepository(s, nil)
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
