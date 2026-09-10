package api

import (
	"net/url"
	"testing"
)

func TestQueryDecoderRejectsUnknownDuplicateAndOverflow(t *testing.T) {
	decoder := NewQueryDecoder()
	spec := QuerySpec{EndpointID: "api.v1.inventory-drafts.list", AllowedFilters: []string{"status"}, AllowedSorts: []string{"created-at-asc", "created-at-desc"}, DefaultSort: "created-at-asc"}
	got, err := decoder.Decode(url.Values{"status": {"valid"}}, spec)
	if err != nil || got.Limit != DefaultPageLimit || got.Sort != "created-at-asc" || got.FilterDigest == "" {
		t.Fatalf("query = (%#v, %v)", got, err)
	}
	for _, values := range []url.Values{{"unknown": {"x"}}, {"status": {"valid", "blocked"}}, {"limit": {"201"}}, {"limit": {"01"}}, {"sort": {"created-at-sideways"}}} {
		if _, err := decoder.Decode(values, spec); apiErrorCode(err) != "INPUT_INVALID" {
			t.Fatalf("values %#v error = %v", values, err)
		}
	}
}

func TestSourceListQueryRejectsUnknownSourceAndState(t *testing.T) {
	decoder := NewQueryDecoder()
	spec := QuerySpec{EndpointID: "api.v1.sources.list", AllowedFilters: []string{"source", "state"}, AllowedSorts: []string{"id-asc", "id-desc"}, DefaultSort: "id-asc"}
	for _, values := range []url.Values{{"source": {"cloudflare"}}, {"state": {"green"}}} {
		decoded, err := decoder.Decode(values, spec)
		if err == nil {
			_, err = sourceListQuery(decoded)
		}
		if apiErrorCode(err) != "INPUT_INVALID" {
			t.Fatalf("values %#v error = %v", values, err)
		}
	}
	decoded, err := decoder.Decode(url.Values{"source": {"nodes"}, "state": {"stale"}}, spec)
	if err != nil {
		t.Fatal(err)
	}
	query, err := sourceListQuery(decoded)
	if err != nil || query.Source != "nodes" || query.State != "stale" {
		t.Fatalf("query = %#v, %v", query, err)
	}
}
