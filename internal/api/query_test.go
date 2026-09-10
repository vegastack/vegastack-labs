package api

import (
	"errors"
	"net/url"
	"testing"
)

type testCodedAPIError struct{ code string }

func (err testCodedAPIError) Error() string { return "private backend detail" }
func (err testCodedAPIError) Code() string  { return err.code }

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

func TestAPIErrorCodeAcceptsOnlyGeneratedStableCodesFromTypedBackends(t *testing.T) {
	if code := apiErrorCode(testCodedAPIError{code: "AUTHORIZATION_DENIED"}); code != "AUTHORIZATION_DENIED" {
		t.Fatalf("generated code = %q", code)
	}
	if code := apiErrorCode(testCodedAPIError{code: "PRIVATE_BACKEND_DETAIL"}); code != "" {
		t.Fatalf("unknown code escaped = %q", code)
	}
	if code := apiErrorCode(errors.New("private backend detail")); code != "" {
		t.Fatalf("untyped error escaped = %q", code)
	}
}
