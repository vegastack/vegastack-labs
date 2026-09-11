package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
)

const (
	DefaultPageLimit = 50
	MaxPageLimit     = 200
	MaxCursorBytes   = 2048
)

type ValidatedQuery struct {
	Limit        int
	Sort         string
	Filters      map[string]string
	FilterDigest string
	Cursor       string
}

func sourceListQuery(query ValidatedQuery) (readmodel.SourceListQuery, error) {
	result := readmodel.SourceListQuery{Limit: query.Limit, Sort: query.Sort, Source: readmodel.SourceID(query.Filters["source"]), State: readmodel.SourceState(query.Filters["state"])}
	if result.Source != "" && !readmodel.ValidSourceID(result.Source) || result.State != "" && !readmodel.ValidSourceState(result.State) {
		return readmodel.SourceListQuery{}, failure.New(generated.ErrorCodeInputInvalid, "query", false)
	}
	return result, nil
}

type QuerySpec struct {
	EndpointID     string
	AllowedFilters []string
	AllowedSorts   []string
	DefaultSort    string
}

type QueryDecoder interface {
	Decode(url.Values, QuerySpec) (ValidatedQuery, error)
}
type strictQueryDecoder struct{}

func NewQueryDecoder() QueryDecoder { return strictQueryDecoder{} }

func (strictQueryDecoder) Decode(values url.Values, spec QuerySpec) (ValidatedQuery, error) {
	if spec.EndpointID == "" || spec.DefaultSort == "" || !contains(spec.AllowedSorts, spec.DefaultSort) {
		return ValidatedQuery{}, failure.New("INPUT_INVALID", "query", false)
	}
	allowed := map[string]bool{"limit": true, "sort": true, "cursor": true}
	for _, key := range spec.AllowedFilters {
		allowed[key] = true
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 || entries[0] == "" || len(entries[0]) > MaxCursorBytes || !utf8.ValidString(entries[0]) {
			return ValidatedQuery{}, failure.New("INPUT_INVALID", "query", false)
		}
	}
	result := ValidatedQuery{Limit: DefaultPageLimit, Sort: spec.DefaultSort, Filters: make(map[string]string)}
	if raw := values.Get("limit"); raw != "" {
		if raw[0] == '0' || strings.ContainsAny(raw, "+-") {
			return ValidatedQuery{}, failure.New("INPUT_INVALID", "query", false)
		}
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > MaxPageLimit {
			return ValidatedQuery{}, failure.New("INPUT_INVALID", "query", false)
		}
		result.Limit = limit
	}
	if raw := values.Get("sort"); raw != "" {
		if !contains(spec.AllowedSorts, raw) {
			return ValidatedQuery{}, failure.New("INPUT_INVALID", "query", false)
		}
		result.Sort = raw
	}
	result.Cursor = values.Get("cursor")
	keys := append([]string(nil), spec.AllowedFilters...)
	sort.Strings(keys)
	canonical := []string{spec.EndpointID, "limit=" + strconv.Itoa(result.Limit), "sort=" + result.Sort}
	for _, key := range keys {
		if value := values.Get(key); value != "" {
			result.Filters[key] = value
			canonical = append(canonical, key+"="+value)
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(canonical, "\x00")))
	result.FilterDigest = "sha256:" + hex.EncodeToString(sum[:])
	return result, nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func apiErrorCode(err error) string {
	if stable, ok := failure.As(err); ok {
		return stable.Code
	}
	return ""
}
