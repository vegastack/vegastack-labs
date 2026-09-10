package api

import (
	"bytes"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestCursorExpiresAndCannotCrossScopeQueryEndpointOrRestart(t *testing.T) {
	now := time.Date(2026, 9, 8, 6, 0, 0, 0, time.UTC)
	codec, err := NewCursorCodec(bytes.NewReader(bytes.Repeat([]byte{1}, 32)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	binding := CursorBinding{SchemaMajor: 1, EndpointID: "api.v1.inventory-drafts.list", QueryDigest: "sha256:query-a", ScopeDigest: "sha256:scope-a", GrantRevision: 7, Snapshot: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	binding.EvaluationAt = now
	token, err := codec.Encode(binding, CursorPosition{SortValues: []string{"2026-09-08T06:00:00Z"}, ImmutableID: "draft-test-1:1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range []CursorBinding{
		{SchemaMajor: 1, EndpointID: "api.v1.inventory-draft-assets.list", QueryDigest: binding.QueryDigest, ScopeDigest: binding.ScopeDigest, GrantRevision: 7, Snapshot: binding.Snapshot},
		{SchemaMajor: 1, EndpointID: binding.EndpointID, QueryDigest: "sha256:query-b", ScopeDigest: binding.ScopeDigest, GrantRevision: 7, Snapshot: binding.Snapshot},
		{SchemaMajor: 1, EndpointID: binding.EndpointID, QueryDigest: binding.QueryDigest, ScopeDigest: "sha256:scope-b", GrantRevision: 8, Snapshot: binding.Snapshot},
		{SchemaMajor: 1, EndpointID: binding.EndpointID, QueryDigest: binding.QueryDigest, ScopeDigest: binding.ScopeDigest, GrantRevision: 7, Snapshot: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 3}},
		{SchemaMajor: 1, EndpointID: binding.EndpointID, QueryDigest: binding.QueryDigest, ScopeDigest: binding.ScopeDigest, GrantRevision: 7, Snapshot: binding.Snapshot, EvaluationAt: now.Add(time.Second)},
	} {
		if _, err := codec.Decode(token, changed); apiErrorCode(err) != "STATE_CONFLICT" {
			t.Fatalf("cross-binding error = %v", err)
		}
	}
	decoded, err := codec.Decode(token, binding)
	if err != nil || !decoded.EvaluationAt.Equal(now) {
		t.Fatalf("evaluation time = %v, %v", decoded.EvaluationAt, err)
	}
	tampered := token[:len(token)-1] + "A"
	if tampered == token {
		tampered = token[:len(token)-1] + "B"
	}
	if _, err := codec.Decode(tampered, binding); apiErrorCode(err) != "STATE_CONFLICT" {
		t.Fatalf("tampered error = %v", err)
	}
	now = now.Add(CursorLifetime + time.Second)
	if _, err := codec.Decode(token, binding); apiErrorCode(err) != "STATE_CONFLICT" {
		t.Fatalf("expired error = %v", err)
	}
	restarted, err := NewCursorCodec(bytes.NewReader(bytes.Repeat([]byte{2}, 32)), func() time.Time { return now.Add(-time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Decode(token, binding); apiErrorCode(err) != "STATE_CONFLICT" {
		t.Fatalf("restart error = %v", err)
	}
}

func TestCursorRejectsShortEntropyAndMalformedTokens(t *testing.T) {
	if _, err := NewCursorCodec(bytes.NewReader([]byte("short")), time.Now); apiErrorCode(err) != "DEPENDENCY_UNAVAILABLE" {
		t.Fatalf("short entropy error = %v", err)
	}
	codec, err := NewCursorCodec(bytes.NewReader(bytes.Repeat([]byte{3}, 32)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	binding := CursorBinding{SchemaMajor: 1, EndpointID: "api.v1.inventory-drafts.list", QueryDigest: "q", ScopeDigest: "s", GrantRevision: 1}
	for _, token := range []string{"", "%%%", string(bytes.Repeat([]byte("a"), MaxCursorBytes+1))} {
		if _, err := codec.Decode(token, binding); apiErrorCode(err) != "STATE_CONFLICT" {
			t.Fatalf("token error = %v", err)
		}
	}
}
