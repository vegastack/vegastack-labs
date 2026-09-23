package r2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetentionClientAcceptsCloudflareEnvelopeAndBindsObservedRuleCount(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/accounts/account-a/r2/buckets/bucket-a/lock" || request.Header.Get("Authorization") != "Bearer observer-secret" {
			t.Fatalf("unexpected request %s auth=%q", request.URL.Path, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"success":true,"errors":[],"messages":[],"result":{"rules":[` +
			`{"id":"rule-e","prefix":"critical/gen-a/index/","enabled":true,"condition":{"type":"Indefinite"}},` +
			`{"id":"rule-d","prefix":"critical/gen-a/keys/","enabled":true,"condition":{"type":"Indefinite"}},` +
			`{"id":"rule-c","prefix":"critical/gen-a/snapshots/","enabled":true,"condition":{"type":"Indefinite"}},` +
			`{"id":"rule-b","prefix":"critical/gen-a/data/","enabled":true,"condition":{"type":"Indefinite"}},` +
			`{"id":"rule-a","prefix":"critical/gen-a/config","enabled":true,"condition":{"type":"Indefinite"}}]}}`))
	}))
	defer server.Close()

	observation, err := (RetentionClient{APIBase: server.URL, AccountID: "account-a", Bucket: "bucket-a", Client: server.Client(), Clock: func() time.Time { return now },
		AvailableBytes: 100, AvailablePUTs: 10, AvailableLISTs: 3, RuleCount: 5, RuleLimit: 1000, RetainedGenerations: 2}).Observe(context.Background(), "gen-a", "critical/gen-a", []byte("observer-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !observation.IndefiniteProtection || len(observation.ProtectedRules) != 5 || observation.RuleDigest == "" || !strings.HasSuffix(observation.ProtectedRules[0].Prefix, "/config") {
		t.Fatalf("unexpected observation: %+v", observation)
	}
}

func TestRetentionClientRejectsQualificationRuleCountMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"success":true,"result":{"rules":[]}}`))
	}))
	defer server.Close()
	_, err := (RetentionClient{APIBase: server.URL, AccountID: "account-a", Bucket: "bucket-a", Client: server.Client(), RuleCount: 5}).Observe(context.Background(), "gen-a", "critical/gen-a", []byte("token"))
	if err == nil {
		t.Fatal("mismatched rule count accepted")
	}
}
