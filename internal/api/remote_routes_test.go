package api

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestRemoteReadAdmissionMatchesGeneratedReadAndSessionEndpoints(t *testing.T) {
	for _, endpoint := range generated.Endpoints {
		requestPath := strings.NewReplacer("{draftId}", "draft-test", "{revision}", "1", "{recordId}", "record-test", "{leaseId}", "lease-test").Replace(endpoint.Path)
		browser := slices.Contains(endpoint.Audiences, "browser")
		executor := slices.Contains(endpoint.Audiences, "executor")
		want := endpoint.Availability == "available" && ((endpoint.Method == http.MethodGet && browser) || remoteSessionEndpoints[endpoint.ID] || (executor && remoteExecutorEndpoints[endpoint.ID]))
		if got := RemoteReadRequestAllowed(endpoint.Method, requestPath); got != want {
			t.Fatalf("%s %s admission = %t, want %t", endpoint.Method, endpoint.ID, got, want)
		}
	}
	for _, path := range []string{"/api/v1/inventory-drafts/import", "/api/v1/inventory-diffs", "/api/v1/inventory-exports"} {
		if RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Fatalf("remote mutation admitted: %s", path)
		}
	}
	for _, path := range []string{"/api/v1/executor-leases/claim", "/api/v1/executor-leases/lease-test/renew", "/api/v1/execution-receipts"} {
		if !RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Fatalf("executor operation remote-denied: %s", path)
		}
		if !RemoteExecutorRequestAllowed(http.MethodPost, path) {
			t.Fatalf("executor operation missing machine admission: %s", path)
		}
	}
	if RemoteReadRequestAllowed(http.MethodGet, "/api/v1/not-a-route") || RemoteReadRequestAllowed(http.MethodPost, "/api/v1/summary") {
		t.Fatal("unknown route or wrong method admitted")
	}
	if RemoteExecutorRequestAllowed(http.MethodPost, "/api/v1/session") || RemoteExecutorRequestAllowed(http.MethodPost, "/api/v1/plans/plan-test/execute") || RemoteExecutorRequestAllowed(http.MethodGet, "/api/v1/executor-leases/claim") {
		t.Fatal("non-executor or wrong-method route gained machine admission")
	}
}
