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
		requestPath := strings.NewReplacer("{declarationId}", "declaration-test", "{draftId}", "draft-test", "{planId}", "plan-test", "{runId}", "run-test", "{revision}", "1", "{recordId}", "record-test", "{leaseId}", "lease-test", "{idempotencyKey}", "request-test").Replace(endpoint.Path)
		browser := slices.Contains(endpoint.Audiences, "browser")
		executor := slices.Contains(endpoint.Audiences, "executor")
		want := endpoint.Availability == "available" && ((endpoint.Method == http.MethodGet && browser) || (browser && remoteBrowserWriteEndpoints[endpoint.ID]) || remoteSessionEndpoints[endpoint.ID] || (executor && remoteExecutorEndpoints[endpoint.ID]))
		if got := RemoteReadRequestAllowed(endpoint.Method, requestPath); got != want {
			t.Fatalf("%s %s admission = %t, want %t", endpoint.Method, endpoint.ID, got, want)
		}
	}
	for _, path := range []string{"/api/v1/inventory-drafts/import", "/api/v1/inventory-diffs", "/api/v1/inventory-exports"} {
		if RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Fatalf("remote mutation admitted: %s", path)
		}
	}
	for _, path := range []string{"/api/v1/declarations/declaration-test/revisions", "/api/v1/declarations/declaration-test/plans", "/api/v1/plans/plan-test/approval-request", "/api/v1/plans/plan-test/execute", "/api/v1/runs/run-test/cancel", "/api/v1/runs/run-test/resume"} {
		if !RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Fatalf("browser change operation remote-denied: %s", path)
		}
	}
	if RemoteReadRequestAllowed(http.MethodPost, "/api/v1/plans/plan-test/acknowledgements") {
		t.Fatal("protected acknowledgement contract entered browser route")
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

func TestConstrainedSSHAdmissionIsGeneratedOperatorAPIWithoutAlternateAuthorities(t *testing.T) {
	allowedWrites := map[string]bool{
		"api.v1.inventory-diffs.create":   true,
		"api.v1.inventory-drafts.import":  true,
		"api.v1.inventory-exports.create": true,
		"api.v1.plans.create":             true,
		"api.v1.plans.execute":            true,
		"api.v1.runs.cancel":              true,
		"api.v1.runs.resume":              true,
	}
	for _, endpoint := range generated.Endpoints {
		requestPath := strings.NewReplacer(
			"{declarationId}", "declaration-test", "{draftId}", "draft-test", "{planId}", "plan-test",
			"{revision}", "1", "{recordId}", "record-test", "{runId}", "run-test", "{leaseId}", "lease-test", "{idempotencyKey}", "request-test",
		).Replace(endpoint.Path)
		operator := slices.Contains(endpoint.Audiences, "operator")
		want := endpoint.Availability == generated.AvailabilityAvailable && operator &&
			((endpoint.Method == http.MethodGet && endpoint.ID != "api.v1.events.stream") || allowedWrites[endpoint.ID])
		if got := ConstrainedSSHRequestAllowed(endpoint.Method, requestPath); got != want {
			t.Fatalf("%s %s constrained SSH admission = %t, want %t", endpoint.Method, endpoint.ID, got, want)
		}
	}
	for _, denied := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/plans/plan-test/acknowledgements"},
		{http.MethodPost, "/api/v1/session"},
		{http.MethodPost, "/api/v1/executor-leases/claim"},
		{http.MethodGet, "/api/v1/events"},
		{http.MethodGet, "/api/v1/not-a-route"},
	} {
		if ConstrainedSSHRequestAllowed(denied.method, denied.path) {
			t.Fatalf("alternate authority admitted through constrained SSH: %s %s", denied.method, denied.path)
		}
	}
}
