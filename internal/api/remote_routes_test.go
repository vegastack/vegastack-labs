package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestRemoteReadAdmissionMatchesGeneratedReadAndSessionEndpoints(t *testing.T) {
	for _, endpoint := range generated.Endpoints {
		requestPath := strings.NewReplacer("{draftId}", "draft-test", "{revision}", "1", "{recordId}", "record-test").Replace(endpoint.Path)
		want := endpoint.Availability == "available" && (endpoint.Method == http.MethodGet || remoteSessionEndpoints[endpoint.ID])
		if got := RemoteReadRequestAllowed(endpoint.Method, requestPath); got != want {
			t.Fatalf("%s %s admission = %t, want %t", endpoint.Method, endpoint.ID, got, want)
		}
	}
	for _, path := range []string{"/api/v1/inventory-drafts/import", "/api/v1/inventory-diffs", "/api/v1/inventory-exports"} {
		if RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Fatalf("remote mutation admitted: %s", path)
		}
	}
	if RemoteReadRequestAllowed(http.MethodGet, "/api/v1/not-a-route") || RemoteReadRequestAllowed(http.MethodPost, "/api/v1/summary") {
		t.Fatal("unknown route or wrong method admitted")
	}
}
