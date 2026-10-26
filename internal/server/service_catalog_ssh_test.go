package server

import (
	"bytes"
	"context"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/apissh"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"testing"
)

func TestServiceSSHExactOperationsAndBoundArguments(t *testing.T) {
	for _, tc := range []struct {
		op, method, path, want string
		args                   []string
	}{
		{"api.v1.services.list", "GET", "/api/v1/services", "/api/v1/services?after=service-a&limit=7", []string{"service", "list", "--after", "service-a", "--limit", "7"}},
		{"api.v1.services.get", "GET", "/api/v1/services/service-a", "/api/v1/services/service-a", []string{"service", "show", "--service-id", "service-a"}},
		{"api.v1.services.observation.get", "GET", "/api/v1/services/service-a/observation", "/api/v1/services/service-a/observation", []string{"service", "observe", "--service-id", "service-a"}},
		{"api.v1.services.import-drafts.create", "POST", "/api/v1/services/import-drafts", "/api/v1/services/import-drafts", []string{"service", "import", "draft"}},
	} {
		op, ok := api.ConstrainedSSHOperation(tc.method, tc.path)
		if !ok || op != tc.op {
			t.Fatalf("route=%s op=%s allowed=%v", tc.path, op, ok)
		}
		path, ok := apiSSHArgumentsAllowed(op, tc.path, tc.args)
		if !ok || path != tc.want {
			t.Fatalf("args=%v mapped=%s allowed=%v", tc.args, path, ok)
		}
	}
	for _, args := range [][]string{{"service", "list", "--limit", "101"}, {"service", "list", "--after", "../secret"}, {"service", "list", "--limit", "2", "--limit", "3"}, {"service", "list", "--url", "https://invalid.example"}} {
		if _, ok := apiSSHArgumentsAllowed("api.v1.services.list", "/api/v1/services", args); ok {
			t.Fatalf("accepted %v", args)
		}
	}
	if _, ok := apiSSHArgumentsAllowed("api.v1.services.get", "/api/v1/services/service-a", []string{"service", "show", "--service-id", "service-b"}); ok {
		t.Fatal("cross-service arguments accepted")
	}
	if api.ConstrainedSSHRequestAllowed(localtransport.MethodPost, "/api/v1/services/service-a/deploy") {
		t.Fatal("provider write admitted")
	}
}

func TestServiceSSHFrameForwardsBoundPagination(t *testing.T) {
	recorder := &apiSSHRecorder{responses: []localtransport.Response{apiSSHLocalResponse(t, apiSSHEnvelope("server status", "health", 4, 9)), apiSSHLocalResponse(t, apiSSHEnvelope("api.v1.services.list", "services", 4, 9))}}
	handler := newAPISSHTestHandler(recorder)
	wire := apiSSHRequestWire(t, "GET /api/v1/services", []string{"service", "list", "--after", "service-a", "--limit", "7"}, 4, nil)
	var output bytes.Buffer
	if err := handler.Serve(context.Background(), bytes.NewReader(wire), &output); err != nil {
		t.Fatal(err)
	}
	response, err := apissh.ReadResponse(&output, apiSSHRequestID)
	if err != nil || len(response.Envelope.Errors) != 0 || len(recorder.requests) != 2 || recorder.requests[1].Path != "/api/v1/services?after=service-a&limit=7" {
		t.Fatalf("response=%+v err=%v requests=%+v", response, err, recorder.requests)
	}
}
