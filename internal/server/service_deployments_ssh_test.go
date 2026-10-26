package server

import (
	"github.com/vegastack/vegastack-labs/internal/api"
	"testing"
)

func TestServiceDeploymentSSHExactSurface(t *testing.T) {
	for _, tc := range []struct {
		op, method, path string
		args             []string
	}{{"api.v1.services.deployment-drafts.create", "POST", "/api/v1/services/deployment-drafts", []string{"service", "deployment", "draft"}}, {"api.v1.services.deployment.get", "GET", "/api/v1/services/service-a/deployment", []string{"service", "deployment", "show", "--service-id", "service-a"}}} {
		op, ok := api.ConstrainedSSHOperation(tc.method, tc.path)
		if !ok || op != tc.op {
			t.Fatalf("%s %v", op, ok)
		}
		path, ok := apiSSHArgumentsAllowed(op, tc.path, tc.args)
		if !ok || path != tc.path {
			t.Fatalf("%s %v", path, ok)
		}
	}
	for _, args := range [][]string{{"service", "deployment", "show", "--service-id", "service-b"}, {"service", "deployment", "show", "--service-id", "service-a", "--url", "https://private"}} {
		if _, ok := apiSSHArgumentsAllowed("api.v1.services.deployment.get", "/api/v1/services/service-a/deployment", args); ok {
			t.Fatal(args)
		}
	}
	if api.RemoteReadRequestAllowed("POST", "/api/v1/services/deployment-drafts") {
		t.Fatal("operator draft exposed to browser")
	}
}
