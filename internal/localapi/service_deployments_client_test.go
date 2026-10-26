package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"reflect"
	"testing"
)

func TestServiceDeploymentRemoteArgumentsAreExact(t *testing.T) {
	for _, tc := range []struct {
		op, path string
		want     []string
	}{{"api.v1.services.deployment-drafts.create", "/api/v1/services/deployment-drafts", []string{"service", "deployment", "draft"}}, {"api.v1.services.deployment.get", "/api/v1/services/service-a/deployment", []string{"service", "deployment", "show", "--service-id", "service-a"}}} {
		if got := remoteCommandArguments(requestSpec{command: tc.op, path: tc.path}); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%v", got)
		}
	}
	for _, path := range []string{"/api/v1/services/../deployment", "/api/v1/services/service-a/deployment?scope=all", "https://private.example/api/v1/services/service-a/deployment"} {
		if got := remoteCommandArguments(requestSpec{command: "api.v1.services.deployment.get", path: path}); got != nil {
			t.Fatalf("accepted %s %v", path, got)
		}
	}
}
func TestServiceDeploymentClientRejectsInvalidInputBeforeTransport(t *testing.T) {
	c := &client{}
	if _, e := c.GetServiceDeployment(context.Background(), serverconfig.Profile{}, "../service"); e == nil {
		t.Fatal("invalid ID")
	}
	if _, e := c.DraftServiceDeployment(context.Background(), serverconfig.Profile{}, generated.ServiceDeploymentDraftRequest{}); e == nil {
		t.Fatal("invalid draft")
	}
}
