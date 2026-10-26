package cli

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

type serviceConfigurationControlFixture struct {
	*stubControlOperations
	calls int
}

func (f *serviceConfigurationControlFixture) GetServiceConfiguration(_ context.Context, p, id string) (localapi.TypedResponse[generated.ServiceConfigurationStatus], error) {
	f.calls++
	return localapi.TypedResponse[generated.ServiceConfigurationStatus]{Data: generated.ServiceConfigurationStatus{ServiceID: id, PlacementState: "blocked", PlacementReason: "capacity-unknown"}, Raw: []byte("{\"configurationFixture\":true}\n")}, nil
}
func TestServiceConfigurationCLIUsesExactProtectedTransport(t *testing.T) {
	for _, id := range []string{"service-a", "../private"} {
		f := &serviceConfigurationControlFixture{stubControlOperations: successfulControlOperations(t)}
		code, out, _ := runTestAppWithOptions(t, context.Background(), []string{"service", "configuration", "show", "--config", "fixture/client.json", "--service-id", id}, nil, WithControlOperations(f, nil))
		if id == "service-a" {
			if code != 0 || f.calls != 1 || !strings.Contains(out, "capacity-unknown") {
				t.Fatal(code, out, f.calls)
			}
		} else if code == 0 || f.calls != 0 {
			t.Fatal("unsafe service reached control")
		}
	}
}
