package metadata

import "testing"

func TestControllerSetupEndpointsStayLocalOperatorOnly(t *testing.T) {
	endpoints := controllerSetupClaimEndpoints()
	if len(endpoints) != 3 {
		t.Fatal("setup endpoint set changed")
	}
	for _, endpoint := range endpoints {
		if endpoint.TransportScope != "local" || len(endpoint.Audiences) != 1 || endpoint.Audiences[0] != AudienceOperator || endpoint.Method != "POST" || endpoint.MaxRequestBytes != 65536 {
			t.Fatalf("setup endpoint widened: %s", endpoint.ID)
		}
	}
}
