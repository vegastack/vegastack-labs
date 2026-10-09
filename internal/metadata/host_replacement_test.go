package metadata

import "testing"

func TestReplacementContractsHaveOnlyExactOperatorEndpoints(t *testing.T) {
	endpoints := hostReplacementEndpoints()
	if len(endpoints) != 2 {
		t.Fatal("replacement endpoint surface expanded")
	}
	for _, e := range endpoints {
		if len(e.Audiences) != 1 || e.Audiences[0] != AudienceOperator || e.Availability != AvailabilityAvailable || e.OwnerPhase != "6" {
			t.Fatalf("replacement endpoint widened: %+v", e)
		}
	}
	if endpoints[0].Method != "POST" || endpoints[0].Path != "/api/v1/host-replacements" || endpoints[1].Method != "GET" || endpoints[1].Path != "/api/v1/host-replacements/{replacementId}" {
		t.Fatal("unexpected replacement endpoint")
	}
	if len(hostReplacementSchemas()) != 8 {
		t.Fatal("unexpected replacement schemas")
	}
}
