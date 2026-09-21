package metadata

import "testing"

func TestLifecycleDraftSurfaceIsFiniteOperatorOnly(t *testing.T) {
	registry := Current()
	allowedFlags := map[string]bool{"--config": true, "--file": true}
	for _, flag := range commonFlags() {
		allowedFlags[flag.Name] = true
	}
	for _, action := range []string{"stage", "activate", "rotate", "revoke", "recover"} {
		found := false
		for _, command := range registry.Commands {
			if len(command.Path) == 2 && command.Path[0] == "credential" && command.Path[1] == action {
				found = true
				if command.Availability != AvailabilityAvailable || command.RequestSchema != credentialLifecycleRequestSchemaID || command.DataSchema != credentialLifecycleSubmissionID || command.Risk != RiskMutation {
					t.Fatalf("unqualified lifecycle leaf: %+v", command)
				}
				for _, flag := range command.Flags {
					if !allowedFlags[flag.Name] {
						t.Fatalf("unexpected lifecycle value flag %s", flag.Name)
					}
				}
			}
		}
		if !found {
			t.Fatalf("missing lifecycle leaf credential %s", action)
		}
	}
	endpoint := endpointByID(t, registry, "api.v1.credential-lifecycle-drafts.create")
	if endpoint.Method != "POST" || endpoint.Path != "/api/v1/credential-lifecycle-drafts" || endpoint.Availability != AvailabilityAvailable || endpoint.Stream != StreamFinite || len(endpoint.Audiences) != 1 || endpoint.Audiences[0] != AudienceOperator {
		t.Fatalf("lifecycle draft admission: %+v", endpoint)
	}
}
