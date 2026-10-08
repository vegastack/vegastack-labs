package contractgen

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/metadata"
)

func TestPhase5BrowserGraphRejectsSecretShape(t *testing.T) {
	registry := metadata.Current()
	for index := range registry.Schemas {
		if registry.Schemas[index].ID == "vegastack-labs.dev/gate-definition" {
			registry.Schemas[index].Fields = append(registry.Schemas[index].Fields,
				metadata.FieldDefinition{JSONName: "plaintextSecret", GoName: "PlaintextSecret", Kind: metadata.ValueString, Required: true})
		}
	}
	if _, err := Generate(registry); err == nil || !strings.Contains(err.Error(), "GENERATED_BROWSER_SCHEMA_UNSAFE") {
		t.Fatalf("secret-shaped Phase 5 browser graph accepted: %v", err)
	}
}

func TestDiscoveryPlanKeepsPrivateMaterialOutOfBrowserGraph(t *testing.T) {
	for _, name := range []string{"credentialBytes", "privateKey", "credentialPublicKeyDigestExtra"} {
		r := metadata.Current()
		for i := range r.Schemas {
			if r.Schemas[i].ID == "vegastack-labs.dev/host-discovery-target" {
				r.Schemas[i].Fields = append(r.Schemas[i].Fields, metadata.FieldDefinition{JSONName: name, GoName: "Unsafe", Kind: metadata.ValueString, Required: true})
			}
		}
		if _, err := Generate(r); err == nil || !strings.Contains(err.Error(), "GENERATED_BROWSER_SCHEMA_UNSAFE") {
			t.Fatalf("accepted %s: %v", name, err)
		}
	}
}
