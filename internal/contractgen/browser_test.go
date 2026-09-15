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
