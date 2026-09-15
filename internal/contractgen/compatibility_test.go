package contractgen

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/metadata"
)

func TestPhase5RegistryMajorFailsClosed(t *testing.T) {
	registry := metadata.Current()
	registry.SchemaVersion = "2.0.0"
	if _, err := Generate(registry); err == nil || !strings.Contains(err.Error(), "SCHEMA_MAJOR_UNSUPPORTED") {
		t.Fatalf("unknown registry major accepted: %v", err)
	}
}

func TestPhase5SchemaCarriesFixtureProofGuard(t *testing.T) {
	artifacts, err := Generate(metadata.Current())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"schemas/v1/gate-evidence.schema.json", "schemas/v1/backup-status-data.schema.json", "schemas/v1/audit-checkpoint-list-data.schema.json"} {
		var source []byte
		for _, artifact := range artifacts {
			if artifact.Path == path {
				source = artifact.Content
				break
			}
		}
		if source == nil {
			t.Fatalf("missing %s", path)
		}
		var schema map[string]any
		if err := json.Unmarshal(source, &schema); err != nil {
			t.Fatal(err)
		}
		guarded := schema
		if path == "schemas/v1/backup-status-data.schema.json" {
			guarded = schema["$defs"].(map[string]any)["backup-job"].(map[string]any)
		}
		if path == "schemas/v1/audit-checkpoint-list-data.schema.json" {
			guarded = schema["$defs"].(map[string]any)["audit-checkpoint"].(map[string]any)
		}
		guard, _ := json.Marshal(guarded["allOf"])
		if !strings.Contains(string(guard), "sourceKind") || !strings.Contains(string(guard), "proofClass") || !strings.Contains(string(guard), "fixture") {
			t.Errorf("%s lacks fixture-to-live guard", path)
		}
	}
}

func TestPhase5RegistryAdditiveMinorAccepted(t *testing.T) {
	registry := metadata.Current()
	registry.SchemaVersion = "1.17.0"
	if _, err := Generate(registry); err != nil {
		t.Fatalf("additive same-major registry rejected: %v", err)
	}
}
