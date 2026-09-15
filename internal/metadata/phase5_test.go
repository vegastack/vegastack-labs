package metadata

import "testing"

func TestPhase5GateCredentialSchemas(t *testing.T) {
	wanted := map[string]bool{
		"vegastack-labs.dev/gate-definition":              false,
		"vegastack-labs.dev/gate-evidence":                false,
		"vegastack-labs.dev/gate-evaluation":              false,
		"vegastack-labs.dev/credential-reference":         false,
		"vegastack-labs.dev/credential-resolution-record": false,
	}
	for _, schema := range Current().Schemas {
		if _, ok := wanted[schema.ID]; !ok {
			continue
		}
		wanted[schema.ID] = true
		fields := make(map[string]bool, len(schema.Fields))
		for _, field := range schema.Fields {
			fields[field.JSONName] = true
			if field.JSONName == "value" || field.JSONName == "material" || field.JSONName == "payload" || field.AdditionalProperties {
				t.Fatalf("unsafe public field %s.%s", schema.ID, field.JSONName)
			}
		}
		if !fields["schema"] || !fields["schemaVersion"] || schema.ArtifactPath == "" {
			t.Errorf("schema %s is not a versioned artifact", schema.ID)
		}
	}
	for id, found := range wanted {
		if !found {
			t.Errorf("missing schema %s", id)
		}
	}
}
