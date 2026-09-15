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

func TestPhase5RecoveryJobSchemas(t *testing.T) {
	wanted := map[string]bool{
		"vegastack-labs.dev/backup-policy":        false,
		"vegastack-labs.dev/backup-job":           false,
		"vegastack-labs.dev/recovery-point":       false,
		"vegastack-labs.dev/audit-checkpoint":     false,
		"vegastack-labs.dev/restore-binding":      false,
		"vegastack-labs.dev/restore-verification": false,
		"vegastack-labs.dev/scheduled-job-policy": false,
		"vegastack-labs.dev/scheduled-job":        false,
	}
	for _, schema := range Current().Schemas {
		if _, ok := wanted[schema.ID]; !ok {
			continue
		}
		wanted[schema.ID] = true
		fields := map[string]bool{}
		for _, field := range schema.Fields {
			fields[field.JSONName] = true
			if field.AdditionalProperties {
				t.Fatalf("open Phase 5 field %s.%s", schema.ID, field.JSONName)
			}
		}
		if schema.ID == "vegastack-labs.dev/restore-binding" {
			for _, name := range []string{"pointId", "dependencyIds", "targetIds", "targetDigest", "planId", "planDigest", "humanAcknowledgementId", "formerControllerFenceDigest", "priorInstanceId", "newInstanceId", "priorRecoveryEpoch", "nextRecoveryEpoch"} {
				if !fields[name] {
					t.Errorf("missing restore binding %s", name)
				}
			}
		}
	}
	for id, found := range wanted {
		if !found {
			t.Errorf("missing schema %s", id)
		}
	}
}

func TestPhase5SurfaceRemainsPlanned(t *testing.T) {
	found := false
	for _, endpoint := range Current().Endpoints {
		if endpoint.OwnerPhase != "5" {
			continue
		}
		found = true
		if endpoint.Availability != AvailabilityPlanned || endpoint.DataSchema == "" {
			t.Errorf("unsafe Phase 5 endpoint %s", endpoint.ID)
		}
		if endpoint.ID == "api.v1.credential-resolution-records.get" {
			for _, audience := range endpoint.Audiences {
				if audience == AudienceBrowser {
					t.Fatal("resolution record exposed to browser")
				}
			}
		}
	}
	if !found {
		t.Fatal("Phase 5 endpoints absent")
	}
	if err := Validate(Current()); err != nil {
		t.Fatal(err)
	}
}

func TestPhase5RequestsDoNotAcceptServerIssuedProof(t *testing.T) {
	for _, schema := range Current().Schemas {
		if schema.ID != gateEvidenceRequestSchemaID && schema.ID != backupRunRequestSchemaID && schema.ID != auditCheckpointRequestSchemaID {
			continue
		}
		for _, field := range schema.Fields {
			switch field.JSONName {
			case "sourceKind", "proofClass", "verificationStatus", "result", "value", "material", "payload":
				t.Errorf("request %s accepts server-issued field %s", schema.ID, field.JSONName)
			}
		}
	}
}

func TestPhase5LifecycleRejectsInvalidEdge(t *testing.T) {
	registry := Current()
	registry.Lifecycle.RestoreTransitions[0] = TransitionDefinition{From: "failed", To: "verified"}
	if err := Validate(registry); err == nil {
		t.Fatal("failed restore promoted to verified")
	}
}
