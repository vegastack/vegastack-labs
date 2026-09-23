package metadata

import (
	"strings"
	"testing"
)

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

func TestCredentialV11SourceIsScopedAndImportDescriptorIsLocalBinary(t *testing.T) {
	versions := map[string]string{}
	for _, schema := range Current().Schemas {
		versions[schema.ID] = schema.Version
	}
	for _, id := range []string{credentialReferenceSchemaID, credentialResolutionRecordSchemaID, credentialReferenceRequestSchemaID, credentialImportRequestSchemaID, credentialImportSubmissionSchemaID} {
		if versions[id] != "1.1.0" {
			t.Errorf("credential schema %s version = %s", id, versions[id])
		}
	}
	if versions[auditCheckpointSchemaID] != "1.1.0" || versions[auditVerificationDataSchemaID] != "1.1.0" {
		t.Errorf("audit schemas were not versioned together")
	}
	for _, id := range []string{restoreBindingSchemaID} {
		if versions[id] != "1.0.0" {
			t.Errorf("unowned schema %s version = %s", id, versions[id])
		}
	}
	found := false
	for _, endpoint := range Current().Endpoints {
		if endpoint.ID != "api.v1.credential-references.import-stream" {
			continue
		}
		found = true
		if endpoint.Method != "POST" || endpoint.RequestEncoding != "binary" || endpoint.TransportScope != "local" || endpoint.MaxRequestBytes != 4096 || endpoint.Availability != AvailabilityAvailable || endpoint.RequestSchema != credentialImportRequestSchemaID || endpoint.DataSchema != credentialImportSubmissionSchemaID || len(endpoint.Audiences) != 1 || endpoint.Audiences[0] != AudienceOperator {
			t.Fatalf("unsafe credential import descriptor: %#v", endpoint)
		}
	}
	if !found {
		t.Fatal("local binary import descriptor missing")
	}
}

func TestBackupCreationContractsAreVersionedAndInert(t *testing.T) {
	registry := Current()
	schemas := map[string]SchemaDefinition{}
	for _, schema := range registry.Schemas {
		schemas[schema.ID] = schema
	}
	for _, id := range []string{backupPolicySchemaID, backupJobSchemaID, recoveryPointSchemaID, backupDependencySchemaID, backupPolicyDraftRequestSchemaID, backupPolicyDraftSubmissionSchemaID} {
		schema, ok := schemas[id]
		if !ok {
			t.Fatalf("missing backup schema %s", id)
		}
		wantVersion := "1.1.0"
		if id == backupPolicySchemaID {
			wantVersion = "1.2.0"
		}
		if schema.Version != wantVersion {
			t.Errorf("backup schema %s version = %s", id, schema.Version)
		}
	}

	policy := schemas[backupPolicySchemaID]
	policyFields := map[string]FieldDefinition{}
	for _, field := range policy.Fields {
		policyFields[field.JSONName] = field
		if field.JSONName == "value" || field.JSONName == "material" || field.JSONName == "payload" || field.AdditionalProperties {
			t.Fatalf("unsafe backup policy field %s", field.JSONName)
		}
	}
	for _, name := range []string{"ownerId", "sourceSelectors", "consistencyHookId", "repositoryClass", "expectedBytes", "expectedGrowthBytes", "minimumFreeBytes", "encryptionKeyReferenceId", "recoveryKeyReferenceId", "retentionDays", "restoreTargetId", "dependencies", "functionalTestRequired"} {
		if _, ok := policyFields[name]; !ok {
			t.Errorf("backup policy missing field %s", name)
		}
	}
	if policyFields["repositoryId"].Kind != ValueString || !policyFields["repositoryId"].Nullable {
		t.Errorf("repositoryId must be a nullable string, got %#v", policyFields["repositoryId"])
	}

	job := schemas[backupJobSchemaID]
	pending := false
	for _, field := range job.Fields {
		if field.JSONName == "status" {
			for _, value := range field.Enum {
				if value == "pending" {
					pending = true
				}
			}
		}
	}
	if !pending {
		t.Error("backup job status enum missing pending")
	}

	var draftEndpoint *EndpointDefinition
	for index := range registry.Endpoints {
		if registry.Endpoints[index].ID == "api.v1.backup-policy-drafts.create" {
			draftEndpoint = &registry.Endpoints[index]
		}
		if registry.Endpoints[index].ID == "api.v1.backups.run" && registry.Endpoints[index].Availability != AvailabilityAvailable {
			t.Error("backup run is unavailable")
		}
	}
	if draftEndpoint == nil || draftEndpoint.Method != "POST" || draftEndpoint.Path != "/api/v1/backups/policies/drafts" ||
		draftEndpoint.Availability != AvailabilityAvailable || draftEndpoint.RequestSchema != backupPolicyDraftRequestSchemaID ||
		draftEndpoint.DataSchema != backupPolicyDraftSubmissionSchemaID {
		t.Fatalf("inert backup draft endpoint = %#v", draftEndpoint)
	}

	command := false
	for _, candidate := range registry.Commands {
		if strings.Join(candidate.Path, " ") == "backup policy draft" {
			command = true
			if candidate.Availability != AvailabilityAvailable || candidate.RequestSchema != backupPolicyDraftRequestSchemaID {
				t.Fatalf("backup policy draft command = %#v", candidate)
			}
		}
	}
	if !command {
		t.Fatal("backup policy draft command absent")
	}
	if err := Validate(registry); err != nil {
		t.Fatal(err)
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
		available := endpoint.ID == "api.v1.gate-profile-drafts.create" || endpoint.ID == "api.v1.gates.list" || endpoint.ID == "api.v1.gates.get" || endpoint.ID == "api.v1.gates.check" || endpoint.ID == "api.v1.gate-evidence.create" || endpoint.ID == "api.v1.credential-references.import-stream" || endpoint.ID == "api.v1.credential-lifecycle-drafts.create" || endpoint.ID == "api.v1.audit-checkpoints.list" || endpoint.ID == "api.v1.audit-checkpoints.create" || endpoint.ID == "api.v1.audit-history.verification" || endpoint.ID == "api.v1.backup-policy-drafts.create" || endpoint.ID == "api.v1.backup-retention-lock-drafts.create" || endpoint.ID == "api.v1.backups.status" || endpoint.ID == "api.v1.backups.run" || endpoint.ID == "api.v1.backups.verify"
		if (!available && endpoint.Availability != AvailabilityPlanned) || (available && endpoint.Availability != AvailabilityAvailable) || endpoint.DataSchema == "" {
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

func TestGateProfileDraftIsGeneratedAndOnlyInert(t *testing.T) {
	registry := Current()
	found := false
	for _, endpoint := range registry.Endpoints {
		if endpoint.ID == "api.v1.gate-profile-drafts.create" {
			found = true
			if endpoint.Availability != AvailabilityAvailable || endpoint.Method != "POST" || endpoint.RequestSchema != gateProfileDraftRequestSchemaID {
				t.Fatalf("profile draft endpoint %+v", endpoint)
			}
		}
	}
	if !found {
		t.Fatal("inert profile draft endpoint absent")
	}
}

func TestPhase5LifecycleRejectsInvalidEdge(t *testing.T) {
	registry := Current()
	registry.Lifecycle.RestoreTransitions[0] = TransitionDefinition{From: "failed", To: "verified"}
	if err := Validate(registry); err == nil {
		t.Fatal("failed restore promoted to verified")
	}
}
