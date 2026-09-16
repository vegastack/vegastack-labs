package metadata

import "testing"

func TestCredentialImportContractIsLocalInertAndServerFingerprinted(t *testing.T) {
	registry := Current()
	endpoint := endpointByID(t, registry, "api.v1.credential-references.import-stream")
	if endpoint.Availability != AvailabilityAvailable || endpoint.Method != "POST" || endpoint.TransportScope != "local" || endpoint.RequestEncoding != "binary" || endpoint.MaxRequestBytes != 4096 || endpoint.RequestSchema != "vegastack-labs.dev/credential-import-request" || endpoint.DataSchema != "vegastack-labs.dev/credential-import-submission" {
		t.Fatalf("credential import endpoint=%#v", endpoint)
	}
	request := schemaByID(t, registry, endpoint.RequestSchema)
	for _, field := range request.Fields {
		if field.JSONName == "fingerprint" || field.JSONName == "material" || field.JSONName == "plaintext" {
			t.Fatal("caller-authored private/fingerprint field in import metadata")
		}
	}
	submission := schemaByID(t, registry, endpoint.DataSchema)
	seen := map[string]bool{}
	for _, field := range submission.Fields {
		seen[field.JSONName] = true
	}
	for _, name := range []string{"draftId", "referenceId", "ciphertextFingerprint", "status", "stateRevision", "recoveryEpoch"} {
		if !seen[name] {
			t.Fatalf("inert import response missing %s", name)
		}
	}
}

func TestCredentialImportIsTheOnlyAvailableCredentialSurface(t *testing.T) {
	registry := Current()
	endpoint := endpointByID(t, registry, "api.v1.credential-references.import-stream")
	if endpoint.Availability != AvailabilityAvailable || endpoint.TransportScope != "local" || endpoint.RequestEncoding != "binary" || endpoint.MaxRequestBytes != 4096 {
		t.Fatalf("unsafe import endpoint: %#v", endpoint)
	}
	for _, id := range []string{"api.v1.credential-references.get", "api.v1.credential-resolution-records.get"} {
		if endpointByID(t, registry, id).Availability != AvailabilityPlanned {
			t.Fatalf("unowned endpoint activated: %s", id)
		}
	}
	command := commandByName(t, registry, "credential import")
	if command.Availability != AvailabilityAvailable || command.RequestSchema != credentialImportRequestSchemaID || command.DataSchema != credentialImportSubmissionSchemaID {
		t.Fatalf("unsafe command: %#v", command)
	}
}
