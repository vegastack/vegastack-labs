package metadata

import "testing"

func TestNativeCollectionCannotImportReportsOrClassification(t *testing.T) {
	var found bool
	for _, schema := range qualificationSchemas() {
		if schema.ID != "vegastack-labs.dev/native-collect-request" {
			continue
		}
		found = true
		allowed := map[string]bool{"schema": true, "schemaVersion": true, "scopeDigest": true, "stage": true, "evidenceId": true, "profileId": true, "producers": true, "expectedStateRevision": true, "recoveryEpoch": true, "idempotencyKey": true}
		for _, field := range schema.Fields {
			if !allowed[field.JSONName] {
				t.Fatalf("collector accepts unreviewed field %s", field.JSONName)
			}
		}
	}
	if !found {
		t.Fatal("missing finite collector request")
	}
	for _, endpoint := range qualificationEndpoints() {
		for _, audience := range endpoint.Audiences {
			if audience == AudienceBrowser {
				t.Fatal("native collection must remain operator-local")
			}
		}
	}
}
