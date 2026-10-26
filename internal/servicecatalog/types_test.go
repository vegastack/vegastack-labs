package servicecatalog

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestValidateImportRequestRequiresObservedInitialRegistration(t *testing.T) {
	digest := Digest("fixture")
	in := generated.ServiceImportRequest{Schema: generated.SchemaIDServiceImportRequest, SchemaVersion: "1.0.0", Definition: generated.ServiceDefinition{Schema: generated.SchemaIDServiceDefinition, SchemaVersion: "1.0.0", ServiceID: "service-a", EnvironmentID: "development", OwnerID: "owner-a", HostID: "host-a", HostIdentityDigest: digest, BindingID: "binding-a", BindingDigest: digest}, ObservationDigest: digest, IdempotencyKey: "import-a", ReasonDigest: digest}
	if err := ValidateImportRequest(in); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*generated.ServiceImportRequest){func(v *generated.ServiceImportRequest) { v.ObservationDigest = "" }, func(v *generated.ServiceImportRequest) { v.ExpectedServiceRevision = 1 }, func(v *generated.ServiceImportRequest) { v.ExpectedDeclarationRevision = 1 }, func(v *generated.ServiceImportRequest) { v.Definition.BindingDigest = "invalid" }, func(v *generated.ServiceImportRequest) { v.Definition.EnvironmentID = "" }} {
		changed := in
		mutate(&changed)
		if ValidateImportRequest(changed) == nil {
			t.Fatal("invalid import accepted", changed)
		}
	}
}
