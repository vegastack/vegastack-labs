package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"testing"
)

const serviceTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func servicePolicyFixture() servicecatalog.Policy {
	return servicecatalog.Policy{Definition: generated.ServiceDefinition{Schema: generated.SchemaIDServiceDefinition, SchemaVersion: "1.0.0", ServiceID: "service-a", EnvironmentID: "development", OwnerID: "operator-a", HostID: "synthetic-host", HostIdentityDigest: serviceTestDigest, BindingID: "binding-a", BindingDigest: serviceTestDigest}, ResourceKeyDigest: serviceTestDigest}
}
func TestServicePolicyDefensiveCopyAndUniqueness(t *testing.T) {
	p := servicePolicyFixture()
	input := []servicecatalog.Policy{p}
	c, err := normalizeConfig(Config{ToolVersion: "test", BuildVersion: "test", ServiceImportPolicies: input})
	if err != nil {
		t.Fatal(err)
	}
	input[0].Definition.ServiceID = "mutated"
	if c.ServiceImportPolicies[0].Definition.ServiceID != "service-a" {
		t.Fatal("policy mutated")
	}
	for _, policies := range [][]servicecatalog.Policy{{p, p}, make([]servicecatalog.Policy, 129), {{Definition: p.Definition, ResourceKeyDigest: "invalid"}}} {
		if _, err := normalizeConfig(Config{ToolVersion: "test", BuildVersion: "test", ServiceImportPolicies: policies}); err == nil {
			t.Fatal("invalid policies accepted")
		}
	}
}
func TestServiceImportDeclarationBindsExactIntent(t *testing.T) {
	p := servicePolicyFixture()
	in := generated.ServiceImportRequest{Schema: generated.SchemaIDServiceImportRequest, SchemaVersion: "1.0.0", Definition: p.Definition, ObservationDigest: serviceTestDigest, IdempotencyKey: "import-a", ReasonDigest: serviceTestDigest}
	digest := servicecatalog.Digest(in)
	d := generated.DeclarationRevision{ServiceImport: &in, DeclarationID: serviceDeclarationID(in.Definition.ServiceID), DeclarationType: "service.import", Revision: 1, StateRevision: 1, Status: "draft", Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: servicecatalog.OperationID, OperationType: servicecatalog.Operation, AdapterID: servicecatalog.AdapterID, TargetID: in.Definition.ServiceID, InputDigest: digest, ArtifactDigest: digest}}}
	if !ValidateServiceImportDeclaration(d) {
		t.Fatal("valid rejected")
	}
	d.Operations[0].TargetID = "other"
	if ValidateServiceImportDeclaration(d) {
		t.Fatal("changed target accepted")
	}
	d.Operations[0].TargetID = in.Definition.ServiceID
	in.ObservationDigest = ""
	if ValidateServiceImportDeclaration(d) {
		t.Fatal("missing observation accepted")
	}
}
