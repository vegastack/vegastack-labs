package contractgen

import (
	"github.com/vegastack/vegastack-labs/internal/metadata"
	"testing"
)

func TestHostActionPlanMaterialVersionIsPublicMetadata(t *testing.T) {
	if _, err := Generate(metadata.Current()); err != nil {
		t.Fatal(err)
	}
}

func TestHostActionPlanStillRejectsPrivateMaterial(t *testing.T) {
	for _, name := range []string{"credentialBytes", "privateKey", "credentialMaterialVersionExtra"} {
		r := metadata.Current()
		for i := range r.Schemas {
			if r.Schemas[i].ID == "vegastack-labs.dev/host-action-request" {
				r.Schemas[i].Fields = append(r.Schemas[i].Fields, metadata.FieldDefinition{JSONName: name, GoName: "Unsafe", Kind: metadata.ValueString, Required: true})
			}
		}
		if _, err := Generate(r); err == nil {
			t.Fatalf("secret field %s accepted", name)
		}
	}
}
