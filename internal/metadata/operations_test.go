package metadata

import (
	"testing"
)

func TestOperationsPhaseIsFiniteAndObservationHasNoHealthUpload(t *testing.T) {
	r := Current()
	if e := Validate(r); e != nil {
		t.Fatal(e)
	}
	found := false
	for i := range r.Endpoints {
		if r.Endpoints[i].ID == "api.v1.operations.observe" {
			found = true
			r.Endpoints[i].OwnerPhase = "11"
		}
	}
	if !found {
		t.Fatal("missing collection endpoint")
	}
	if e := Validate(r); e == nil {
		t.Fatal("unapproved owner phase accepted")
	}
	for _, schema := range operationsSchemas() {
		if schema.ID == operationsObserveID {
			for _, f := range schema.Fields {
				if f.JSONName != "schema" && f.JSONName != "schemaVersion" {
					t.Fatal("caller-controlled observation", f.JSONName)
				}
			}
		}
	}
}
