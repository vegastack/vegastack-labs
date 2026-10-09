package metadata

import (
	"testing"
)

func TestAuthorizationGrantBatchContractIsBounded(t *testing.T) {
	r := Current()
	found := false
	for _, s := range r.Schemas {
		if s.ID != "vegastack-labs.dev/authorization-grant-batch-request" {
			continue
		}
		found = true
		for _, f := range s.Fields {
			if f.JSONName == "changes" && f.MaxItems != nil && *f.MaxItems == 32 && f.MinItems != nil && *f.MinItems == 1 {
				return
			}
		}
		t.Fatal("grant batch is not bounded to1..32 exact changes")
	}
	if !found {
		t.Fatal("fresh setup has no bounded grant-batch contract")
	}
}
