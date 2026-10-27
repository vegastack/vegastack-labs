package server

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func ciEnrollmentPolicies(input []generated.CiEnrollmentBinding) ([]store.CIEnrollmentPolicy, error) {
	frozen, err := serverconfig.FreezeCIEnrollmentBindings(input)
	if err != nil {
		return nil, err
	}
	out := make([]store.CIEnrollmentPolicy, 0, len(frozen))
	for _, b := range frozen {
		out = append(out, store.CIEnrollmentPolicy{Definition: generated.CiEnrollmentDefinition{Schema: generated.SchemaIDCiEnrollmentDefinition, SchemaVersion: "1.0.0", EnrollmentID: b.EnrollmentID, OwnerID: b.OwnerID, BindingID: b.BindingID, BindingDigest: hostaction.Digest(b)}, Binding: b, ResourceKeyDigest: store.CIEnrollmentPolicyKey(b)})
	}
	return out, nil
}
