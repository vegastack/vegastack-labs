package plan

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestMeshPayloadCannotChangeBetweenDeclarationAndPlan(t *testing.T) {
	a := []generated.ContractExtension{{Name: "x-cloudflare-mesh-change", ValueDigest: testDigestString("a")}}
	if credentialBindingExtensionsEqual(a, nil) {
		t.Fatal("omitted Mesh payload accepted")
	}
	b := []generated.ContractExtension{{Name: "x-cloudflare-mesh-change", ValueDigest: testDigestString("b")}}
	if credentialBindingExtensionsEqual(a, b) {
		t.Fatal("substituted Mesh payload accepted")
	}
	if !credentialBindingExtensionsEqual(a, a) {
		t.Fatal("exact Mesh payload denied")
	}
}
