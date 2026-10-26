package plan

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestIngressPayloadCannotBeSubstituted(t *testing.T) {
	a := []generated.ContractExtension{{Name: "x-cloudflare-ingress-change", ValueDigest: testDigestString("a")}}
	b := []generated.ContractExtension{{Name: "x-cloudflare-ingress-change", ValueDigest: testDigestString("b")}}
	if credentialBindingExtensionsEqual(a, nil) || credentialBindingExtensionsEqual(a, b) {
		t.Fatal("ingress payload lost exact declaration binding")
	}
}
