package networkingress

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestDisconnectCannotWidenToAllConnectors(t *testing.T) {
	if Validate(generated.IngressChange{Action: "connector-disconnect", ConnectorID: ""}) == nil {
		t.Fatal("all-connector effect accepted")
	}
}
func TestPublicOrCredentialBearingOriginsAreRejected(t *testing.T) {
	for _, origin := range []string{"https://example.com", "https://user:password@10.0.0.1", "http://10.0.0.1", "https://10.0.0.1?token=fixture"} {
		if Validate(generated.IngressChange{OriginService: origin}) == nil {
			t.Fatalf("accepted unsafe origin %s", origin)
		}
	}
}

func TestTunnelOperationsHaveOneOwner(t *testing.T) {
	c := generated.IngressChange{AccountID: "account", TunnelID: "tunnel", ZoneID: "zone", ResourceKind: "tunnel-configuration", ResourceID: "tunnel"}
	key := ResourceKey(c)
	for _, kind := range []string{"connector", "tunnel-token"} {
		c.ResourceKind, c.ResourceID = kind, "different-child"
		if ResourceKey(c) != key {
			t.Fatal("tunnel ownership split by operation")
		}
	}
	c.TunnelID = "other-tunnel"
	if ResourceKey(c) == key {
		t.Fatal("different tunnel has same owner key")
	}
}
