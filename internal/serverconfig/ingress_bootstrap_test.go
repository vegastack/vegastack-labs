package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"testing"
)

func TestBootstrapProtectedProfileDoesNotRequireInventedProviderIDs(t *testing.T) {
	old := pilotFixture()
	c := old.Change
	c.Action = "bootstrap-tunnel"
	c.ResourceKind = "tunnel-configuration"
	c.ResourceID = ""
	c.TunnelID = ""
	c.AccessAppID = ""
	c.AccessPolicyID = ""
	c.AllowedGroupIDs = []string{}
	c.Connectors[0].ConnectorID = ""
	c.ConnectorID = ""
	c.PolicyName = "console-bootstrap"
	c.Bootstrap = &generated.IngressBootstrap{Name: "console-bootstrap", AllowedEmail: "operator@example.test", OriginCAPool: "/etc/vsk-labs/ingress/origin-ca.pem", SourceRunIDs: []string{}}
	p := generated.IngressBootstrapPolicy{Change: c, ControllerHostID: old.ControllerHostID, ControllerIdentityDigest: old.ControllerIdentityDigest, ControllerMachineIDDigest: old.ControllerMachineIDDigest, ControllerInstanceID: old.ControllerInstanceID}
	profile := validGeneratedProfile()
	profile.IngressBootstrap = &p
	profile.IngressScopeDigests = []string{ingress.BootstrapScopeDigest(c)}
	if _, e := convertGeneratedProfile(profile, 1001); e != nil {
		t.Fatal(e)
	}
	profile.IngressScopeDigests = nil
	if _, e := convertGeneratedProfile(profile, 1001); e == nil {
		t.Fatal("unscoped bootstrap accepted")
	}
}
