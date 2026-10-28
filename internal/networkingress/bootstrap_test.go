package networkingress

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func bootstrapFixture() generated.IngressChange {
	return generated.IngressChange{Schema: generated.SchemaIDIngressChange, SchemaVersion: "1.0.0", ProfileID: "console-bootstrap", AccountID: strings.Repeat("a", 32), ZoneID: strings.Repeat("b", 32), Action: "bootstrap-tunnel", ResourceKind: "tunnel-configuration", OwnerID: "operator-a", DeviceID: "device-a", BeforeDigest: Digest("absent"), Hostname: "console.example.test", OriginService: "https://10.0.0.7:8443", OriginServerName: "console.example.test", OriginIdentityDigest: Digest("leaf"), DNSRecordID: strings.Repeat("c", 32), PolicyName: "console-bootstrap", Connectors: []generated.IngressConnectorTarget{{HostID: "controller-a", IdentityDigest: Digest("controller")}}, ObservationReferenceID: "ingress-reader", MutationReferenceID: "ingress-writer", ReplacementReferenceID: "ingress-replacement", Bootstrap: &generated.IngressBootstrap{Schema: generated.SchemaIDIngressBootstrap, SchemaVersion: "1.0.0", Name: "console-bootstrap", AllowedEmail: "operator@example.test", SourceRunIDs: []string{}}}
}
func TestBootstrapRejectsWildcard(t *testing.T) {
	c := bootstrapFixture()
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*generated.IngressChange){
		"wildcard":        func(c *generated.IngressChange) { c.Hostname = "*.example.test" },
		"other resource":  func(c *generated.IngressChange) { c.ResourceID = "11111111-1111-4111-8111-111111111111" },
		"TLS bypass":      func(c *generated.IngressChange) { c.OriginService = "http://10.0.0.7:8443" },
		"foreign CA path": func(c *generated.IngressChange) { c.Bootstrap.OriginCAPool = "/etc/other-project/ca.pem" },
		"unbounded email": func(c *generated.IngressChange) {
			c.Bootstrap.AllowedEmail = "operator@example.test,other@example.test"
		},
		"protected host":             func(c *generated.IngressChange) { c.Connectors[0].HostID = "vsk-node-04" },
		"credentials shared purpose": func(c *generated.IngressChange) { c.MutationReferenceID = c.ObservationReferenceID },
		"extra predecessor":          func(c *generated.IngressChange) { c.Bootstrap.SourceRunIDs = []string{"run-extra"} },
		"ordinary action":            func(c *generated.IngressChange) { c.Action = "dns-record-update" },
	} {
		t.Run(name, func(t *testing.T) {
			c := bootstrapFixture()
			mutate(&c)
			if Validate(c) == nil {
				t.Fatal("invalid scope accepted")
			}
		})
	}
}
func TestBootstrapPolicyPinsIntentAndAllowsOnlyReceiptBoundIDs(t *testing.T) {
	c := bootstrapFixture()
	p := generated.IngressBootstrapPolicy{Change: c, ControllerHostID: c.Connectors[0].HostID, ControllerIdentityDigest: c.Connectors[0].IdentityDigest, ControllerMachineIDDigest: Digest("machine"), ControllerInstanceID: "instance-a"}
	if ValidateBootstrapPolicy(p) != nil {
		t.Fatal("valid policy rejected")
	}
	next := bootstrapFixture()
	next.Action = "bootstrap-cutover"
	next.ResourceKind = "dns-record"
	next.TunnelID = "11111111-1111-4111-8111-111111111111"
	next.AccessAppID = "22222222-2222-4222-8222-222222222222"
	next.AccessPolicyID = "33333333-3333-4333-8333-333333333333"
	next.AllowedGroupIDs = []string{"44444444-4444-4444-8444-444444444444"}
	next.Connectors[0].ConnectorID = "55555555-5555-4555-8555-555555555555"
	next.Bootstrap.SourceRunIDs = []string{"run-tunnel", "run-app", "run-group", "run-policy", "run-seed"}
	if err := ValidateBootstrapChange(p, next, 0); err != nil {
		t.Fatal(err)
	}
	next.Bootstrap.AllowedEmail = "different@example.test"
	if ValidateBootstrapChange(p, next, 0) == nil {
		t.Fatal("email changed outside protected policy")
	}
	next.Bootstrap.AllowedEmail = c.Bootstrap.AllowedEmail
	if ValidateBootstrapChange(p, next, 1) == nil {
		t.Fatal("recovery epoch changed")
	}
	next.Bootstrap.SourceRunIDs[4] = next.Bootstrap.SourceRunIDs[0]
	if Validate(next) == nil {
		t.Fatal("duplicate dependency accepted")
	}
}
func TestBootstrapCannotExpandExistingPilot(t *testing.T) {
	c := bootstrapFixture()
	if ValidatePilotChange(generated.IngressControllerReadPilot{}, c, 0) == nil {
		t.Fatal("bootstrap passed ordinary pilot validation")
	}
}
